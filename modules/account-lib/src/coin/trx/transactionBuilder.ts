import { createHash } from 'crypto';
import * as _ from 'lodash';
import BigNumber from 'bignumber.js';
import { BaseCoin as CoinConfig } from '@bitgo/statics';
import {
  SigningError,
  BuildTransactionError,
  InvalidTransactionError,
  ParseTransactionError,
} from '../baseCoin/errors';
import { BaseTransactionBuilder } from '../baseCoin';
import { BaseKey } from '../baseCoin/iface';
import { TransactionReceipt } from './iface';
import { Address } from './address';
import { isBase58Address, signTransaction, decodeTransaction } from './utils';
import { KeyPair } from './keyPair';
import { Transaction } from './transaction';

/**
 * Tron transaction builder.
 */
export class TransactionBuilder extends BaseTransactionBuilder {
  // transaction being built
  private _transaction: Transaction;
  protected _signingKeys: BaseKey[];
  /**
   * Public constructor.
   *
   * @param {CoinConfig} _coinConfig Configuration object
   */
  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
    this._signingKeys = [];
    this._transaction = new Transaction(_coinConfig);
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    // This method must be extended on child classes
    if (this._signingKeys.length > 0) {
      this.applySignatures();
    }

    if (!this.transaction.id) {
      throw new BuildTransactionError('A valid transaction must have an id');
    }
    return Promise.resolve(this.transaction);
  }

  /**
   * Parse transaction takes in raw JSON directly from the node.
   *
   * @param {TransactionReceipt} rawTransaction The Tron transaction in JSON format as returned by the Tron lib or a stringifyed version of such JSON.
   * @returns {Transaction} Tron transaction
   */
  protected fromImplementation(rawTransaction: TransactionReceipt | string): Transaction {
    let receipt;
    if (typeof rawTransaction === 'string') {
      receipt = JSON.parse(rawTransaction);
    } else {
      receipt = rawTransaction;
    }
    const transaction = new Transaction(this._coinConfig, receipt);
    this.initBuilder(transaction);
    return transaction;
  }

  /** @inheritdoc */
  protected signImplementation(key: BaseKey): Transaction {
    if (this._signingKeys.includes(key)) {
      throw new SigningError('Duplicated key');
    }
    this._signingKeys.push(key);

    // We keep this return for compatibility but is not meant to be use
    return this.transaction;
  }

  /**
   * Initialize the transaction builder fields using the decoded transaction data
   *
   * @param {Transaction} tx the transaction data
   */
  initBuilder(tx: Transaction): void {
    // this method should extended on each child class
    this._transaction = tx;
    this._signingKeys = [];
  }

  //region validations
  /** @inheritdoc */
  validateAddress(address: Address): void {
    // assumes a base 58 address for our addresses
    if (!isBase58Address(address.address)) {
      throw new Error(address + ' is not a valid base58 address.');
    }
  }

  /** @inheritdoc */
  validateKey(key: BaseKey): void {
    try {
      new KeyPair({ prv: key.key });
    } catch (err) {
      throw new Error('The provided key is not valid');
    }
  }

  /**
   * Validate the contents of a raw transaction. The validation
   * phase is to compare the raw-data-hex to the raw-data of the
   * transaction.
   *
   * The contents to be validated are
   * 1. The transaction id
   * 2. The expiration date
   * 3. The timestamp
   * 4. The contract
   *
   * @param {TransactionReceipt | string} rawTransaction The raw transaction to be validated
   */
  validateRawTransaction(rawTransaction: TransactionReceipt | string): void {
    // TODO: Validation of signature
    // TODO: Refactor with new implementation
    if (!rawTransaction) {
      throw new InvalidTransactionError('Raw transaction is empty');
    }
    let currTransaction: TransactionReceipt;
    // rawTransaction can be either Stringified JSON OR
    // it can be a regular JSON object (not stringified).
    if (typeof rawTransaction === 'string') {
      try {
        currTransaction = JSON.parse(rawTransaction);
      } catch (e) {
        throw new ParseTransactionError('There was error in parsing the JSON string');
      }
    } else if (_.isObject(rawTransaction)) {
      currTransaction = rawTransaction;
    } else {
      throw new InvalidTransactionError('Transaction is not an object or stringified json');
    }
    const decodedRawDataHex = decodeTransaction(currTransaction.raw_data_hex);
    if (!currTransaction.txID) {
      throw new InvalidTransactionError('Transaction ID is empty');
    }
    // Validate the transaction ID from the raw data hex
    const hexBuffer = Buffer.from(currTransaction.raw_data_hex, 'hex');
    const currTxID = createHash('sha256')
      .update(hexBuffer)
      .digest('hex');
    if (currTransaction.txID !== currTxID) {
      throw new InvalidTransactionError('Transaction has not have a valid id');
    }
    // Validate the expiration time from the raw-data-hex
    if (currTransaction.raw_data.expiration !== decodedRawDataHex.expiration) {
      throw new InvalidTransactionError('Transaction has not have a valid expiration');
    }
    // Validate the timestamp from the raw-data-hex
    if (currTransaction.raw_data.timestamp !== decodedRawDataHex.timestamp) {
      throw new InvalidTransactionError('Transaction has not have a valid timetamp');
    }
    // Transaction contract must exist
    if (!currTransaction.raw_data.contract) {
      throw new InvalidTransactionError('Transaction contracts are empty');
    }
  }

  /** @inheritdoc */
  // Specifically, checks hex underlying transaction hashes to correct transaction ID.
  validateTransaction(transaction: Transaction): void {
    const hexBuffer = Buffer.from(transaction.toJson().raw_data_hex, 'hex');
    const txId = createHash('sha256')
      .update(hexBuffer)
      .digest('hex');
    if (transaction.id !== txId) {
      throw new InvalidTransactionError(transaction.id + ' is not a valid transaction id. Expecting: ' + txId);
    }
  }

  /** @inheritdoc */
  validateValue(value: BigNumber): void {
    if (value.isLessThanOrEqualTo(0)) {
      throw new Error('Value cannot be below zero.');
    }

    // max long in Java - assumed upper limit for a TRX transaction
    if (value.isGreaterThan(new BigNumber('9223372036854775807'))) {
      throw new Error('Value cannot be greater than handled by the javatron node.');
    }
  }
  //endregion

  /** @inheritdoc */
  protected get transaction(): Transaction {
    return this._transaction;
  }

  /** @inheritdoc */
  protected set transaction(transaction: Transaction) {
    this._transaction = transaction;
  }

  private applySignatures(): void {
    if (!this.transaction.inputs) {
      throw new SigningError('Transaction has no sender');
    }

    if (!this.transaction.outputs) {
      throw new SigningError('Transaction has no receiver');
    }
    this._signingKeys.forEach(key => this.applySignature(key));
  }

  private applySignature(key: BaseKey): void {
    const oldTransaction = this.transaction.toJson();
    // Store the original signatures to compare them with the new ones in a later step. Signatures
    // can be undefined if this is the first time the transaction is being signed
    const oldSignatureCount = oldTransaction.signature ? oldTransaction.signature.length : 0;
    let signedTransaction: TransactionReceipt;
    try {
      const keyPair = new KeyPair({ prv: key.key });
      // Since the key pair was generated using a private key, it will always have a prv attribute,
      // hence it is safe to use non-null operator
      signedTransaction = signTransaction(keyPair.getKeys().prv!, this.transaction.toJson());
    } catch (e) {
      throw new SigningError('Failed to sign transaction via helper.');
    }

    // Ensure that we have more signatures than what we started with
    if (!signedTransaction.signature || oldSignatureCount >= signedTransaction.signature.length) {
      throw new SigningError('Transaction signing did not return an additional signature.');
    }
  }

  /** //TODO: Remove this method from here, it should be a tx method
   * Extend the validity of this transaction by the given amount of time
   *
   * @param {number} extensionMs The number of milliseconds to extend the validTo time
   * @returns {undefined}
   */
  extendValidTo(extensionMs: number): void {
    this.transaction.extendExpiration(extensionMs);
  }
}
