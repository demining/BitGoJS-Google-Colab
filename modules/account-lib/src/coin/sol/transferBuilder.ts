import { BaseCoin as CoinConfig } from '@bitgo/statics';
import { BuildTransactionError } from '../baseCoin/errors';
import { TransactionBuilder } from './transactionBuilder';
import { Transaction } from './transaction';
import { isValidAmount, validateAddress } from './utils';
import { TransactionType } from '../baseCoin';
import { InstructionBuilderTypes } from './constants';
import { Transfer } from './iface';

import assert from 'assert';
import { Signer } from '@solana/web3.js';

export interface SendParams {
  address: string;
  amount: string;
  mint?: string;
  source?: string;
  multiSigners?: Array<Signer>;
}

export class TransferBuilder extends TransactionBuilder {
  private _sendParams: SendParams[] = [];

  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
  }

  protected get transactionType(): TransactionType {
    return TransactionType.Send;
  }

  initBuilder(tx: Transaction): void {
    super.initBuilder(tx);

    for (const instruction of this._instructionsData) {
      if (instruction.type === InstructionBuilderTypes.Transfer) {
        const transferInstruction: Transfer = instruction;

        this.sender(transferInstruction.params.fromAddress);
        this.send({
          address: transferInstruction.params.toAddress,
          amount: transferInstruction.params.amount,
          mint: transferInstruction.params.mint || undefined,
          source: transferInstruction.params.source || undefined,
          multiSigners: transferInstruction.params.multiSigners || undefined,
        });
      }
    }
  }

  /**
   *  Set a transfer
   *
   * @param {string} fromAddress - the sender address
   * @param {string} toAddress - the receiver address
   * @param {string} amount - the amount sent
   * @returns {TransactionBuilder} This transaction builder
   */
  send({ address, amount, mint }: SendParams): this {
    mint = mint || undefined;
    validateAddress(address, 'address');
    if (!amount || !isValidAmount(amount)) {
      throw new BuildTransactionError('Invalid or missing amount, got: ' + amount);
    }

    this._sendParams.push({ address, amount, mint });

    return this;
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    assert(this._sender, 'Sender must be set before building the transaction');

    const transferData = this._sendParams.map((sendParams: SendParams): Transfer => {
      return {
        type: InstructionBuilderTypes.Transfer,
        params: {
          fromAddress: this._sender,
          toAddress: sendParams.address,
          amount: sendParams.amount,
          mint: sendParams.mint,
          source: sendParams.source,
          multiSigners: sendParams.multiSigners,
        },
      };
    });
    this._instructionsData = transferData;

    return await super.buildImplementation();
  }
}
