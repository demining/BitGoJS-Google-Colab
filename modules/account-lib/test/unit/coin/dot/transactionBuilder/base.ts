import { BaseCoin as CoinConfig, coins, DotNetwork, Networks } from '@bitgo/statics';
import { DecodedSignedTx, DecodedSigningPayload, UnsignedTransaction } from '@substrate/txwrapper-core';
import Eddsa from '../../../../../src/mpc/tss';
import should from 'should';
import sinon from 'sinon';
import { TransactionType } from '../../../../../src/coin/baseCoin';
import { BaseKey } from '../../../../../src/coin/baseCoin/iface';
import { TransactionBuilder, Transaction, TransferBuilder, KeyPair } from '../../../../../src/coin/dot';
import { Material } from '../../../../../src/coin/dot/iface';
import utils from '../../../../../src/coin/dot/utils';
import { rawTx, accounts } from '../../../../resources/dot';

export interface TestDotNetwork extends DotNetwork {
  genesisHash: string;
  specVersion: number;
  metadataRpc: `0x${string}`;
}

export const buildTestConfig = (): Readonly<CoinConfig> => {
  return coins.get('tdot');
};

class StubTransactionBuilder extends TransactionBuilder {
  protected validateDecodedTransaction(decodedTxn: DecodedSigningPayload | DecodedSignedTx): void {
    return;
  }
  protected buildTransaction(): UnsignedTransaction {
    throw new Error('Method not implemented.');
  }

  getSender(): string {
    return this._sender;
  }

  getBlockNumber(): number {
    return this._blockNumber;
  }

  getReferenceBlock(): string {
    return this._referenceBlock;
  }

  getNonce(): number {
    return this._nonce;
  }

  getTip(): number | undefined {
    return this._tip;
  }

  getEraPeriod(): number | undefined {
    return this._eraPeriod;
  }

  buildImplementation(): Promise<Transaction> {
    return super.buildImplementation();
  }

  fromImplementation(rawTransaction: string): Transaction {
    return super.fromImplementation(rawTransaction);
  }

  signImplementation(key: BaseKey): Transaction {
    return super.signImplementation(key);
  }

  protected get transactionType(): TransactionType {
    throw new Error('Method not implemented.');
  }

  getTransaction(): Transaction {
    return this._transaction;
  }

  getMaterial(): Material {
    return this._material;
  }
}

// TODO: BG-43197
xdescribe('Dot Transfer Builder', () => {
  let builder: StubTransactionBuilder;

  const sender = accounts.account1;
  const { specName, specVersion, genesisHash, chainName } = Networks.test.dot;
  const receiver = DotResources.accounts.account2;

  beforeEach(() => {
    const config = buildTestConfig();
    builder = new StubTransactionBuilder(config).material(utils.getMaterial(config));
  });

  describe('setter validation', () => {
    it('should validate sender address', () => {
      const spy = sinon.spy(builder, 'validateAddress');
      should.throws(
        () => builder.sender({ address: 'asd' }),
        (e: Error) => e.message === `The address 'asd' is not a well-formed dot address`,
      );
      should.doesNotThrow(() => builder.sender({ address: sender.address }));
      sinon.assert.calledTwice(spy);
    });

    it('should validate eraPeriod', () => {
      const spy = sinon.spy(builder, 'validateValue');
      should.throws(
        () => builder.validity({ maxDuration: -1 }),
        (e: Error) => e.message === 'Value cannot be less than zero',
      );
      should.doesNotThrow(() => builder.validity({ maxDuration: 64 }));
      sinon.assert.calledTwice(spy);
    });

    it('should validate nonce', () => {
      const spy = sinon.spy(builder, 'validateValue');
      should.throws(
        () => builder.sequenceId({ name: 'Nonce', keyword: 'nonce', value: -1 }),
        (e: Error) => e.message === 'Value cannot be less than zero',
      );
      should.doesNotThrow(() => builder.sequenceId({ name: 'Nonce', keyword: 'nonce', value: 10 }));
      sinon.assert.calledTwice(spy);
    });

    it('should validate tip', () => {
      const spy = sinon.spy(builder, 'validateValue');
      should.throws(
        () => builder.fee({ amount: -1, type: 'tip' }),
        (e: Error) => e.message === 'Value cannot be less than zero',
      );
      should.doesNotThrow(() => builder.fee({ amount: 10, type: 'tip' }));
      sinon.assert.calledTwice(spy);
    });

    it('should validate blockNumber', () => {
      const spy = sinon.spy(builder, 'validateValue');
      should.throws(
        () => builder.validity({ firstValid: -1 }),
        (e: Error) => e.message === 'Value cannot be less than zero',
      );
      should.doesNotThrow(() => builder.validity({ firstValid: 10 }));
      sinon.assert.calledTwice(spy);
    });
  });

  describe('build base transaction', () => {
    it('should build validate base fields', async () => {
      builder
        .sender({ address: sender.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      should.doesNotThrow(() => builder.validateTransaction(builder.getTransaction()));
    });

    it('should build a base transaction on testnet', async () => {
      const material = builder.getMaterial();
      should.deepEqual(material.specName, specName);
      should.deepEqual(material.genesisHash, genesisHash);
      should.deepEqual(material.specVersion, specVersion);
      should.deepEqual(material.chainName, chainName);
    });

    it('should build from raw signed tx', async () => {
      builder.from(rawTx.transfer.signed);
      should.deepEqual(builder.getSender(), sender.address);
      should.deepEqual(builder.getNonce(), 200);
      should.deepEqual(builder.getEraPeriod(), 64);
      should.deepEqual(builder.getTip(), undefined);
    });

    it('should build from raw unsigned tx', async () => {
      builder.from(rawTx.transfer.unsigned);
      should.deepEqual(
        builder.getReferenceBlock(),
        '0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d',
      );
      should.deepEqual(builder.getNonce(), 200);
      should.deepEqual(builder.getEraPeriod(), 64);
      should.deepEqual(builder.getTip(), undefined);
    });
  });

  describe('add signature', () => {
    let builder: TransferBuilder;

    beforeEach(() => {
      const config = buildTestConfig();
      builder = new TransferBuilder(config).material(utils.getMaterial(config));
    });

    it('should add a signature to transaction', async () => {
      builder
        .amount('90034235235322')
        .sender({ address: sender.address })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });

      builder.sign({ key: DotResources.accounts.account1.secretKey });
      const signedTx = await builder.build();
      // const builtInSignature = signedTx.signature[0];

      const rawTransaction = signedTx.toBroadcastFormat() as string;
      builder.from(rawTransaction);
      const rebuiltSignedTransaction = await builder.build();
      rebuiltSignedTransaction.signature.should.deepEqual(signedTx.signature);
    });

    it('should add TSS signature', async () => {
      const MPC = await Eddsa();
      const A = MPC.keyShare(1, 2, 3);
      const B = MPC.keyShare(2, 2, 3);
      const C = MPC.keyShare(3, 2, 3);

      const A_combine = MPC.keyCombine(A.uShare, [B.yShares[1], C.yShares[1]]);
      const B_combine = MPC.keyCombine(B.uShare, [A.yShares[2], C.yShares[2]]);
      // const C_combine = MPC.keyCombine(C.uShare, [A.yShares[3], B.yShares[3]]);

      const dotKeyPair = new KeyPair({ pub: A_combine.pShare.y });

      builder
        .amount('90034235235322')
        .to({ address: '5Ffp1wJCPu4hzVDTo7XaMLqZSvSadyUQmxWPDw74CBjECSoq' })
        .sender({ address: dotKeyPair.getAddress() })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });

      const tx = await builder.build();
      // create a buffer out of the txHex
      const message_buffer = tx.signablePayload;

      // signing with A and B
      const A_sign_share = MPC.signShare(message_buffer, A_combine.pShare, [A_combine.jShares[2]]);
      const B_sign_share = MPC.signShare(message_buffer, B_combine.pShare, [B_combine.jShares[1]]);
      const A_sign = MPC.sign(message_buffer, A_sign_share.xShare, [B_sign_share.rShares[1]]);
      const B_sign = MPC.sign(message_buffer, B_sign_share.xShare, [A_sign_share.rShares[2]]);
      // sign the message_buffer (unsigned txHex)
      const signature = MPC.signCombine([A_sign, B_sign]);
      const rawSignature = Buffer.concat([Buffer.from(signature.R, 'hex'), Buffer.from(signature.sigma, 'hex')]);
      builder.from(tx.toBroadcastFormat());
      builder.addSignature(A_combine.pShare.y, rawSignature);
      // signature can be verified
      dotKeyPair.verifySignature(message_buffer, rawSignature).should.be.true();
    });
  });
});
