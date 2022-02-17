import { BaseCoin as CoinConfig, coins, DotNetwork, Networks } from '@bitgo/statics';
import { DecodedSignedTx, DecodedSigningPayload, UnsignedTransaction } from '@substrate/txwrapper-core';
import Eddsa from '../../../../../src/mpc/tss';
import should from 'should';
import sinon from 'sinon';
import { TransactionType } from '../../../../../src/coin/baseCoin';
import { BaseKey } from '../../../../../src/coin/baseCoin/iface';
import { TransactionBuilder, Transaction, KeyPair, TransactionBuilderFactory } from '../../../../../src/coin/dot';
import { Material } from '../../../../../src/coin/dot/iface';
import utils from '../../../../../src/coin/dot/utils';
import { rawTx, accounts } from '../../../../resources/dot';
import { register } from '../../../../../src';

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
  const receiver = accounts.account2;

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
    const factory = register('tdot', TransactionBuilderFactory);

    it('should add a signature to transaction', async () => {
      const transferBuilder = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .sender({ address: sender.address })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });

      transferBuilder.sign({ key: accounts.account1.secretKey });
      const signedTx = await transferBuilder.build();
      const signature = signedTx.signature[0];

      // verify rebuilt transaction contains signature
      const rawTransaction = signedTx.toBroadcastFormat() as string;
      const rebuiltSignedTransaction = await factory
        .from(rawTransaction)
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .build();
      rebuiltSignedTransaction.signature.should.deepEqual(signedTx.signature);

      const transferBuilder2 = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .sender({ address: sender.address })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      transferBuilder2.addSignature({ pub: accounts.account1.publicKey }, Buffer.from(signature, 'hex'));
      const signedTransaction2 = await transferBuilder2.build();

      // verify signatures are correct
      signedTx.signature.should.deepEqual(signedTransaction2.signature);
      const rawTransaction2 = signedTransaction2.toBroadcastFormat() as string;
      const rebuiltTransaction2 = await factory
        .from(rawTransaction2)
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .build();
      rebuiltTransaction2.signature.should.deepEqual(signedTransaction2.signature);
    });

    it('should add TSS signature', async () => {
      const MPC = await Eddsa();
      const A = MPC.keyShare(1, 2, 3);
      const B = MPC.keyShare(2, 2, 3);
      const C = MPC.keyShare(3, 2, 3);

      const A_combine = MPC.keyCombine(A.uShare, [B.yShares[1], C.yShares[1]]);
      const B_combine = MPC.keyCombine(B.uShare, [A.yShares[2], C.yShares[2]]);
      const C_combine = MPC.keyCombine(C.uShare, [A.yShares[3], B.yShares[3]]);

      const commonPub = A_combine.pShare.y;
      const dotKeyPair = new KeyPair({ pub: commonPub });
      const sender = dotKeyPair.getAddress();

      let transferBuilder = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .to({ address: '5Ffp1wJCPu4hzVDTo7XaMLqZSvSadyUQmxWPDw74CBjECSoq' })
        .sender({ address: sender })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      const unsignedTransaction = await transferBuilder.build();
      const signablePayload = unsignedTransaction.signablePayload;

      // signing with 3-3 signatures
      let A_sign_share = MPC.signShare(signablePayload, A_combine.pShare, [A_combine.jShares[2], A_combine.jShares[3]]);
      let B_sign_share = MPC.signShare(signablePayload, B_combine.pShare, [B_combine.jShares[1], B_combine.jShares[3]]);
      let C_sign_share = MPC.signShare(signablePayload, C_combine.pShare, [C_combine.jShares[1], C_combine.jShares[2]]);
      let A_sign = MPC.sign(signablePayload, A_sign_share.xShare, [B_sign_share.rShares[1], C_sign_share.rShares[1]]);
      let B_sign = MPC.sign(signablePayload, B_sign_share.xShare, [A_sign_share.rShares[2], C_sign_share.rShares[2]]);
      let C_sign = MPC.sign(signablePayload, C_sign_share.xShare, [A_sign_share.rShares[3], B_sign_share.rShares[3]]);
      let signature = MPC.signCombine([A_sign, B_sign, C_sign]);
      let rawSignature = Buffer.concat([Buffer.from(signature.R, 'hex'), Buffer.from(signature.sigma, 'hex')]);

      transferBuilder = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .to({ address: '5Ffp1wJCPu4hzVDTo7XaMLqZSvSadyUQmxWPDw74CBjECSoq' })
        .sender({ address: sender })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      transferBuilder.addSignature({ pub: dotKeyPair.getKeys().pub }, rawSignature);
      let signedTransaction = await transferBuilder.build();
      signedTransaction.signature.length.should.equal(1);
      signedTransaction.signature[0].should.equal(rawSignature.toString('hex'));

      // signing with A and B
      A_sign_share = MPC.signShare(signablePayload, A_combine.pShare, [A_combine.jShares[2]]);
      B_sign_share = MPC.signShare(signablePayload, B_combine.pShare, [B_combine.jShares[1]]);
      A_sign = MPC.sign(signablePayload, A_sign_share.xShare, [B_sign_share.rShares[1]]);
      B_sign = MPC.sign(signablePayload, B_sign_share.xShare, [A_sign_share.rShares[2]]);
      // sign the message_buffer (unsigned txHex)
      signature = MPC.signCombine([A_sign, B_sign]);
      rawSignature = Buffer.concat([Buffer.from(signature.R, 'hex'), Buffer.from(signature.sigma, 'hex')]);
      transferBuilder = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .to({ address: '5Ffp1wJCPu4hzVDTo7XaMLqZSvSadyUQmxWPDw74CBjECSoq' })
        .sender({ address: sender })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      transferBuilder.addSignature({ pub: dotKeyPair.getKeys().pub }, rawSignature);
      signedTransaction = await transferBuilder.build();
      signedTransaction.signature.length.should.equal(1);
      signedTransaction.signature[0].should.equal(rawSignature.toString('hex'));

      // signing with A and C
      A_sign_share = MPC.signShare(signablePayload, A_combine.pShare, [A_combine.jShares[3]]);
      C_sign_share = MPC.signShare(signablePayload, C_combine.pShare, [C_combine.jShares[1]]);
      A_sign = MPC.sign(signablePayload, A_sign_share.xShare, [C_sign_share.rShares[1]]);
      C_sign = MPC.sign(signablePayload, C_sign_share.xShare, [A_sign_share.rShares[3]]);
      signature = MPC.signCombine([A_sign, C_sign]);
      rawSignature = Buffer.concat([Buffer.from(signature.R, 'hex'), Buffer.from(signature.sigma, 'hex')]);
      transferBuilder = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .to({ address: '5Ffp1wJCPu4hzVDTo7XaMLqZSvSadyUQmxWPDw74CBjECSoq' })
        .sender({ address: sender })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      transferBuilder.addSignature({ pub: dotKeyPair.getKeys().pub }, rawSignature);
      signedTransaction = await transferBuilder.build();
      signedTransaction.signature.length.should.equal(1);
      signedTransaction.signature[0].should.equal(rawSignature.toString('hex'));

      // signing with B and C
      B_sign_share = MPC.signShare(signablePayload, B_combine.pShare, [B_combine.jShares[3]]);
      C_sign_share = MPC.signShare(signablePayload, C_combine.pShare, [C_combine.jShares[2]]);
      B_sign = MPC.sign(signablePayload, B_sign_share.xShare, [C_sign_share.rShares[2]]);
      C_sign = MPC.sign(signablePayload, C_sign_share.xShare, [B_sign_share.rShares[3]]);
      signature = MPC.signCombine([B_sign, C_sign]);
      rawSignature = Buffer.concat([Buffer.from(signature.R, 'hex'), Buffer.from(signature.sigma, 'hex')]);
      transferBuilder = factory
        .getTransferBuilder()
        .amount('90034235235322')
        .to({ address: '5Ffp1wJCPu4hzVDTo7XaMLqZSvSadyUQmxWPDw74CBjECSoq' })
        .sender({ address: sender })
        .to({ address: receiver.address })
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .sequenceId({ name: 'Nonce', keyword: 'nonce', value: 200 })
        .fee({ amount: 0, type: 'tip' });
      transferBuilder.addSignature({ pub: dotKeyPair.getKeys().pub }, rawSignature);
      signedTransaction = await transferBuilder.build();
      signedTransaction.signature.length.should.equal(1);
      signedTransaction.signature[0].should.equal(rawSignature.toString('hex'));

      const rebuiltTransaction = await factory
        .from(signedTransaction.toBroadcastFormat())
        .validity({ firstValid: 3933, maxDuration: 64 })
        .referenceBlock('0x149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d')
        .build();

      rebuiltTransaction.signature[0].should.equal(rawSignature.toString('hex'));
    });
  });
});
