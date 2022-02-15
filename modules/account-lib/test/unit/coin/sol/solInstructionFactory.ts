import should from 'should';
import * as testData from '../../../resources/sol/sol';
import { solInstructionFactory } from '../../../../src/coin/sol/solInstructionFactory';
import { InstructionBuilderTypes, MEMO_PROGRAM_PK } from '../../../../src/coin/sol/constants';
import { InstructionParams } from '../../../../src/coin/sol/iface';
import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import BigNumber from 'bignumber.js';
const splToken = require('@solana/spl-token');

describe('Instruction Builder Tests: ', function () {
  describe('Succeed ', function () {
    it('Memo', () => {
      const memo = 'test memo';
      const memoParams: InstructionParams = {
        type: InstructionBuilderTypes.Memo,
        params: { memo },
      };

      const result = solInstructionFactory(memoParams);
      should.deepEqual(result, [
        new TransactionInstruction({
          keys: [],
          programId: new PublicKey(MEMO_PROGRAM_PK),
          data: Buffer.from(memo),
        }),
      ]);
    });

    it('Transfer', () => {
      const fromAddress = testData.authAccount.pub;
      const toAddress = testData.nonceAccount.pub;
      const amount = '100000';
      const transferParams: InstructionParams = {
        type: InstructionBuilderTypes.Transfer,
        params: { fromAddress, toAddress, amount },
      };

      const result = solInstructionFactory(transferParams);
      should.deepEqual(result, [
        SystemProgram.transfer({
          fromPubkey: new PublicKey(fromAddress),
          toPubkey: new PublicKey(toAddress),
          lamports: new BigNumber(amount).toNumber(),
        }),
      ]);
    });

    it('Advance nonce', () => {
      const authWalletAddress = testData.authAccount.pub;
      const walletNonceAddress = testData.nonceAccount.pub;
      const nonceAdvanceParams: InstructionParams = {
        type: InstructionBuilderTypes.NonceAdvance,
        params: { walletNonceAddress, authWalletAddress },
      };

      const result = solInstructionFactory(nonceAdvanceParams);
      should.deepEqual(result, [
        SystemProgram.nonceAdvance({
          noncePubkey: new PublicKey(walletNonceAddress),
          authorizedPubkey: new PublicKey(authWalletAddress),
        }),
      ]);
    });

    it('Create and Nonce initialize', () => {
      const fromAddress = testData.authAccount.pub;
      const nonceAddress = testData.nonceAccount.pub;
      const authAddress = testData.authAccount.pub;
      const amount = '100000';
      const createNonceAccountParams: InstructionParams = {
        type: InstructionBuilderTypes.CreateNonceAccount,
        params: { fromAddress, nonceAddress, authAddress, amount },
      };

      const result = solInstructionFactory(createNonceAccountParams);
      should.deepEqual(
        result,
        SystemProgram.createNonceAccount({
          fromPubkey: new PublicKey(fromAddress),
          noncePubkey: new PublicKey(nonceAddress),
          authorizedPubkey: new PublicKey(authAddress),
          lamports: new BigNumber(amount).toNumber(),
        }).instructions,
      );
    });

    it('Create associated token account', () => {
      const mintAddress = testData.associatedTokenAccounts.mint;
      const ataAddress = testData.associatedTokenAccounts.accounts[0].ata;
      const ownerAddress = testData.associatedTokenAccounts.accounts[0].pub;
      const payerAddress = testData.associatedTokenAccounts.accounts[0].pub;
      const createATAParams: InstructionParams = {
        type: InstructionBuilderTypes.CreateAssociatedTokenAccount,
        params: { mintAddress, ataAddress, ownerAddress, payerAddress },
      };

      const result = solInstructionFactory(createATAParams);
      should.deepEqual(result, [
        splToken.createAssociatedTokenAccountInstruction(
          splToken.ASSOCIATED_TOKEN_PROGRAM_ID,
          splToken.TOKEN_PROGRAM_ID,
          new PublicKey(mintAddress),
          new PublicKey(ataAddress),
          new PublicKey(ownerAddress),
          new PublicKey(payerAddress),
        ),
      ]);
    });
  });

  describe('Fail ', function () {
    it('Invalid type', () => {
      // @ts-expect-error Testing for an invalid type, should throw error
      should(() => solInstructionFactory({ type: 'random', params: {} })).throwError(
        'Invalid instruction type or not supported',
      );
    });
  });
});
