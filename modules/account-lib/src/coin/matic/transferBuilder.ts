import { TransferBuilder as EthTransferBuilder } from '../eth';

/** MATICL transfer builder */
export class TransferBuilder extends EthTransferBuilder {
  /**
   * Get the prefix used in generating an operation hash for sending tokens
   * See https://github.com/BitGo/eth-multisig-v2/blob/master/contracts/coins/EtcWalletSimple.sol
   *
   * @returns the string prefix
   */
  protected getTokenOperationHashPrefix(): string {
    return 'MATICL-ERC20';
  }

  /**
   * Get the prefix used in generating an operation hash for sending native coins
   * See https://github.com/BitGo/eth-multisig-v2/blob/master/contracts/coins/EtcWalletSimple.sol
   *
   * @returns the string prefix
   */
  protected getNativeOperationHashPrefix(): string {
    return 'MATICL';
  }
}
