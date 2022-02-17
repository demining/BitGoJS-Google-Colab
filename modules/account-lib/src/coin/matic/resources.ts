import { coins, EthereumNetwork } from '@bitgo/statics';
import EthereumCommon from '@ethereumjs/common';

/**
 * A Common object defining the chain and the hardfork for MaticL Testnet
 */
export const testnetCommon = EthereumCommon.forCustomChain(
  'mumbai',
  {
    name: 'testnet',
    networkId: (coins.get('tmaticl').network as EthereumNetwork).chainId,
    chainId: (coins.get('tmaticl').network as EthereumNetwork).chainId,
  },
  'bor',
);

/**
 * A Common object defining the chain and the hardfork for MaticL Mainnet
 */
export const mainnetCommon = EthereumCommon.forCustomChain(
  'mainnet',
  {
    name: 'mainnet',
    networkId: (coins.get('maticl').network as EthereumNetwork).chainId,
    chainId: (coins.get('maticl').network as EthereumNetwork).chainId,
  },
  'bor',
);
