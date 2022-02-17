import { TypeRegistry } from '@substrate/txwrapper-core/lib/types';
import { getRegistry } from '@substrate/txwrapper-polkadot';
import { PolkadotSpecNameType } from '@bitgo/statics';

export class SingletonRegistry {
  private static instance: TypeRegistry;
  private static material: any;
  static getInstance(material) {
    if (material !== SingletonRegistry.material) {
      SingletonRegistry.material = material;
      SingletonRegistry.instance = getRegistry({
        chainName: material.chainName,
        specName: material.specName as PolkadotSpecNameType,
        specVersion: material.specVersion,
        metadataRpc: material.metadata as `0x${string}`,
      });
    }
    return SingletonRegistry.instance;
  }
}

module.exports = SingletonRegistry;
