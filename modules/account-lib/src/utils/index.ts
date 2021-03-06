import * as coinModules from '..';
import { BaseUtils } from '../coin/baseCoin';
import { coins } from '@bitgo/statics';
import { NotSupported } from '../coin/baseCoin/errors';

/**
 * Register the factory method for coin utils methods
 * throw if coin not supported
 * @param {String} coinName
 * @returns {BaseUtils}
 */
export function register(coinName: string): BaseUtils {
  const sanitizedCoinName = coins.get(coinName.trim().toLowerCase()).family;
  const key = Object.keys(coinModules)
    .filter((k) => coinModules[k].Utils)
    .find((k) => k.trim().toLowerCase() === sanitizedCoinName);
  if (key) {
    return new coinModules[key].Utils();
  }
  throw new NotSupported(`${coinName} util factory not supported`);
}
