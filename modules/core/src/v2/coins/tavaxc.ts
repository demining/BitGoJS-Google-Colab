/**
 * @prettier
 */
import { BaseCoin } from '../baseCoin';
import { BitGo } from '../../bitgo';
import { BaseCoin as StaticsBaseCoin } from '@bitgo/statics';

import { AvaxC } from './avaxc';

export class TavaxC extends AvaxC {
  protected constructor(bitgo: BitGo, staticsCoin?: Readonly<StaticsBaseCoin>) {
    super(bitgo, staticsCoin);
  }

  static createInstance(bitgo: BitGo, staticsCoin?: Readonly<StaticsBaseCoin>): BaseCoin {
    return new TavaxC(bitgo, staticsCoin);
  }
}
