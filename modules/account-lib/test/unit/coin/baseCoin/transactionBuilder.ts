import sinon from 'sinon';
import should from 'should';
import { TestTransactionBuilder } from '../../../resources/testTransactionBuilder';
import { TestTransaction } from '../../../resources/testTransaction';

describe('Transaction builder', () => {
  let txBuilder;
  let sandbox: sinon.SinonSandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    txBuilder = new TestTransactionBuilder();
  });

  afterEach(() => {
    sandbox.restore();
  });

  it('should sign a transaction that is valid', () => {
    const testTx = sinon.createStubInstance(TestTransaction);
    testTx.canSign.returns(true);
    const validateKey = sinon.spy(txBuilder, 'validateKey');

    txBuilder.from(testTx);
    txBuilder.sign({ key: 'validKey' });

    sandbox.assert.calledOnce(validateKey);
  });

  it('should sign a transaction with an invalid signature', () => {
    const testTx = sinon.createStubInstance(TestTransaction);
    testTx.canSign.returns(false);
    const validateKey = sinon.spy(txBuilder, 'validateKey');

    txBuilder.from(testTx);
    should.throws(() => txBuilder.sign({ key: 'invalidKey' }));

    sandbox.assert.calledOnce(validateKey);
  });

  it('should parse a valid transaction', () => {
    const testTx = sinon.createStubInstance(TestTransaction);
    testTx.canSign.returns(true);
    const validateRawTransaction = sinon.spy(txBuilder, 'validateRawTransaction');
    const fromImplementation = sinon.spy(txBuilder, 'fromImplementation');

    txBuilder.from(testTx);

    sandbox.assert.calledOnce(validateRawTransaction);
    sandbox.assert.calledOnce(fromImplementation);
  });

  it('should build a valid transaction', () => {
    const testTx = sinon.createStubInstance(TestTransaction);
    testTx.canSign.returns(true);
    const validateTransaction = sinon.spy(txBuilder, 'validateTransaction');
    const buildImplementation = sinon.spy(txBuilder, 'buildImplementation');

    txBuilder.from(testTx);
    txBuilder.build();

    sandbox.assert.calledOnce(validateTransaction);
    sandbox.assert.calledOnce(buildImplementation);
  });

  it('should verified validity windows params', () => {
    const testTx = sinon.createStubInstance(TestTransaction);
    testTx.canSign.returns(true);
    txBuilder.from(testTx);
    txBuilder.build();
    let validityWindow;

    let params = {};
    validityWindow = txBuilder.getValidityWindow(params);
    validityWindow.should.have.properties(['firstValid', 'lastValid', 'minDuration', 'maxDuration', 'unit']);
    validityWindow.firstValid.should.be.equal(0);
    validityWindow.lastValid.should.be.equal(100000);
    validityWindow.minDuration.should.be.equal(100000);
    validityWindow.maxDuration.should.be.equal(100000);
    validityWindow.unit.should.be.equal('blockheight');

    params = {
      firstValid: 10,
      lastValid: 11,
      minDuration: 10,
      maxDuration: 20,
      unit: 'timestamp',
    };
    validityWindow = txBuilder.getValidityWindow(params);
    validityWindow.should.have.properties(['firstValid', 'lastValid', 'minDuration', 'maxDuration', 'unit']);
    validityWindow.firstValid.should.be.equal(10);
    validityWindow.lastValid.should.be.equal(20);
    validityWindow.minDuration.should.be.equal(10);
    validityWindow.maxDuration.should.be.equal(20);
    validityWindow.unit.should.be.equal('timestamp');

    params = {
      firstValid: 10,
      lastValid: 23,
      minDuration: 10,
      maxDuration: 20,
      unit: '',
    };
    validityWindow = txBuilder.getValidityWindow(params);
    validityWindow.should.have.properties(['firstValid', 'lastValid', 'minDuration', 'maxDuration', 'unit']);
    validityWindow.firstValid.should.be.equal(10);
    validityWindow.lastValid.should.be.equal(23);
    validityWindow.minDuration.should.be.equal(10);
    validityWindow.maxDuration.should.be.equal(20);
    validityWindow.unit.should.be.equal('blockheight');

    params = {
      firstValid: 10,
      lastValid: 23,
      minDuration: 10,
      maxDuration: 5,
      unit: '',
    };
    validityWindow = txBuilder.getValidityWindow(params);
    validityWindow.should.have.properties(['firstValid', 'lastValid', 'minDuration', 'maxDuration', 'unit']);
    validityWindow.firstValid.should.be.equal(10);
    validityWindow.lastValid.should.be.equal(20);
    validityWindow.minDuration.should.be.equal(10);
    validityWindow.maxDuration.should.be.equal(10);
    validityWindow.unit.should.be.equal('blockheight');
  });
});
