'use strict';

module.exports = {
  require: 'ts-node/register',
  timeout: '20000',
  reporter: 'mochawesome',
  'reporter-option': ['cdn=true', 'json=false'],
  exit: true,
  spec: ['test/unit/*.ts'],
};
