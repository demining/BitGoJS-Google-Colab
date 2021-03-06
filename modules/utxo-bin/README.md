# `utxo-bin`

This repository contains a CLI tool for parsing BitGo wallet transactions (withdrawals) and
formatting them for terminal output.

## Sample Usage

```
» jq -r '.transaction.hex' \
  ../utxo-lib/test/integration_local_rpc/fixtures/testnet/v1/spend_p2shP2wsh.json |
  yarn ts-node bin/index.ts parse -n bitcoin -

reading from stdin
transaction
├── id: a7b64a92c6fb7e0c6ea0b95c0db8a3253347d22f76562df4dc187ed5d442767b
├── version: 1
├── hasWitnesses: true
├─┬ inputs: 2
│ ├─┬ 0: 61268e441d4078474679c063d1c268b5098163410553329dac0c8069f51bba97:0
│ │ ├── script: 2200201553f31a3e25e770b7bc857b82909e83734dbfe4bcdb5a5e6fc419b6920c398a
│ │ ├── witness: witnessscripthash
│ │ └─┬ signature: p2shP2wsh
│ │   └── buffers: 72 72
│ └─┬ 1: 1761eea952ede40e9f363134f8ee4fb72658f02c4fbb13c882bb2f020a9e512e:1
│   ├── script: 2200201553f31a3e25e770b7bc857b82909e83734dbfe4bcdb5a5e6fc419b6920c398a
│   ├── witness: witnessscripthash
│   └─┬ signature: p2shP2wsh
│     └── buffers: 72 71
└─┬ outputs: 2
  └─┬ 0: 34qSMWWEvrKnykAwMYLyjsKUfD976EjRJL
    └── value: 1.99999
```

With `--all`:

```
» jq -r '.transaction.hex' \
  ../utxo-lib/test/integration_local_rpc/fixtures/testnet/v1/spend_p2shP2wsh.json |
  yarn ts-node bin/index.ts parse --all -n bitcoin -

reading from stdin
transaction
├── id: a7b64a92c6fb7e0c6ea0b95c0db8a3253347d22f76562df4dc187ed5d442767b
├── version: 1
├── hasWitnesses: true
├─┬ inputs: 2
│ ├─┬ 0: 61268e441d4078474679c063d1c268b5098163410553329dac0c8069f51bba97:0
│ │ ├─┬ script: scripthash
│ │ │ └─┬ 0: 00201553f31a3e25e770b7bc857b82909e83734dbfe4bcdb5a5e6fc419b6920c398a
│ │ │   └── asm: 
│ │ │       OP_0
│ │ │       1553f31a3e25e770b7bc857b82909e83734dbfe4bcdb5a5e6fc419b6920c398a
│ │ ├─┬ witness: witnessscripthash
│ │ │ ├── 0: []
│ │ │ ├── 1: 3045022100cb6125485a4e9e2d98dafde8074a29d43ef28ffdd34f0d7f8048423f1fd54c01022065798d67d21f18383db7c4e9532e497b1b54d7e9c3676a079d9502cd0663963c01
│ │ │ ├── 2: 3045022100c3a36135223671fac881d4a48f16b2698500887ac91530b4145000ba4950967902200737c216d2cc705b3d6d88d8443870be168c9bfad2525795ac14ec4ea3598ca801
│ │ │ └─┬ 3: 5221028fedaf75b5b08cddf3bf4631c658b68ee6766a8e999467a641d7cb7aaaecec972103316bc27d95b96418349afc6298c259bb999c6e8f39a7217787ad53602be7c1472102e21c29b4a7eeace9c7a8cefb568ca00c86ff9bf5e79e07e5442c29d4a0950d0453ae
│ │ │   └── asm: 
│ │ │       OP_2
│ │ │       028fedaf75b5b08cddf3bf4631c658b68ee6766a8e999467a641d7cb7aaaecec97
│ │ │       03316bc27d95b96418349afc6298c259bb999c6e8f39a7217787ad53602be7c147
│ │ │       02e21c29b4a7eeace9c7a8cefb568ca00c86ff9bf5e79e07e5442c29d4a0950d04
│ │ │       OP_3
│ │ │       OP_CHECKMULTISIG
│ │ └─┬ signature: p2shP2wsh
│ │   ├── 0: 3045022100cb6125485a4e9e2d98dafde8074a29d43ef28ffdd34f0d7f8048423f1fd54c01022065798d67d21f18383db7c4e9532e497b1b54d7e9c3676a079d9502cd0663963c01
│ │   └── 1: 3045022100c3a36135223671fac881d4a48f16b2698500887ac91530b4145000ba4950967902200737c216d2cc705b3d6d88d8443870be168c9bfad2525795ac14ec4ea3598ca801
│ └─┬ 1: 1761eea952ede40e9f363134f8ee4fb72658f02c4fbb13c882bb2f020a9e512e:1
│   ├─┬ script: scripthash
│   │ └─┬ 0: 00201553f31a3e25e770b7bc857b82909e83734dbfe4bcdb5a5e6fc419b6920c398a
│   │   └── asm: 
│   │       OP_0
│   │       1553f31a3e25e770b7bc857b82909e83734dbfe4bcdb5a5e6fc419b6920c398a
│   ├─┬ witness: witnessscripthash
│   │ ├── 0: []
│   │ ├── 1: 3045022100f0279fa27d0f85c4c3ee7ea3104963bd88ec02f62f23ae0b73d122293e58c7b8022024b8c9dca8d9d77bda69da70282a45422c2baf0d4a05ecbe57a48b65f92d950d01
│   │ ├── 2: 304402203bb213db0b4842ea5f8c1b9290c8b42dbe65f72bee29e4ad7e8d57e5f16390010220347df34c34a4df5fabe8571c7168c8111df7275a56672126f434bdc44fea6c5901
│   │ └─┬ 3: 5221028fedaf75b5b08cddf3bf4631c658b68ee6766a8e999467a641d7cb7aaaecec972103316bc27d95b96418349afc6298c259bb999c6e8f39a7217787ad53602be7c1472102e21c29b4a7eeace9c7a8cefb568ca00c86ff9bf5e79e07e5442c29d4a0950d0453ae
│   │   └── asm: 
│   │       OP_2
│   │       028fedaf75b5b08cddf3bf4631c658b68ee6766a8e999467a641d7cb7aaaecec97
│   │       03316bc27d95b96418349afc6298c259bb999c6e8f39a7217787ad53602be7c147
│   │       02e21c29b4a7eeace9c7a8cefb568ca00c86ff9bf5e79e07e5442c29d4a0950d04
│   │       OP_3
│   │       OP_CHECKMULTISIG
│   └─┬ signature: p2shP2wsh
│     ├── 0: 3045022100f0279fa27d0f85c4c3ee7ea3104963bd88ec02f62f23ae0b73d122293e58c7b8022024b8c9dca8d9d77bda69da70282a45422c2baf0d4a05ecbe57a48b65f92d950d01
│     └── 1: 304402203bb213db0b4842ea5f8c1b9290c8b42dbe65f72bee29e4ad7e8d57e5f16390010220347df34c34a4df5fabe8571c7168c8111df7275a56672126f434bdc44fea6c5901
└─┬ outputs: 2
  └─┬ 0: 34qSMWWEvrKnykAwMYLyjsKUfD976EjRJL
    └── value: 1.99999
```
