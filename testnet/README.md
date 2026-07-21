# Quantova testnet bring up

This brings up a Quantova public testnet node with a faucet, so people can create a wallet and receive
TQTOV to transact with. Everything here is ours. The chain is not a fork of Ethereum or Solidity, the
addresses are Q1, the unit is Quon, and the signatures are post quantum.

## What you need

The `quantovad` daemon from this repository and the `qcore` binary from QCore.rs, both built and on
PATH or pointed at by the QUANTOVAD and QCORE environment variables.

```
cargo build --release --bin quantovad
cargo build --release --manifest-path ../QCore.rs/Cargo.toml --bin qcore
```

## Generate the genesis and the config

```
QCORE=./target/release/qcore OUT=./testnet-live CHAIN_ID=Q-test-net-1 ./testnet/setup.sh
```

This creates a fresh faucet wallet, writes the genesis file and the node config under `OUT`, and prints
the faucet seed once. Save that seed. It funds the faucet account and it is never written into the
genesis or committed anywhere, only the faucet public key goes into the genesis so the account can
sign from the first block.

## Run the node and the faucet

```
quantovad --config ./testnet-live/node.conf --dev
cd ../Transparency-Website/faucet-service
FAUCET_OPERATOR_SEED=<the seed setup printed> FAUCET_RPC=http://127.0.0.1:8645 npm start
```

The node serves the gateway on the configured RPC address, the faucet dispenses TQTOV to a Q1 address
over that gateway through the QCore SDK, and the explorer indexer reads the same gateway to fill the
explore page. A person onboards with the QCore SDK or the qcore terminal client. They create a wallet,
claim from the faucet, and send a transfer.

## Two things to know before a public run

The validator identity is derived from its id, which is correct while one operator runs every
validator, and the daemon refuses to start without the development flag for exactly that reason. A
second party running a validator needs operator held keys, one secret per validator that no one else
can derive, which is a separate step before the network leaves one pair of hands.

The slot budget is the height horizon. The sortition keys are one time, so the chain halts honestly at
that height. The default of one hundred thousand blocks is about a day at a one second block interval.
A longer testnet raises the horizon at the cost of larger key trees and more startup time, and running
with no horizon needs the epoch and key rotation mechanism, which is a known open item. A public
testnet either sets a horizon it is willing to reach and resets, or waits for key rotation.

Contract deploy and call transactions are held off the network until compute is priced by the meter
and a per block budget bounds it, so a submitter cannot make every validator do unbounded work for a
flat fee. Native transfers, staking, and governance are live. This is enforced in the node, not left
to the operator.
