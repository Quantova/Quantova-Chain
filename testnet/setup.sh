#!/usr/bin/env bash
#
# Bring up a Quantova public testnet node. This generates the faucet wallet, writes the genesis file
# and the node config, and prints the next steps. The operator holds the faucet seed. It is printed
# once and never written into the genesis or committed anywhere, only the faucet public key goes into
# the genesis so the faucet account can sign from the first block.
#
# Requirements: the qcore binary (from QCore.rs) and quantovad (from this repo) on PATH, or set QCORE
# and QUANTOVAD to their paths.
#
# Usage:
#   OUT=./testnet-live CHAIN_ID=Q-test-net-1 FAUCET_TQTOV=1000000 ./testnet/setup.sh
#
set -euo pipefail

QCORE="${QCORE:-qcore}"
OUT="${OUT:-./testnet-live}"
CHAIN_ID="${CHAIN_ID:-Q-test-net-1}"
FAUCET_TQTOV="${FAUCET_TQTOV:-1000000}"
RPC="${RPC:-127.0.0.1:8645}"
LISTEN="${LISTEN:-127.0.0.1:40404}"
# The height horizon. The sortition keys are one time, so the chain halts honestly at this height. A
# longer testnet raises this at the cost of larger validator key trees and more startup time. Running
# with no horizon needs the epoch and key rotation mechanism, which is a known open item, so a public
# testnet either sets a horizon it is willing to reach and resets, or waits for key rotation.
SLOTS="${SLOTS:-100000}"

mkdir -p "$OUT/store"

echo "Generating the faucet wallet"
FAUCET=$("$QCORE" new)
FAUCET_SEED=$(printf '%s\n' "$FAUCET" | awk '/^seed/{print $2}')
FAUCET_ADDR=$(printf '%s\n' "$FAUCET" | awk '/^address/{print $2}')
FAUCET_PUBKEY=$("$QCORE" pubkey "$FAUCET_SEED" 0 | awk '/^pubkey/{print $2}')

# One TQTOV is one million Quon, the base unit the ledger accounts in.
FAUCET_QUON=$(( FAUCET_TQTOV * 1000000 ))
GENESIS_TIME=$(date +%s)

cat > "$OUT/genesis.q" <<EOF
chain_id = $CHAIN_ID
genesis_time = $GENESIS_TIME
slots = $SLOTS
asset = TQTOV
fee_transfer_micro_usd = 500
fee_rate_micro_usd_per_qtov = 1000000
fee_native_unit = 1000000
fee_max_native = 1000
validator = 1 2000 online
account = 1 $FAUCET_PUBKEY $FAUCET_QUON
EOF

cat > "$OUT/node.conf" <<EOF
id = 1
store_dir = $OUT/store
listen = $LISTEN
genesis = $OUT/genesis.q
rpc = $RPC
block_interval_ms = 1000
view_timeout_ms = 2000
EOF

echo
echo "Genesis and config written under $OUT"
echo "Chain id     $CHAIN_ID"
echo "Faucet float $FAUCET_TQTOV TQTOV"
echo "Faucet addr  $FAUCET_ADDR"
echo "Height horizon $SLOTS blocks"
echo
echo "Save the faucet seed now. It is shown once and is not stored anywhere."
echo "  FAUCET_OPERATOR_SEED=$FAUCET_SEED"
echo
echo "Next steps"
echo "  1. Start the node"
echo "       quantovad --config $OUT/node.conf --dev"
echo "  2. Start the faucet with the seed above"
echo "       cd faucet-service && FAUCET_OPERATOR_SEED=<seed> FAUCET_RPC=http://$RPC npm start"
echo "  3. Point the explorer indexer at http://$RPC"
echo
echo "The --dev flag runs the operator held validator under the id derived key model, which is correct"
echo "while one operator runs every validator. A second party running a validator needs operator held"
echo "keys, which is a separate step before the network leaves one pair of hands."
