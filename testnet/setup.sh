#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

QCORE="${QCORE:-qcore}"
QUANTOVAD="${QUANTOVAD:-quantovad}"
OUT="${OUT:-./testnet-live}"
CHAIN_ID="${CHAIN_ID:-Q-test-net-1}"
FAUCET_TQTOV="${FAUCET_TQTOV:-1000000}"
STAKE="${STAKE:-2000}"
RPC="${RPC:-127.0.0.1:8645}"
LISTEN="${LISTEN:-127.0.0.1:40404}"
SLOTS="${SLOTS:-100000}"

mkdir -p "$OUT/store"

echo "Generating the faucet wallet"
FAUCET=$("$QCORE" new)
FAUCET_SEED=$(printf '%s\n' "$FAUCET" | awk '/^seed/{print $2}')
FAUCET_ADDR=$(printf '%s\n' "$FAUCET" | awk '/^address/{print $2}')
FAUCET_PUBKEY=$(FAUCET_SEED="$FAUCET_SEED" "$QCORE" pubkey env:FAUCET_SEED 0 | awk '/^pubkey/{print $2}')

FAUCET_QUON=$(( FAUCET_TQTOV * 1000000 ))
GENESIS_TIME=$(date +%s)

KEYSTORE="$OUT/store/keystore"
echo "Generating the node keystore and its published registration"
VALIDATOR_LINE=$("$QUANTOVAD" register --keystore "$KEYSTORE" --id 1 --stake "$STAKE" --online --slots "$SLOTS")

cat > "$OUT/genesis.q" <<EOF
chain_id = $CHAIN_ID
genesis_time = $GENESIS_TIME
slots = $SLOTS
asset = TQTOV
fee_transfer_micro_usd = 500
fee_rate_micro_usd_per_qtov = 1000000
fee_native_unit = 1000000
fee_max_native = 1000
$VALIDATOR_LINE
account = 1 $FAUCET_PUBKEY $FAUCET_QUON
EOF

cat > "$OUT/node.conf" <<EOF
id = 1
store_dir = $OUT/store
keystore = $KEYSTORE
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
SEED_FILE="$OUT/faucet.seed"
( umask 077; printf 'FAUCET_OPERATOR_SEED=%s\n' "$FAUCET_SEED" > "$SEED_FILE" )
echo "The faucet seed was written to $SEED_FILE (mode 600). Move it somewhere safe and"
echo "delete it from this host once stored. It is not written anywhere else."
echo
echo "Next steps"
echo "  1. Start the node"
echo "       quantovad --config $OUT/node.conf"
echo "  2. Start the faucet, taking the seed from the file rather than the command line"
echo "       cd faucet-service && set -a; . $SEED_FILE; set +a; FAUCET_RPC=http://$RPC npm start"
echo "  3. Point the explorer indexer at http://$RPC"
echo
echo "The node holds only its own secret in $KEYSTORE and reads every peer's public registration from"
echo "the genesis. To add a second validator, that operator runs 'quantovad register' on their own"
echo "machine over their own keystore and hands you the printed 'validator = ...' line for the genesis;"
echo "no party can reproduce another's key material."
