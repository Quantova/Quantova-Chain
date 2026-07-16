#!/usr/bin/env bash
#
# Deploy and run the Quantova wide area finality harness across real hosts.
#
# This is the coordinator. It starts one validator on each host, lets them rendezvous
# over the real qtv-net mesh, drives the sustained signed workload from the ingress
# host, collects each host's measurement, and gathers the finality distribution. The
# founder runs this from a machine that can reach every host over SSH; it does not have
# to be one of the validator hosts.
#
# WHAT THIS SCRIPT ASSUMES, STATED PLAINLY.
#   1. Reachable addresses. Every address in HOSTS is reachable from this coordinator
#      over SSH, and every host reaches every other host on the transport port over the
#      internet. The hosts are geographically spread for the run to measure real
#      propagation; in one datacentre the propagation is near loopback and the run adds
#      nothing over the loopback figure.
#   2. Exactly one open port. The single transport TCP port is 40404, the TRANSPORT_PORT
#      constant in the qtv-widearea crate. Open exactly this one port inbound on every
#      validator host firewall. Nothing else needs to be open inbound for the run; the
#      coordinator reaches the hosts over SSH, and the validators reach each other on
#      40404.
#   3. The binary is present on each host. The qtv-validator-wide binary is already at
#      REMOTE_BIN on every host, built for that host's architecture, and the store
#      directory REMOTE_BASE is writable there. This script does not build or copy the
#      binary; provisioning the binary and the port is ordinary deployment setup.
#
# The rendezvous needs no extra service. The transport port is fixed and every host is
# handed the full ordered address list, so each validator dials every peer at its known
# address with a short retry and accepts the peers that dial it, and the mesh handshake
# barrier holds each host until every up peer is connected before the round starts.
#
# Host identity. A validator's network identity is derived from its index, so the host
# at index i in HOSTS must be started with QTV_WA_INDEX=i, which this script does. Keep
# the HOSTS order fixed across a run so the identities and the addresses line up.
#
# Usage:
#   HOSTS="ip0 ip1 ip2 ip3" SSH_USER=ubuntu \
#     REMOTE_BIN=/opt/quantova/qtv-validator-wide REMOTE_BASE=/var/lib/quantova/wa \
#     ACCOUNTS=250 HEIGHTS=60 WARMUP=2 VIEWMS=4000 STALLSECS=60 \
#     ./run-widearea.sh
#
# The block width is ACCOUNTS, the run length is HEIGHTS measured heights, VIEWMS is the
# view timeout that must sit above the real round trip so propagation does not trip a
# spurious rotation, and STALLSECS is the per height stall guard. The run finalises a
# fixed number of heights so every host stops on the same height, which the notes explain.
set -euo pipefail

PORT=40404

HOSTS="${HOSTS:?set HOSTS to the space separated validator host addresses in index order}"
SSH_USER="${SSH_USER:-$(whoami)}"
REMOTE_BIN="${REMOTE_BIN:-/opt/quantova/qtv-validator-wide}"
REMOTE_BASE="${REMOTE_BASE:-/var/lib/quantova/wa}"
ACCOUNTS="${ACCOUNTS:-250}"
HEIGHTS="${HEIGHTS:-60}"
WARMUP="${WARMUP:-2}"
VIEWMS="${VIEWMS:-4000}"
STALLSECS="${STALLSECS:-60}"
UP="${UP:-}"
SLOWMS="${SLOWMS:-}"
OUT="${OUT:-./wa-results}"

read -r -a HOST_ARR <<< "$HOSTS"
N=${#HOST_ARR[@]}

# Build the ordered address list every validator reads its peers from, host joined to
# the one fixed transport port.
ADDRS=""
for h in "${HOST_ARR[@]}"; do
  if [ -z "$ADDRS" ]; then ADDRS="$h:$PORT"; else ADDRS="$ADDRS,$h:$PORT"; fi
done

# Default the up set to every host, so a plain run starts the whole committee. Pass UP
# to drop a host by leaving its index out, and SLOWMS as index:milliseconds to model a
# slow host, the same faults the injection test asserts.
if [ -z "$UP" ]; then
  UP=""
  for ((i=0; i<N; i++)); do
    if [ -z "$UP" ]; then UP="$i"; else UP="$UP,$i"; fi
  done
fi

echo "Quantova wide area run over $N hosts on transport port $PORT"
echo "  hosts        $HOSTS"
echo "  addresses    $ADDRS"
echo "  up set       $UP"
echo "  block width  $ACCOUNTS accounts, $HEIGHTS measured heights, $WARMUP warmup"
echo "  view timeout $VIEWMS ms, stall guard $STALLSECS s"
echo "  results into $OUT"
echo

mkdir -p "$OUT"

# Which host indices to start this run, the up set.
IFS=',' read -r -a UP_ARR <<< "$UP"

pids=()
for idx in "${UP_ARR[@]}"; do
  host="${HOST_ARR[$idx]}"
  slow=0
  if [ -n "$SLOWMS" ]; then
    for pair in ${SLOWMS//,/ }; do
      i="${pair%%:*}"; ms="${pair##*:}"
      if [ "$i" = "$idx" ]; then slow="$ms"; fi
    done
  fi
  echo "starting validator $idx on $host (slow ${slow} ms)"
  # Start the validator over SSH. Its RESULT line is its stdout, captured back over the
  # SSH channel into a per host result file; its progress is its stderr, kept in a log.
  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$SSH_USER@$host" \
    "QTV_WA_INDEX=$idx QTV_WA_ADDRS='$ADDRS' QTV_WA_UP='$UP' \
     QTV_WA_ACCOUNTS=$ACCOUNTS QTV_WA_HEIGHTS=$HEIGHTS QTV_WA_WARMUP=$WARMUP \
     QTV_WA_VIEWMS=$VIEWMS QTV_WA_STALLSECS=$STALLSECS QTV_WA_SLOWMS=$slow \
     QTV_WA_BASE='$REMOTE_BASE/node-$((idx+1))' \
     '$REMOTE_BIN' $idx" \
    > "$OUT/result-$idx.txt" 2> "$OUT/log-$idx.txt" &
  pids+=($!)
done

echo
echo "waiting for ${#pids[@]} validator(s) to finish the run ..."
fail=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then fail=1; fi
done

echo
echo "collected results into $OUT. gathering the finality distribution ..."
echo
# Report the collected results with the local coordinator binary in collect mode. It
# checks the hosts agree on a byte identical chain and prints the finality distribution.
# Point QTV_WA_COORDINATOR at the qtv-widearea binary on this coordinator machine.
COORD="${QTV_WA_COORDINATOR:-qtv-widearea}"
if command -v "$COORD" >/dev/null 2>&1 || [ -x "$COORD" ]; then
  QTV_WA_COLLECT="$OUT" "$COORD"
else
  echo "the qtv-widearea coordinator binary was not found; the raw host results are in $OUT."
  echo "set QTV_WA_COORDINATOR to its path and rerun with QTV_WA_COLLECT=$OUT to gather them."
fi

exit "$fail"
