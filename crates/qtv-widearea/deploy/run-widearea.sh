#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

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

ADDRS=""
for h in "${HOST_ARR[@]}"; do
  if [ -z "$ADDRS" ]; then ADDRS="$h:$PORT"; else ADDRS="$ADDRS,$h:$PORT"; fi
done

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
COORD="${QTV_WA_COORDINATOR:-qtv-widearea}"
if command -v "$COORD" >/dev/null 2>&1 || [ -x "$COORD" ]; then
  QTV_WA_COLLECT="$OUT" "$COORD"
else
  echo "the qtv-widearea coordinator binary was not found; the raw host results are in $OUT."
  echo "set QTV_WA_COORDINATOR to its path and rerun with QTV_WA_COLLECT=$OUT to gather them."
fi

exit "$fail"
