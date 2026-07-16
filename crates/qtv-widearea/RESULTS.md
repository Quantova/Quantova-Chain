# Wide area harness results

These results come from the qtv-widearea harness in this crate, run on one host over
localhost sockets to validate the harness before any host is provisioned. Every figure
here is a loopback multi process figure over real sockets with near zero propagation,
exactly as the loopback run was labelled. It is parallel per process compute plus the
loopback socket cost of moving the sealed records between processes on one host. It is
not a geographic network throughput and not a real global finality, because the sockets
are localhost and carry no inter host bandwidth or propagation latency. The network
propagation figure this harness exists to produce comes only from a real run across
regions driven by the deploy script, and no such figure is recorded here.

## What this validates

The wide area harness is the loopback multi process harness with the localhost peer
addresses replaced by real addresses read from configuration, plus the honest degradation
path a wide area run needs. This crate validates on one host that the harness stands up
over the real qtv-net mesh, finalises, and that every up host agrees on a byte identical
chain, and that the fault injection test degrades honestly under a slow host, one host
dropping, and two hosts dropping. That is the proof the wide area number will be honest
before the founder pays for the hosts.

## Reference host and build

The host is an Apple M4, ten cores, sixteen gigabytes. The build is the release profile
at optimisation level three. The run uses four validator processes and one coordinator
process on this one host. The committee size read from a real finalised block is four.
The supermajority to finalise is three. The single transport port a real deployment fixes
is 40404, and the local run binds a distinct localhost port per process since one host
cannot share one port across several processes.

## The stand up

The harness stands up over the real qtv-net post quantum mesh, finalises the whole run,
and every up host finalises the byte identical chain, checked before any figure is taken.
A healthy run of four up hosts at a small block width finalises every height at view zero
with no leader rotation, so the finality is the parallel per process compute plus the
loopback socket cost, near zero propagation. The exact millisecond figures move a little
between runs and are near zero propagation figures, not network figures.

## The fault injection

The fault injection test stands the real validator binary up on this one host over real
localhost sockets and injects the three faults a wide area run will meet, then asserts the
harness degrades honestly under each. The test passes. A representative run at a committee
of four, a small block width, and a short view timeout showed the following, all loopback
multi process near zero propagation figures that show the direction of each fault rather
than any network number.

```
                              healthy      slow host      one host down    two hosts down
heights finalised                  24            24                  24        stall, none
transactions finalised            288           288                 288                  0
heights via a view change           0             6                   3          stall, na
sustained throughput (tx/s)       855            38                 195        stall, none
finality p50 (ms)                14.2         166.2                11.0          stall, na
finality p99 (ms)                16.1         789.9               420.4          stall, na
finality max (ms)                16.2         792.5               420.8          stall, na
```

The slow host is present and attesting but slow to send every message, so the round, which
waits for every online member, waits for it, and the finality distribution widens with its
tail moving from about sixteen milliseconds to about eight hundred, some of it in heights
the slow host led badly enough to rotate. One host dropping leaves three of four, still the
supermajority, so the run continues and finalises the whole height count on the byte
identical chain, but the dropped host's heights rotate through a view change, so the median
stays fast on the heights an up host leads while the tail carries the rotated heights and
the finalised throughput falls by about four times. Two hosts dropping leaves two of four,
below the supermajority, so no height finalises and the run reports the stall and the zero
finalised count as a stall, never a fabricated number.

## The network figures, pending the real run

No network figure is recorded here, because there are no remote hosts. The founder's run
across regions fills this section with the real figures, committed in this q-prover form
with the host regions and the measured inter host round trips, the profile, the process
count, the committee size, the block width, the transaction mix, the run length, the
method, then the figures. The finding is the delta from the loopback finality at the same
committee and width, and that delta is the propagation cost.

## Reproduce

Build and run in release from the Quantova-Chain workspace. The local stand up validation
runs the coordinator, which spawns one validator process per validator over the real
qtv-net mesh, checks the byte identity across the up hosts, and reports the finality
distribution.

```
QTV_WA_VALIDATORS=4 QTV_WA_ACCOUNTS=64 QTV_WA_HEIGHTS=40 QTV_WA_WARMUP=2 \
  QTV_WA_VIEWMS=800 cargo run --release -p qtv-widearea --bin qtv-widearea
```

The fault injection test drives the same validator binary through the three faults and
asserts the honest degradation.

```
cargo test --release -p qtv-widearea --test fault_injection
```

The faults can be reproduced by hand against the coordinator. QTV_WA_DOWN drops the given
host indices and QTV_WA_SLOW slows a host by index and milliseconds.

```
QTV_WA_ACCOUNTS=12 QTV_WA_HEIGHTS=24 QTV_WA_VIEWMS=400 QTV_WA_SLOW=3:150 \
  cargo run --release -p qtv-widearea --bin qtv-widearea
QTV_WA_ACCOUNTS=12 QTV_WA_HEIGHTS=24 QTV_WA_VIEWMS=400 QTV_WA_DOWN=3 \
  cargo run --release -p qtv-widearea --bin qtv-widearea
QTV_WA_ACCOUNTS=12 QTV_WA_HEIGHTS=24 QTV_WA_VIEWMS=400 QTV_WA_STALLSECS=5 QTV_WA_DOWN=2,3 \
  cargo run --release -p qtv-widearea --bin qtv-widearea
```
