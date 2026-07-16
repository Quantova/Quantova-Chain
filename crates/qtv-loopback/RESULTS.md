# Loopback multi process run results

These numbers come from the qtv-loopback harness in this crate. The driver runs both
sides on one host and prints the same fields to standard output. Rerun it with the
command at the end and the figures move a little between runs. Every figure here is a
loopback multi process figure over real localhost sockets with near zero propagation.
It is parallel per process compute plus the loopback socket cost of moving the sealed
records between processes on one host. It is not a geographic network throughput and
not a real global finality, because the sockets are localhost and carry no inter host
bandwidth or propagation latency.

## The question this settles

The in process baseline runs every committee member's compute serially inside one
process over an in memory duplex, so its finality at a committee of four is serial
single host compute. This run gives each validator its own operating system process
and lets the processes talk over real localhost TCP sockets through the real qtv-net
post quantum channel, so the committee computes in parallel with near zero
propagation. It changes exactly one thing against the in process baseline. Serial
becomes parallel. Nothing else changes. The finalised chains are byte identical
between the two runs, which is the proof that only the one variable moved.

## Reference host and build

The host is an Apple M4, ten cores, sixteen gigabytes. The build is the release
profile at optimisation level three. The loopback run uses four validator processes
and one driver process. The in process baseline runs four validator instances inside
one process. The committee size read from a real finalised block is four on both
sides. The supermajority to finalise is three.

## Configuration

Both sides run the identical configuration, so parallelism is the only difference. The
committee is four. The block width is two hundred and fifty distinct signing accounts,
each sending one transfer per height, so a block carries two hundred and fifty real
transactions. Each transaction carries a real 3309 byte module lattice signature over
a distinct key on a distinct state leaf and is verified on the ingress path. No
transaction is a no op. The committee is drawn by the real qtv-sampler one time key
sortition of consensus v0.4.0 with the minimum self stake floor on. The proposal is
disseminated as its real erasure coded shards under a SHA3 commitment and rebuilt from
any k. The attestations are real module lattice signatures and the finality
certificate is a real aggregate every process verifies.

## Method

Each side drives back to back heights of the same deterministic signed workload and
times the consensus work per height on the wall clock. The ingress process signs the
batch outside the timed region and the timed region covers the admission, the gossip,
the build, the attestation, the aggregation, and the finalisation, the same region the
in process baseline times. Only transactions in a genuinely finalised block are
counted, and only the transactions the block actually carried. The sustained
throughput is the finalised transactions over the consensus wall clock. The finality
is one sample per finalised block, the wall clock to build, attest, aggregate, and
verify that block across the committee, reported as a distribution with its tail. The
loopback figures are the ingress process's own measurement, the same node the in
process baseline measures.

## The measured figures

Both runs finalised the byte identical chain on every process and against the in
process baseline, checked before any figure was taken.

```
                                    in process serial      loopback multi process
                                    one host, in memory     real localhost TCP
heights finalised                          35                       60
transactions finalised                   8750                    15000
consensus wall clock (seconds)           60.1                     41.4
sustained throughput (tx per second)      146                      363
end to end throughput (tx per second)     136                      296
```

The sustained finalised throughput moves from 146 transactions a second serial to 363
transactions a second loopback multi process, a factor of 2.49 at this committee and
block width. The end to end throughput, which includes the client side signing, moves
from 136 to 296.

## Finality distribution with its tail

Each sample is one finalised block's wall clock across the committee.

```
                             in process serial      loopback multi process
median p50 (ms)                    1691.9                    686.3
p90 (ms)                           1845.0                    708.1
p99 (ms)                           1874.7                    736.1
maximum (ms)                       1876.1                    744.7
minimum (ms)                       1625.4                    659.7
```

The median finality per block moves from 1691.9 milliseconds serial to 686.3
milliseconds loopback multi process, a factor of 2.47. The serial figure sits in the
region of roughly 1.7 to 2.0 seconds across reruns, the serial single host compute the
baseline reports. The loopback figure holds near 0.68 to 0.69 seconds across reruns.

## What moved and what did not

Parallelism carries the whole move. The committee's compute went from serial in one
process to parallel across one process per validator over real qtv-net TCP sockets, and
the throughput rose by about 2.5 times and the per block finality fell by about the
same, so the parallelism gain is real and large at a committee of four. The workload,
the committee, the sortition, the module lattice attestations, the certificate, and the
coded proposal dissemination are byte identical between the two runs, so nothing other
than the parallelism and the loopback socket cost moved. The sockets are localhost, so
there is no inter host bandwidth and no geographic propagation in either figure. This
is not a network throughput and not a real global finality. A geographically
distributed validator set would add real propagation latency this run deliberately
excludes so that parallelism is isolated on its own.

## Run length and the sortition slot ceiling

The consensus v0.4.0 one time key sortition commits each validator's tree to a fixed
slot count, sixty four by the pinned default, one slot per height, and a run cannot
finalise more heights than that without the sortition refusing a slot past the
commitment. The in process serial baseline reaches sixty seconds of consensus wall
clock in thirty five blocks, over a minute, well under the ceiling. The loopback run is
about two and a half times faster per block, so it reaches the sixty block cap of this
run in 41.4 seconds, under a minute, because the same sixty four slot ceiling bounds
the height count and the faster per block finality spends the slots sooner. Both
windows are sustained over dozens of finalised blocks and neither is a burst. Reaching
a full minute of loopback wall clock would need more heights than the sixty four slot
tree serves, which is a sortition sizing change in the pinned consensus repo and a
founder decision on pinning. It is not taken here, so the loopback sustained window is
whatever fits under the committed slot count at this per block speed.

## Reproduce

Build and run in release from the Quantova-Chain workspace.

```
QTV_MP_VALIDATORS=4 QTV_MP_ACCOUNTS=250 QTV_MP_SECS=60 QTV_MP_WARMUP=2 \
  QTV_MP_HEIGHTCAP=60 cargo run --release -p qtv-loopback --bin qtv-loopback
```

The variables are the validator process count, the distinct signing accounts that set
the block width, the target sustained consensus duration in seconds, the warmup heights
that are not counted, and the height cap that keeps the run under the one time
sortition tree's committed slot count. The driver spawns one qtv-validator process per
validator, rendezvous their listener ports, and prints the host, the process count, the
committee, the byte identity checks, and the two figures side by side with the finality
distribution.
