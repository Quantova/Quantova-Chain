# The live in process multi node harness

## What this is

`qtv-live` stands up several real validator instances, drives a real signed
transaction workload through them to a real aggregated finality certificate, and
measures two numbers on the wall clock: the sustained finalised throughput and the
finality latency as a distribution with its tail. It measures. It does not tune the
workload to a favourable path, and the number it measures is the number it reports.

## Where it lives and why

The harness lives in Quantova-Chain, next to `qtv-devnet`, and drives the devnet
through path dependencies. The devnet is the real multi node substrate: several
`DevNode` instances that gossip real consensus over the real qtv-net post quantum
channel to a real finality certificate. Driving it from within the same workspace
measures the exact current node and consensus, not a lagging git tag, and it builds,
tests, and runs offline where the whole stack is already vendored. Quantova-Bench,
the other measurement home, pins the stack by git tag and models the finality and
throughput from component costs and a synthetic global topology; it does not depend
on the devnet and cannot drive the real multi node consensus without that dependency.
So the modelled figure lives in Quantova-Bench, labelled modelled there, and the
measured live figure lives here, next to the substrate it measures.

## The two numbers, and exactly what they mean

1. Sustained finalised throughput. The finalised transactions divided by the
   consensus wall clock, over a run driven until the consensus wall clock reaches at
   least a minute. Only transactions in a genuinely finalised block are counted, and
   only the transactions the block actually included. Client side transaction signing
   is timed separately and excluded from this figure; an end to end figure that
   includes it is reported alongside.

2. Finality latency as a distribution with its tail. One sample per finalised block,
   the real wall clock to build, attest, aggregate, and verify that block across the
   committee. Reported as the median, the ninetieth and ninety ninth percentiles, and
   the maximum over the run, sampled from real finalised blocks, never a single point.

## What is real

- Several real validator instances, each with its own module lattice key.
- Real committee sortition from qtv-sampler over the beacon.
- Real block production, real execution through the virtual machine to a real state
  root, real module lattice attestations, and a real aggregated finality certificate
  that every node verifies before it advances. The certificate is not a stub.
- Real transactions, each carrying a real module lattice signature of 3309 bytes,
  moving value between distinct accounts, verified on the ingress path. No no op
  transactions.
- The real qtv-net post quantum transport: every gossip byte is sealed and opened
  through an ML-KEM and ML-DSA handshake with a ChaCha20-Poly1305 record layer.

## What is in process, not multi machine, and so not measured

This pass is an in process multi node run, not a live multi machine network. It is
labelled as such at every number.

- The validators run as several instances inside one operating system process on one
  host. Every committee member's compute runs serially on that host, not in parallel
  across machines.
- The transport is an in memory duplex, not a socket to another machine. The seal and
  open cryptography is paid for real, but the network transfer is a memory copy, so
  inter node bandwidth and propagation latency are not measured.
- The devnet schedules the consensus round on a logical clock, so the modelled slot
  and view timeouts are logical, not wall clock. The finality figure reported here is
  the measured wall clock compute per block, not those logical slots, and not the wall
  clock finality a globally distributed validator set would see. That network bound
  finality and the bandwidth bound throughput are the modelled figures in
  Quantova-Bench, kept separate and labelled modelled there.

The two honest consequences: the throughput is a compute bound, network free, single
host rate with the members serial, so it is not a multi machine network throughput;
the finality distribution is the in process compute floor per block, excluding real
network propagation. Both are stated in the code beside the number.

## The sortition, stated plainly

The task this harness serves asked for the one time key sortition with the stake
floor on, the closed sortition gate. That construction lives in the QRC-CONSENSUS
working tree and is not yet tagged. The devnet pins consensus v0.3.0, whose sortition
is the module lattice (ML-DSA) verifiable random draw, the grindable predecessor the
one time construction replaces. So this harness measures the module lattice draw
sortition, real and NIST module lattice, but not the one time construction, and it
enforces no stake floor at this pin.

Wiring the one time construction into the live harness is a cross repo step: a new
QRC-CONSENSUS tag for the one time sortition, then a qtv-devnet pin bump with the
attestation membership moved from the draw to the one time credential and the stake
floor turned on. That is a founder decision on release and pinning across two repos.
It is flagged here and not taken in this pass, and it is the first item of remaining
work.

## The block width bound

A single gossiped proposal carries the whole block body as one qtv-net record, and a
record's plaintext is bounded at one mebibyte. At the 3309 byte module lattice
signature the transaction is about 3.5 kilobytes on the wire, so the block width is
bounded at about three hundred transactions per block over the plain gossip path. The
harness estimates the body size from one real signed transaction and refuses an
oversize block width with a clear message rather than failing inside the transport.
Lifting this bound is the erasure coded block dissemination the devnet already carries
in `coded.rs` but the round loop does not yet use for the proposal; that is the second
item of remaining work.

## Remaining work

1. Bump the devnet to the one time key sortition with the stake floor, the flagged
   cross repo founder decision above.
2. Disseminate the proposal over the erasure coded path so the block width is not
   bounded by the single record size.
3. A true multi machine run: the same harness over qtv-net sockets across hosts, which
   is what finally measures inter node bandwidth and propagation latency and turns the
   in process finality compute floor into a real network finality.

## Measured figures on the reference host

The host is an Apple M4, ten cores, sixteen gigabytes, the same reference host the
modelled benchmark uses, built in release. The figures move a little between runs;
rerun for current ones. They are measured, in process, on one host, and carry the
caveats above: the throughput is compute bound, network free, and serial over the
committee on one host, and the finality is the in process compute time per block
excluding real network propagation. They are not multi machine network figures.

Two configurations, each a real run over the stated committee and block width.

- Four validators, committee four, supermajority three, block width 250. Over 73
  seconds of consensus wall clock it finalised 30 blocks and 7500 transactions.
  Sustained finalised throughput about 103 transactions a second, consensus only,
  about 96 end to end with client signing. Finality per block: median about 2360
  milliseconds, p90 about 2840, p99 about 3010, maximum about 3050.

- Seven validators, committee seven, supermajority five, block width 100. Over 45
  seconds of consensus wall clock it finalised 37 blocks and 3700 transactions.
  Sustained finalised throughput about 82 transactions a second, consensus only,
  about 78 end to end. Finality per block: median about 1210 milliseconds, p90 about
  1340, p99 about 1490, maximum about 1540.

The per block time is dominated by the committee re verifying the block serially on
one host, so it rises with both the block width and the validator count, which is
the serial single host artefact named above and not a property of the consensus. A
real multi machine network verifies the members in parallel and pays real network
latency instead; measuring that is the third item of remaining work.

## Reproduce

Build and run in release from the Quantova-Chain workspace. Parameters are read from
the environment, so a short local run is available.

```
QTV_LIVE_VALIDATORS=4 QTV_LIVE_ACCOUNTS=250 QTV_LIVE_SECS=70 cargo run --release -p qtv-live
```

The variables are the validator instance count, the distinct signing accounts that
set the block width, and the target sustained consensus duration in seconds. The
harness prints the host, the instance count, the committee size read from a real
finalised block, the realism labels, and the two measured numbers with their caveats.
