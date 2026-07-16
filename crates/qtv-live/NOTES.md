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

The devnet pins consensus v0.4.0, the one time key sortition with the minimum self
stake floor on. Committee membership and proposer eligibility are drawn and rechecked
as a committed one time preimage with its Merkle path against the registered root, and
an account below the floor is not eligible. The attestation over that membership
carries the module lattice signature. This is the grinding resistant successor to the
v0.3.0 module lattice verifiable random draw, which is no longer on the path. The
sortition is real and NIST module lattice.

## The block width

The devnet no longer carries a proposal as one whole qtv-net record. It codes the
block the proposal commits to into k data shards and n minus k parity shards under a
SHA3 commitment and disseminates the shards over the overlay, each shard within the one
mebibyte record plaintext bound, and every node rebuilds the block from any k shards
and verifies it against the header before use. So the block width is no longer bounded
by the record size. The harness estimates the old single record width from one real
signed transaction, about three hundred transactions at the 3309 byte module lattice
signature, and drives a width above it, which the single record path would have
refused.

## Remaining work

A true multi machine run: the same harness over qtv-net sockets across hosts, which is
what finally measures inter node bandwidth and propagation latency and turns the in
process finality compute floor into a real network finality.

## Measured figures

The harness measures two numbers on each run over the stated committee and block
width, on the wall clock: the sustained finalised throughput and the finality latency
distribution with its tail. No committed results file backs a stated figure here, so
the current numbers come from running the harness with the command below, and they
carry the caveats above. The throughput is compute bound, network free, and serial
over the committee on one host, so it is not a multi machine network throughput. The
finality is the in process compute time per block, dominated by the committee re
verifying the block serially on one host, so it rises with both the block width and the
validator count; that is the serial single host artefact, not a property of the
consensus, and it excludes real network propagation. A real multi machine run verifies
the members in parallel and pays real network latency instead, which is the remaining
work above.

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
