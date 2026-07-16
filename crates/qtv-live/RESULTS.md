Sustained finality past the one time slot ceiling

These numbers come from the live in process harness in this crate. Run it with the
command at the end and the figures move a little between runs. Every figure here is a
live in process figure measured on one host, so inter node bandwidth and propagation
latency are not present and not measured. It is the compute of the real consensus
software with the committee run serially on one host over an in memory transport.

The question this settles. The one time key sortition serves one slot per finalised
height from a tree each validator commits at registration. The consensus default sizes
that tree to sixty four slots, so a run cannot finalise more than sixty four heights
before the sortition refuses a slot past the commitment. The founder authorised a
larger slot count for the harness alone. This run confirms that with the harness
sizing each validator tree to four thousand and ninety six slots through the attester
slot count constructor, a single sustained run finalises far more than sixty four
heights and the tree no longer bounds it.

Host and build. The host is an Apple M4 with ten cores and seventeen gigabytes of
memory. The profile is the release build at optimisation level three. The source is
the Quantova chain at commit 6ea0182, which drives the devnet nodes over path
dependencies, with the consensus crates pinned at tag v0.5.0.

Configuration. The node count is four real validator instances, so the committee read
from a real finalised block is four and the supermajority to finalise is three. The
width is eight distinct signing accounts, each sending one transfer to the next
account every height, so a block carries eight real transactions and each transaction
carries a real module lattice signature over a distinct key on a distinct state leaf
and is verified on the ingress path. The mix is a uniform transfer workload, one
transfer per account per height, and none is a no op. The committee is drawn by the
real one time key sortition of consensus v0.5.0 with the minimum self stake floor on,
and each validator commits a one time preimage tree of four thousand and ninety six
slots bonded to its stake. The proposal is disseminated as its real erasure coded
shards under a hash commitment and rebuilt from any k.

Duration. The run drives heights until the consensus wall clock reaches the target of
twenty five seconds, which took twenty eight point nine seconds of total wall clock.

Method. The harness drives back to back heights of the same signed transfer workload
and times the consensus work per height on the wall clock. The client side signing
runs outside the timed region and is reported apart from it. The timed region covers
the admission, the gossip, the build, the attestation, the aggregation, and the
finalisation. Only transactions in a genuinely finalised block are counted, and only
the transactions the block actually carried. Two warmup heights advance the chain
before the measured window and are not counted.

The measured figures. The run finalised 879 heights and 7032 transactions over the
twenty five second consensus wall clock. The sustained finalised throughput was 281
transactions a second measured over the consensus wall clock, and 243 transactions a
second end to end including the client side signing. The per block finality across the
committee had a median of 28.3 milliseconds, a ninetieth percentile of 29.4
milliseconds, a ninety ninth percentile of 32.0 milliseconds, and a maximum of 52.4
milliseconds, with a minimum of 24.2 milliseconds and a mean of 28.5 milliseconds over
the 879 finalised blocks.

What this proves. The 879 finalised heights in one sustained run are more than
thirteen times the sixty four height ceiling the default slot count imposes, and every
height finalised without the sortition refusing a slot, so the one time key tree at
four thousand and ninety six slots no longer bounds the sustained window. The slot
count is a harness parameter only. The consensus default stays sixty four, and only
the harness opts into the larger count through the attester slot count constructor,
which sizes the committee sampler tree and the attester tree together so the whole draw
and verify path serves the larger count.

Reproduce. Build and run in release from the Quantova chain workspace with four
validators, eight signing accounts, and a twenty five second target.

```
QTV_LIVE_VALIDATORS=4 QTV_LIVE_ACCOUNTS=8 QTV_LIVE_SECS=25 cargo run --release -p qtv-live
```
