Parallel verification on the racks, what it bought and what it did not

This records what parallelising signature verification bought on rack04 and rack05, and
it leads with the honest limit so the change is not misread. Every figure is committee of
two on one office LAN with no propagation, so it is a figure for a node using its cores
and it is not the chain's throughput.

The finding. A profile showed about ninety four percent of the node's single threaded work
was one operation, module lattice signature verification, in two homes: the block verify on
the consensus path, and the transaction admission. Both are now parallel across the cores,
byte identical (the finalised chain hash is unchanged) and deterministic (identical across
one to twenty four cores by test). There is no third heavy compute term, the state root and
the execution are each under one percent, so the node's compute is done rather than a long
tail.

What each change bought, measured alone.
- The block verify parallelisation cut the timed consensus from 12143 to 8580 milliseconds
  over sixty heights, verify down 41 percent and build down 36. It moved because verify and
  build are on the wall clock critical path and the box had idle cores.
- The admission parallelisation is correct and byte identical, and it moved the box average
  from 1.03 to 1.17 cores. Its consensus gain, 8580 to 6623 milliseconds, was mostly the
  wait shrinking, the follower becoming ready sooner, not the node using more cores. It is
  not the change that made the node use its cores, and it is written that way here so nobody
  later reads it as one.

What still holds the wall, and why it is not a node defect. The box still averages about one
core, because the fill, the untimed admission where the leader floods the whole block's
transactions and the nodes admit them, is about eighty percent of the wall clock, and in
this single threaded harness it runs in series with consensus rather than concurrently. A
real validator fills its mempool on a background thread while consensus runs, and a real
network delivers transactions gossiped over time rather than flooded at once, so the fill
overlaps and shrinks. That serial fill is a harness and measurement property, not the node
ignoring its cores.

The two rates, and neither is clean here. The consensus limited rate, the rate if the
mempool stays full and admission overlaps, rose from 1236 to 2265 transactions a second
across the parallel work, and that is the number the parallelism actually improved. The end
to end serial rate, admission and consensus one after the other on these two boxes, rose
from 371 to 459. The truth sits between them and is decided by the node's threading and by
the committee size, neither of which these two boxes settle.

What it means for the next run. The compute converged, so a larger box average from here
needs either the node to overlap admission with consensus, which is a threading change, or a
real committee where the wait is a supermajority and not a two node lockstep. The committee
of four run reads the consensus limited rate with the lockstep gone, and reads whether the
box average lifts once the harness's serial fill is a smaller share.

Reference. rack04 and rack05, Ubuntu 26.04, twenty four cores each, one office LAN, sub
millisecond apart, no propagation. Release profile, the consensus pinned at v0.5.0. The
chainhash is 4bdcda0a byte identical across the serial and the two parallel binaries on the
identical width 250 workload, which is the proof the parallelism changed only how the work
is spread and not what the chain does.
