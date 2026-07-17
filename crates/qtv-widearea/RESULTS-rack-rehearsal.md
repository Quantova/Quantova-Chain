Rehearsal on real servers, corrected

This records a rehearsal run of the wide area harness on two real servers, rack04 and
rack05, in one facility on their local network, run to prove the deploy and the transport
on real hardware before spending on geographically spread hosts.

A correction leads, because an earlier version of this file got the headline wrong and it
was committed and pushed before it was caught. That version claimed these servers were
roughly an order of magnitude slower per core than the Apple M4 that produced the loopback
figures. That was a contaminated measurement. When it was taken, a cargo build was still
consuming the twenty four cores, so the validators were starved of CPU and the run was
slow for that reason, not because of the hardware. It was reported as a hardware finding.
It is not one.

The clean measurement, both servers idle at a load average of about 0.02 with nothing else
on the cores. At block width two hundred and fifty on a committee of two, the plain build
finalises at about 674 milliseconds a block and the optimised build at about 595
milliseconds a block. The M4 loopback figure at the same width was about 686 milliseconds
a block on a committee of four. So the servers are broadly comparable to the M4, within a
small factor, not an order of magnitude apart. The comparison is not exact, because the
servers ran a committee of two and the M4 figure was a committee of four, so a same
committee comparison would move it somewhat, but the order of magnitude claim is refuted
outright. The loopback figures are roughly representative of real server hardware, not
wildly optimistic, and that is the corrected reading.

What still holds. The plumbing works end to end on real hardware, which was the rehearsal's
purpose. The mesh forms over the real local network on the real qtv-net post quantum
channel, both nodes finalise a byte identical chain, committee two, no rotations, no stall,
and the deploy path is proven, the native vendored build with no key on the server, the
binary placed on each host, the one transport port opened between the two internal
addresses only. The same deploy path points at the matched hosts unchanged.

Build flags. Turning on link time optimisation, a single codegen unit, and the AVX2
instruction set gave about ten percent, 674 to 595 milliseconds a block at width two
hundred and fifty, and about nine percent at width fifty, with the chain byte identical
either way. A real but modest win. It is not where the large gains are.

Where the numbers actually stand against the old chain. The gap to the previous classical
chain that ran on these servers is not the hardware, which is fine, it is the cost of real
module lattice signatures against classical ones, which is the whole point of the design
and is not a thing to optimise away. The honest lever that remains, with the crypto
guarantee fully intact, is that signature verification is serial today, one core of twenty
four, so parallelising it across the cores is the real opportunity and it verifies every
signature exactly as now. That is scoped as a change to the pinned consensus and node
path, with a conformance pass, not done in this rehearsal.

The lesson, recorded so it is not repeated. A single anomalous slow measurement was taken
without controlling the machine, committed as a finding, and pushed. It was caught only
when a clean re run for a different purpose contradicted it. Control the measurement
environment before measuring, be suspicious of one slow number, and do not commit a
headline from an uncontrolled run.

Reference hosts and build. rack04 and rack05, each Ubuntu 26.04 on x86 64 with twenty four
cores, in one facility on the internal network a sub millisecond apart. Release profile,
consensus pinned at tag v0.5.0, compiled on the server from the exact commits the lockfile
pins, vendored so no key was copied to the server. The M4 comparison figures are the
committed loopback and live results beside this file, an Apple M4 with ten cores.

What this run is not. The block width figures above are a committee of two, which is a two
of two unanimity with zero fault tolerance, not a Byzantine committee, and the two servers
sit on one sub millisecond local network, so there is no propagation in any of it. None of
these are network numbers or consensus numbers. They settle one thing only, the hardware
is comparable to the M4, and they correct the record that said otherwise.

Method and reproduce. The harness is qtv-validator-wide, one process per host, handed the
ordered peer address list on the fixed transport port and the block parameters. The ingress
at index zero signs the workload outside the timed region and drives the round, and only
transactions in a genuinely finalised block are counted. The clean comparison was committee
two, block width two hundred and fifty, ten measured heights, one warmup height, on idle
cores.
