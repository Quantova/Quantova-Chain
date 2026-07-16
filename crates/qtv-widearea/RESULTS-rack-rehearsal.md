Rehearsal on real servers, and what it says about our benchmark machine

This records a rehearsal run of the wide area harness on two real servers, rack04 and
rack05, in one facility on their local network. It was run to prove the deploy and the
transport on real hardware before spending on geographically spread hosts. It earned a
record for one reason above the plumbing, and that reason leads.

The headline. The two servers are roughly an order of magnitude slower per core than
the Apple M4 that produced the loopback and live figures, on the same real module
lattice workload. The M4 finalised sixty heights at block width two hundred and fifty
in about forty one seconds. These servers could not finalise thirty heights at the same
width in one hundred and forty seconds, and the run was still going when it was stopped.
Per block that is a lower bound of about seven times slower on the servers, and the true
per core gap is wider than that, because the servers ran a committee of two while the M4
figure was a committee of four, a lighter consensus that should have run faster, not
slower. The exact factor is not pinned, because the server run did not complete and the
committee sizes differ, so this is a lower bound and a direction, not a measured
multiple. The direction is unambiguous and the scale is roughly an order of magnitude.

The implication, stated plainly. The loopback median finality of about six hundred and
eighty six milliseconds and the loopback sustained throughput of three hundred and
sixty three transactions a second were measured on the M4, a laptop chip with an
unrepresentatively fast core. A real validator is a server, not a laptop. On at least
one real server, measured here, the same work is roughly an order of magnitude slower
per core. So both figures are optimistic. If a real validator is server class our
finality rises and our throughput falls, by a factor we do not yet know because we have
not measured it on representative hardware. The M4 numbers are a floor on what is
possible on fast silicon, not an estimate of what a validator set will see. These two
servers are one server data point, not the representative validator either, so the
answer is not their number in place of the M4 number, the answer is that the
representative figure is unmeasured and both existing numbers flatter the design. This
is the first hard evidence of that, and it is the finding of this run.

What this run is not. It is a plumbing rehearsal, not a measurement of anything
comparable. The block width was fifty, not the two hundred and fifty the design targets,
because the width two hundred and fifty control was abandoned when the hardware could
not carry it, so the width fifty run compares to nothing, not to the loopback figure and
not to any other. The committee was two, which is a two of two unanimity with zero fault
tolerance, not a Byzantine committee, so its per block time is not a consensus number.
The two servers sit on one sub millisecond local network, so there is no propagation in
it and it is not a network number. The ingress measured about seventy one milliseconds a
block, and that figure carries every one of those caveats and travels as none of them.

Reference hosts and build. rack04 and rack05, each Ubuntu 26.04 on x86 64 with twenty
four cores, in one facility on the internal network a sub millisecond apart. The build
is the release profile at optimisation level three, the consensus pinned at tag v0.5.0,
compiled on the server from the exact commits the lockfile pins, vendored so no key was
copied to the server. The M4 comparison figures are the committed loopback and live
results beside this file, an Apple M4 with ten cores.

The plumbing, which is the footnote. The mesh forms over the real local network on the
real qtv-net post quantum channel, the module lattice handshake and the symmetric record
layer over real TCP sockets. Both nodes finalise a byte identical chain, committee two,
no rotations, no stall. The deploy path is proven end to end, the native vendored build
with no key on the server, the binary placed on each host, the one transport port opened
between the two internal addresses only, the mesh, and the byte identical finalisation.
That is what the rehearsal set out to prove and it holds, which is why the same deploy
path points at the matched hosts unchanged.

The third node, closed. A laptop on a consumer link at real distance was to add a first
taste of propagation. It cannot join, and the block is structural rather than a setup
gap. The mesh holds two connections per pair, one sealed stream per direction, so every
node must accept an inbound dial from every peer, and a node behind NAT cannot. The only
workaround routes the laptop's traffic through a server over a tunnel, which measures the
tunnel and an extra hop rather than the real distance. So the laptop is left out and real
propagation waits for matched publicly reachable hosts.

Method and reproduce. The harness is qtv-validator-wide, one process per host, handed
the ordered peer address list on the fixed transport port and the block parameters. The
ingress at index zero signs the workload outside the timed region and drives the round,
and only transactions in a genuinely finalised block are counted. This run was committee
two, block width fifty, twenty measured heights, two warmup heights, a four second view
timeout well above the sub millisecond local round trip. Each validator is started with
QTV_WA_INDEX set to its position, QTV_WA_ADDRS set to the ordered host:40404 list,
QTV_WA_ACCOUNTS the width, QTV_WA_HEIGHTS the count, and the binary given its index.
