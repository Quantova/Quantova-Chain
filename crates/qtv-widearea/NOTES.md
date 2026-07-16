# qtv-widearea scope

This crate is the wide area run. It is the loopback multi process harness with one
change. Where the loopback validator hardcodes localhost, the wide area validator reads
its own listen address and its peers' real addresses from configuration, so the same
binary runs on a remote host and connects to the other hosts over the internet on the
real qtv-net post quantum channel. Run across regions it measures real propagation on
top of the parallelism the loopback run already measured, and the finding is the delta
from the loopback finality, which is the propagation cost. Run on one host over
localhost sockets, as it is validated here, it produces no network number.

## What is reused unchanged

The workload, the funded accounts, the devnet configuration, the committee sortition,
the module lattice attestations, the aggregated finality certificate, and the erasure
coded proposal dissemination are reused byte for byte from the loopback lib. A wide area
run and a loopback run drive the identical deterministic workload over the identical
committee and differ only in the peer addresses and in the honest degradation path this
crate adds. The consensus is the pinned QRC-CONSENSUS v0.5.0 one time key sortition with
the stake floor on, sized to the harness slot count through the with_slots path exactly
as the loopback run sizes it.

## The one thing that is not identical, stated plainly

The loopback run only ever runs the happy path with every host up, so it finalises once
every online member has attested and never rotates a leader. A wide area run meets slow
and dropped hosts, so this validator adds the real consensus supermajority and the real
view change. A node finalises once every online committee member has attested its staged
block, where the online set is the members whose host is up this run, so the aggregated
certificate is byte identical across the up hosts and the beacon advances alike between
them. A node never advances its own view on a local timer alone. It signs a view change
record for the next view when its timer fires and advances only once a blocking set of
such records shows the network genuinely moved on, the standard Byzantine view
synchronisation, so a stray timer on a healthy height emits one harmless record and the
node still stages and attests the block when it arrives, while a genuinely dropped leader
draws a record from every up member and the whole committee jumps together. This is the
only departure from the loopback substrate, and it is what lets the run degrade honestly
rather than hang.

Where this view change lives, precisely, because the layer matters. The abstract
rotation is in the pinned consensus. qtv-bft at v0.5.0 advances the view of an undecided
height and rotates its leader on a timeout, and its own test rotates past an offline or
byzantine leader, so the consensus holds the rotation logic and proves it. The concrete
distributed realisation this harness drives, the signed view change record, its
collection, and the blocking set of the committee size minus the supermajority plus one
that a node advances on, lives in the qtv-devnet node and uses the pinned consensus
quorum and leader schedule as its primitives. So the honest degradation runs real code
over the real quorum, but the concrete view synchronisation is a devnet layer realisation
of the consensus rotation rather than a frozen consensus wire protocol, and its record is
the same view change record still on the open list, uncoded and not yet specified as a
wire record. When that record is specified and coded, this path is reconciled against it
rather than assumed to match, the same formal to concrete seam the consensus spec already
names for the committee fairness.

## The single transport port

The wide area run fixes one transport TCP port for the whole run, port 40404, the
TRANSPORT_PORT constant in the crate. A real deployment opens exactly this one port
inbound on every validator host and each validator binds it, so every host reaches every
other host on one known port and the firewall rule is a single line. The port is a
deploy convention rather than a hardcoded bind, so the validator binds whatever listen
address its configuration gives it. A real host binds 40404. The local validation binds
a distinct localhost port per process, since several processes cannot share one port on
one host.

## The host spec the run needs

Each validator host runs one validator process and holds one validator's key, state, and
store. The founder provisions server class hosts to match the validator budget and the
one gigabit floor, on the order of four to eight cores, sixteen gigabytes of memory, and
a one gigabit link, one host per validator, at least the committee size of four to match
the loopback comparison. The hosts are spread across three to five regions so the inter
host round trips are on the order of a hundred to three hundred milliseconds, the real
intercontinental range the finality must include. One further host is the coordinator
that starts the validators and gathers the results, and it only needs to reach the
validator hosts over SSH. Cloud virtual machines are the practical form, and the count,
the regions, and the spend are the founder's to authorise.

## The deploy flow

The deploy script `deploy/run-widearea.sh` is the coordinator. Given the host addresses
it starts one validator on each host over SSH, lets them rendezvous over the real qtv-net
mesh, drives the sustained signed workload from the ingress host, collects each host's
measurement into a per host result file, and gathers the finality distribution with the
coordinator binary in collect mode. The rendezvous needs no extra service, because the
transport port is fixed and every host holds the full ordered address list, so each
validator dials every peer at its known address with a short retry and the mesh handshake
barrier holds each host until every up peer is connected before the round starts.

The script assumes three things and states them at the top of its source. Every address
is reachable from the coordinator over SSH and every host reaches every other host on the
transport port. Exactly one port, 40404, is open inbound on every validator host, and
nothing else needs to be open inbound. The qtv-validator-wide binary is already present
on each host at a known path with a writable store directory, since building and copying
the binary and opening the port is ordinary deployment setup rather than part of the run.

```
HOSTS="ip0 ip1 ip2 ip3" SSH_USER=ubuntu \
  REMOTE_BIN=/opt/quantova/qtv-validator-wide REMOTE_BASE=/var/lib/quantova/wa \
  ACCOUNTS=250 HEIGHTS=60 WARMUP=2 VIEWMS=4000 STALLSECS=60 \
  QTV_WA_COORDINATOR=/opt/quantova/qtv-widearea \
  ./deploy/run-widearea.sh
```

The run length is a fixed number of measured heights rather than a per host wall clock,
so every up host stops on the same height in lockstep and no host is stranded mid height
when a host that reached its own budget first closes its sockets. The founder sizes
HEIGHTS to the wall clock the run wants at the finality the hosts see, bounded by the one
time sortition tree, which the plan for the distributed run records.

## What runs on the wire, and what is deferred

The channel is the real qtv-net post quantum secure channel over a reliable byte stream.
It is not the full QUIC transport, and the qtv-net notes name the UDP datagram layer, the
multiplexed streams, the congestion control, and the loss recovery as not yet built, so a
wide area run measures the transport that exists. The block width stays below the record
so catch up sync and view change records, which still serve a whole block per record, are
unaffected, exactly as the plan for the distributed run requires. A wider width waits on
those two records being coded first.
