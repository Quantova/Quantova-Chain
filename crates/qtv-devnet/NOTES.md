# qtv-devnet scope

This crate turns the single process node loop into several real nodes that talk
over the qtv-net post-quantum channel and reach finality over the wire. Each node
holds its own identity, its own state and store, and a bounded set of overlay
neighbors rather than a channel to every peer. A node discovers the network from a
small set of bootstrap peers, then gossips three things to its neighbors and
relays what it hears onward, the submitted transactions, the block proposals, and
the attestations. The committee is chosen by the sampler, the leader proposes over the
overlay, the members attest over the overlay, an entitled supermajority aggregates
into the certificate, and every node commits the same finalized block and persists
it through qtv-store before advancing.

Each node runs its own round on a logical clock rather than in lockstep. A slot
is 150 milliseconds of logical time. A node acts when a sealed message arrives or
a view timeout fires, driven by an event loop over the clock and the qtv-net
channels, not by a central driver stepping every node together. The determinism
the tests need comes from the logical clock and a fixed message order, not from
wall clock threads.

## What is in this crate

- Peer discovery. A node starts from a small set of bootstrap peers and exchanges
  its known peer set with them over a qtv-net channel, merging what it learns until
  every node on a connected bootstrap graph knows the whole network. A peer entry
  carries the network identity and the address. A discovered peer is trusted only
  once a channel to it completes the pinned handshake, so a peer that cannot prove
  the identity is refused rather than trusted from its discovery claim.
- A bounded gossip overlay. A node keeps a bounded neighbor set drawn as a ring
  lattice over the discovered peers ordered by identity fingerprint, not a link to
  every node. A message is relayed to a node's neighbors, and each node remembers
  the messages it has seen, keyed by content id, so it relays each one at most once
  and never loops. Every node links to its ring successor, so the overlay is
  connected and a proposal or attestation from any node reaches every node within a
  bounded number of hops.
- A secure channel per overlay link. Every link runs the qtv-net ML-KEM and ML-DSA
  handshake with identity pinning and then exchanges ChaCha20-Poly1305 sealed
  records. A gossip message travels the channel sealed, and a peer that cannot
  open a record tears the channel down.
- A wire message codec over the canonical qtv-codec: a submitted transaction, a
  block proposal carrying the real header and body, and a committee attestation
  carrying the sampler membership draw and the module lattice signature. A
  message that does not parse by the codec is dropped at the edge.
- A per node loop that reuses the chain crates without forking them. Execution,
  the mempool, committee selection, attestation, and certificate aggregation are
  the same qtv-node, qtv-sampler, and qtv-attest logic. Each node executes the
  proposed body against its own state, checks the resulting state root against the
  proposed header, attests with its own module lattice key, aggregates the
  entitled supermajority into a certificate, and persists the finalized block and
  the account state through qtv-store.
- Restart from disk. A node reopens its block store and state store, rebuilds its
  ledger from the committed leaves, reconstructs the beacon and the parent link
  from its last finalized block, and rejoins at the next height.
- Catch up sync over the qtv-net channels. A node behind the tip learns a peer is
  ahead from its finalized status, asks that peer for the finalized blocks from its
  own height forward, and receives each block carrying its finality certificate in
  the certificate slot. The syncing node trusts nothing about the serving peer. For
  every block it verifies the certificate the way a light client does, an entitled
  supermajority of module lattice attestations over that exact block under the
  committee commitment and the beacon it reconstructs as it advances, checks the
  block links to the one before by parent hash, and re executes the body against
  its own state to reproduce the state root. Only a block whose certificate, parent
  link, and re executed state root all check out is committed and persisted through
  qtv-store, so a forged or altered chain cannot be synced. Once caught up to the
  tip the node rejoins live consensus and finalizes new heights with the group. The
  finalized block now carries the whole certificate in its certificate slot rather
  than only its digest, so the block a peer serves is the block a light client
  verifies.
- Asynchronous per node rounds on a logical clock. A slot is 150 milliseconds of
  logical time. Each node acts when a sealed record arrives or a view timeout
  fires. The leader of a view proposes within its slot; a node that sees no valid
  proposal by its timeout advances the view, and the next leader in rotation
  proposes, reusing the view indexed leader rotation of the qtv-bft core. A silent
  or offline leader no longer stalls the chain: the timeout routes around it.
  Progress continues while an honest supermajority is online, and safety holds
  under reordering and view changes because a node stages at most one block per
  height and never attests a second, so no two nodes finalize different blocks at
  one height. A node finalizes only once every online committee member has
  attested its staged block, and an attestation arriving by several overlay paths
  is de duplicated by its content id and counted once, so the overlay never lets a
  node finalize without genuinely receiving a supermajority. The certificate and
  the finalized block are byte identical across nodes.

## Frozen decisions honored

- Attestations and the certificate are module lattice only, through qtv-attest.
- Offline nodes are skipped and never slashed. An offline node lowers the count
  without stalling a supermajority.
- Provers hold zero votes and are never entitled.
- Only native stake weights the committee.
- The transport is qtv-net. There is no X25519 and no classical cryptography
  anywhere, on this devnet or any other.

## Honest scope: what is deferred to later networking work

This is a small local devnet, a handful of nodes over loopback, driven in one
test process over real qtv-net channels or over localhost TCP. The event loop
turns a logical clock and moves each sealed record between the overlay channels;
it is the devnet harness, not a shortcut around the wire, since every record is
sealed and opened by qtv-net. Discovery and transaction gossip flood over the
overlay at once before a round, since a transaction only has to reach the leader
mempool before it proposes; the logical clock models the consensus round, where
the asynchrony, the timeouts, and the view changes live. The parts a production
network still needs are named here and are not built yet.

- NAT traversal and dynamic membership. The bootstrap graph and the overlay are
  fixed for a run over loopback; a node does not punch through a NAT, and the
  overlay is not repaired or rebalanced as peers join and leave mid run.
- The full QUIC datagram transport, multiplexed streams, congestion control, and
  session key rotation, all of which sit above the qtv-net channel and are named
  in the qtv-net notes.
- Continuous operation and its bounds. With catch up sync the nodes no longer have
  to enter every height together. A lagging node fetches and verifies the finalized
  heights it missed rather than stalling the group, and a fresh node joins from
  genesis and syncs the whole finalized chain before it takes part. The assumption
  relaxes to this. The nodes at a height still finalize it together, but a node
  behind that height catches up by verified sync and then rejoins the round rather
  than blocking it, so nodes may sit at different heights between rounds. What is
  not yet built is a node that syncs while it also proposes and attests at the same
  time. Catch up is a distinct phase a node runs to reach the tip before it rejoins
  live consensus, not a background stream folded into the round. Dynamic membership,
  where a peer joins or leaves mid run and the overlay is repaired around it, is
  still the fixed loopback overlay named above and below.
- Fork choice under deep reorgs. Each node follows the single finalized chain and
  does not resolve competing forks. The single stage per height keeps two blocks
  from finalizing at one height, so no fork forms; a full asynchronous view change
  that lets a node safely re-vote across a proposal split, rather than hold its
  first vote, is the harder case left to the consensus crate.
- Slashing distribution. Only equivocation is slashable and none occurs here, so
  no node is ever slashed and no penalty is distributed.
