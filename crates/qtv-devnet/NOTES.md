# qtv-devnet scope

This crate turns the single process node loop into several real nodes that talk
over the qtv-net post-quantum channel and reach finality over the wire. Each node
holds its own identity, its own state and store, and a secure channel to every
peer. The nodes gossip three things over the channels: submitted transactions,
block proposals, and attestations. The committee is chosen by the sampler, the
leader proposes over the wire, the members attest over the wire, an entitled
supermajority aggregates into the certificate, and every node commits the same
finalized block and persists it through qtv-store before advancing.

Each node runs its own round on a logical clock rather than in lockstep. A slot
is 150 milliseconds of logical time. A node acts when a sealed message arrives or
a view timeout fires, driven by an event loop over the clock and the qtv-net
channels, not by a central driver stepping every node together. The determinism
the tests need comes from the logical clock and a fixed message order, not from
wall clock threads.

## What is in this crate

- A secure channel mesh. Every pair of nodes runs the qtv-net ML-KEM and ML-DSA
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
  attested its staged block, so the certificate and the finalized block are byte
  identical across nodes.

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
turns a logical clock and moves each sealed record between the channels; it is the
devnet harness, not a shortcut around the wire, since every record is sealed and
opened by qtv-net. Transaction gossip is delivered at once before a round, since
the bounded gossip overlay is deferred; the logical clock models the consensus
round, where the asynchrony, the timeouts, and the view changes live. The parts a
production network still needs are named here and are not built yet.

- The bounded gossip overlay, peer discovery, and NAT traversal. The mesh is a
  fixed full mesh over loopback, a record is delivered to every peer rather than
  forwarded to a bounded neighbor set, and transactions spread at once rather than
  over the logical clock.
- The full QUIC datagram transport, multiplexed streams, congestion control, and
  session key rotation, all of which sit above the qtv-net channel and are named
  in the qtv-net notes.
- Catch up sync for a node that missed heights. A restarted node reloads the chain
  it persisted, and a node that was offline for a stall rejoins at the height the
  others held; but a node that fell behind on already finalized heights does not
  fetch and verify them from a peer over the wire.
- Fork choice under deep reorgs. Each node follows the single finalized chain and
  does not resolve competing forks. The single stage per height keeps two blocks
  from finalizing at one height, so no fork forms; a full asynchronous view change
  that lets a node safely re-vote across a proposal split, rather than hold its
  first vote, is the harder case left to the consensus crate.
- Slashing distribution. Only equivocation is slashable and none occurs here, so
  no node is ever slashed and no penalty is distributed.
