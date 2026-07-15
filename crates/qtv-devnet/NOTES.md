# qtv-devnet scope

This crate turns the single process node loop into several real nodes that talk
over the qtv-net post-quantum channel and reach finality over the wire. Each node
holds its own identity, its own state and store, and a secure channel to every
peer. The nodes gossip three things over the channels: submitted transactions,
block proposals, and attestations. The committee is chosen by the sampler, the
leader proposes over the wire, the members attest over the wire, an entitled
supermajority aggregates into the certificate, and every node commits the same
finalized block and persists it through qtv-store before advancing.

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
test process over real qtv-net channels or over localhost TCP. The driver moves
each sealed message between the channels in lockstep rounds; it is the devnet
harness, not a shortcut around the wire, since every message is sealed and opened
by qtv-net. The parts a production network still needs are named here and are not
built yet.

- Peer discovery, NAT traversal, and a bounded gossip overlay. The mesh is a
  fixed full mesh over loopback, and a message is delivered to every peer rather
  than forwarded to a bounded neighbor set.
- The full QUIC datagram transport, multiplexed streams, congestion control, and
  session key rotation, all of which sit above the qtv-net channel and are named
  in the qtv-net notes.
- Asynchronous rounds. The driver runs the propose, attest, and finalize phases
  in lockstep; partial synchrony, timeouts, and view changes are not modeled, so
  the elected leader is assumed online for the slot it leads.
- Fork choice under deep reorgs. Each node follows the single finalized chain and
  does not resolve competing forks.
- Chain sync for a node that missed heights. A restarted node reloads the chain it
  persisted; a node that was fully offline for a stretch does not catch up on the
  heights it missed over the wire.
- Slashing distribution. Only equivocation is slashable and none occurs here, so
  no node is ever slashed and no penalty is distributed.
