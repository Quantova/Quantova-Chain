# qtv-node slice

This is the first vertical slice of the Quantova node. It exists to prove the
whole stack composes. It runs a state transition and finalization loop in one
process over direct calls, holding chain state in qtv-state, executing each
transaction through the virtual machine, and driving a sampler selected committee
through attestation and aggregation into a finality certificate.

## What is in this slice

- Chain state held in the qtv-state sparse Merkle trie, keyed by address, with a
  real post execution state root committed in every finalized header.
- A mempool that admits a signed transaction only when its signature verifies,
  its nonce matches the sender, and the sender can pay the transfer amount, the
  protocol fee, and the gas.
- Execution of each transaction through the qtv-vm interpreter. The virtual
  machine debits the sender by the amount and the protocol fee and credits the
  recipient, and the node writes the post execution balances back into the trie.
- A protocol fee taken from the fee parameters, in dollar micro units converted
  to the native asset, never a hardcoded raw amount.
- Committee selection by the qtv-sampler verifiable random sortition, proposer
  election by the same sortition, attestation and aggregation of an entitled
  supermajority into a qtv-attest finality certificate, and beacon advance from
  the certificate digest.
- Reconciliation of the abstract consensus block with the real chain block by
  folding the real header hash into the consensus block value, so the committee
  attests over the real header without forking the block type.

## Frozen decisions honored

- Consensus attestations are module lattice only.
- Offline validators are skipped and never slashed. Nothing in this slice slashes.
- Provers hold zero votes and are never entitled.
- Only native stake weights the committee.
- The fee follows the protocol fee parameters.

## What is deferred to later node work

- Real networking. There is no QUIC transport, no ML-KEM and ML-DSA handshake,
  no peer discovery, and no gossip. The committee runs in one process over direct
  calls, not over a wire.
- Disk persistence. State, the mempool, and the finalized chain live in memory.
  There is no database and no crash recovery.
- A data availability store. Transaction bodies and proofs are held inline, not
  in a separate store committed by root.
- Full finality certificate serialization for the wire and for storage. The
  finalized header carries the certificate digest, and the node keeps the full
  certificate in memory.
- The fee burn and split, the congestion component, and the validator reward and
  prover auction flows. The fee is charged and removed from the sender only.
- On chain public key registration. A sender public key is provisioned at genesis
  so a signature can be verified from state.
- View changes and timeouts. The in process committee decides one block per
  height with no partial synchrony to tolerate.
