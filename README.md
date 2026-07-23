# Quantova-Chain

Quantova is a sovereign post quantum Layer 1, built from scratch, sharing no code, no wire format, and no trust assumption with any other chain. It is post quantum end to end, not a classical chain with a post quantum signature bolted on. Every layer is its own, and every layer stands on NIST standardized schemes with no classical escape hatch anywhere.

Quantova-Chain is the node and the ledger. It is the integration repository where the cryptography, the virtual machine, and the consensus come together into a running chain. It carries the identifier format, the canonical codec, the account model, the transaction and block and state formats, the post quantum network layer, the mempool, execution, the fee and staking and governance logic, persistence, the RPC gateway, and the `quantovad` daemon.

## What it is

A Cargo workspace of seventeen crates that compose into a state transition and finalization loop. The in repository crates hold the ledger and the formats, and the node crate wires in the three upstream repositories, the Q-Crypto primitives, the QVM execution engine, and the QORUS consensus core, each pinned by an exact git tag. Almost every crate carries `#![forbid(unsafe_code)]`, and a `cargo deny` policy bans classical cryptography from the entire dependency tree.

Nothing here is borrowed. The addresses are Q1 Bech32m, never a twenty byte hex string and never SS58. The unit is Quon. The signatures are ML-DSA. The codec, the state trie, the transaction format, and the RPC surface are all Quantova's own.

## The ledger and the formats

- **qtv-idfmt** is the single formatting path for every identifier. Raw bytes become a Bech32m string under a role prefix, an account address under `q`, so an address reads as `Q1`, and separate prefixes for secrets, transactions, blocks, state roots, contract interfaces, and proofs. Nothing here emits Ethereum style hex.
- **qtv-codec** is the canonical codec. Every value has exactly one valid encoding, deterministic and length delimited, and the decoder refuses any input that is not the canonical form, no trailing bytes, no overlong length, no unknown tag.
- **qtv-account** is the account model and key derivation. Keys are scheme tagged, ML-DSA by default with SLH-DSA and a gated Falcon slot, derived through a SHAKE256 pipeline. An address is the 256 bit SHA3-256 commitment over the scheme tag and the full post quantum public key, so the address binds a real key at full width rather than a truncated hash.
- **qtv-tx** is the transaction body, wrapper, signing, and verification, with domain tagged digests and deterministic signing.
- **qtv-block** is the header, the body, the SHA3-256 Merkle transaction root, and the block event root.
- **qtv-state** is the 256 level SHA3-256 sparse Merkle state trie, with proofs of presence and absence in one shape.
- **qtv-staking** is stake accounting, bonds, reward sessions and vesting, and slashing.
- **qtv-governance** is referenda over conviction voting, seven tracks each with its own thresholds, and a constitutional gate that checks an action before it can enact.
- **qtv-store** is file backed block and state persistence, an append log with in memory indexes rebuilt on open and a torn tail truncated on recovery.

## The node

**qtv-node** composes the chain crates, the virtual machine, and the consensus core into one loop.

- `consensus` wires QORUS over qtv-sampler, qtv-bft, and qtv-attest. It draws the committee by one time sortition, elects a leader, and aggregates online attestations into a finality certificate over the raw block header, so forging a finalized header would require a SHA3-256 collision.
- `execution` runs every state change through the QVM. A native transfer is a fixed assembly program metered on the interpreter, and a contract call runs a real deployed QVM container.
- `ledger` holds all chain state in the sparse Merkle trie, accounts keyed by their address hash, with staking, governance, supply, and the fee split held under domain tagged keys.
- `parallel` executes an ordered block deterministically across threads. It layers transactions by their declared sender and recipient conflict sets and proves bit identical results against serial execution.
- `mempool` admits a transaction only on a verified signature, a strict nonce, the fee and meter floors, and sufficient funds, with a closed set of rejection reasons.

The dependency wiring is explicit. The in repository crates are path dependencies, and qtv-crypto, qtv-vm, and the qtv-bft, qtv-sampler, and qtv-attest crates come from Q-Crypto, QVM, and QRC-CONSENSUS by git tag.

## Fees, burn, and split

A transaction pays a floating fee in the native asset, a band from five hundredths of a cent to one tenth of a cent that floats in QTOV through the governance rate and is paid at what the sender bids. The band is unchanged, and only the split of the collected fee is set here. Every fee divides three ways. Seventy percent is burned, ten percent goes to the validators of the round which is the block proposer, and twenty percent goes to the grants account. The burn is an Ethereum base fee style destruction, so the seventy percent is removed from the total supply and the supply falls with every fee and tracks the activity on the chain rather than a fixed schedule. The sender pays the whole fee, only the proposer and grants shares are credited, and the burned share is destroyed, so the sum of balances and the total supply both fall by the burn and stay equal. Rounding dust falls into the grants share. The grants account is the keyless governance account, spendable only through a vote. Marketing and the market maker are funded from the genesis reserves and take no cut of any fee. There is no yearly supply burn, the per fee burn is the only one.

## The network and the gateway

- **qtv-net** is the post quantum authenticated channel. The handshake exchanges ML-DSA identities, encapsulates an ephemeral ML-KEM key, and signs the transcript with ML-DSA, then a SHAKE256 key schedule derives the directional ChaCha20-Poly1305 record keys. There is no classical cryptography and no X25519. It also carries a systematic Reed-Solomon erasure layer over GF(256) with a SHA3 Merkle commitment, so any k of n shards reconstruct a block proposal.
- **qtv-gateway** is the RPC gateway, plain HTTP and a custom JSON codec written on the standard library. The node stays the single owner of state and the gateway forwards typed requests to it. Every method is Q-native, `node_info`, `head`, `validators`, `chain_params`, `get_account`, `get_transaction`, `submit_transaction`, `get_block`, `pending`, `supply`, `get_container`, `get_storage`, and `get_events`, with no `eth_` method anywhere.

## The daemon and the harnesses

**qtv-daemon** produces the **`quantovad`** binary. It reads a node config and a shared `genesis.q`, opens a node against on disk stores, stands up the qtv-net mesh, and runs a continuous round that finalizes and persists each block and resumes from disk on restart. A committee of one is its own supermajority, so a single `quantovad` is a live chain on its own. The node holds only its own secret in its keystore and reads every peer's public registration from the genesis. `quantovad register` prints the registration line an operator contributes to the genesis.

Alongside the daemon, **qtv-devnet** is the multi node core the daemon and gateway drive, and **qtv-live**, **qtv-loopback**, and **qtv-widearea** are in process, multi process, and cross host measurement harnesses that finalize real blocks and record sustained throughput and finality distribution.

## Build and test

```
cargo build --release --bin quantovad
cargo test
cargo deny check
```

Testing spans 43 integration test files under `crates/*/tests/` alongside extensive inline unit tests. The devnet suite proves safety, convergence, determinism, catch up and fresh sync, rejection of a forged sync, tolerance up to the fault bound, split and heal, and a silent leader, and a `no_classical` test asserts the ban holds on the wire. Performance material lives in committed examples and the harness result files rather than in prose. CI runs the shared Quantova rust workflow.

## Where it sits in the stack

This is the repository that turns the components into a chain. It depends on Q-Crypto for every primitive, on QVM for execution, and on QRC-CONSENSUS for finality, and it contributes the ledger, the formats, the network, the RPC, and the daemon that runs the whole thing.

## Status

At testnet. The `quantovad` daemon is complete and runs the chain, testnet bring up is scripted under `testnet/` with the chain id `Q-test-net-1` and a faucet that dispenses TQTOV. Native transfers and governance are live, staking bonds and slashing operate while reward accrual stays inert until governance sets a mainnet start day so no staking rewards pay on the testnet, and contract execution is metered under a per block compute budget and an admission ceiling. Multi operator key rotation past the one time sortition horizon is a known open item, so a run either sets a height horizon it will reach and resets, or waits for key rotation.

## License

Dual licensed under Apache 2.0 and MIT. See `LICENSE-APACHE` and `LICENSE-MIT`.
