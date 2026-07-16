//! Shared pieces for the loopback multi process run.
//!
//! The loopback run answers exactly one question and nothing else: it isolates the
//! single variable of parallelism against the in process serial baseline. The in
//! process harness (qtv-live) runs every committee member's compute serially on one
//! host over an in memory duplex. This run instead gives each validator its own
//! operating system process and lets them talk over real localhost TCP sockets
//! through the real qtv-net post quantum channel, so the committee computes in
//! parallel across processes with near zero propagation. Serial becomes parallel.
//! Nothing else changes: the same consensus (v0.4.0 one time key sortition with the
//! stake floor on), the same real module lattice attestations, the same real
//! aggregated finality certificate, the same real 3309 byte module lattice signed
//! transactions, and the same erasure coded proposal dissemination.
//!
//! WHAT THIS MEASURES, AND WHAT IT DOES NOT. Every number this produces is a
//! LOOPBACK MULTI PROCESS number over REAL SOCKETS with NEAR ZERO PROPAGATION. It is
//! parallel per process compute plus the loopback socket cost of moving the sealed
//! records between processes on one host. It is NOT a geographic or global network
//! throughput and NOT a real global finality: the sockets are localhost, so inter
//! host bandwidth and propagation latency are not present and not measured. A
//! geographically distributed run would bundle parallelism and propagation together
//! and could not separate them; this run isolates parallelism alone, which is its
//! whole point.
//!
//! To keep the crypto law, the constants and the devnet configuration here are byte
//! for byte the ones the in process baseline uses, so the two runs drive an
//! identical deterministic workload over an identical committee and differ in
//! exactly one thing, the process and socket substrate, and the finalized chains are
//! byte identical between the two. That byte identity is the correctness oracle the
//! driver checks before it reports a single number.

use qtv_account::{derive, Account};
use qtv_devnet::config::{DevnetConfig, NodeConfig, FULL_FANOUT};
use qtv_devnet::wire::{gossip_id, Message};
use qtv_node::execution::{transfer_call, TRANSFER_GAS};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::{sign, Body, Wrapper};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The genesis time the run starts from. The same value the in process baseline
/// uses, so both runs derive the identical genesis and the identical committee.
pub const GENESIS_TIME: u64 = 1_700_000_000_000;
/// The seed the funded sender accounts derive from. Identical to the baseline.
pub const ACCOUNT_SEED: [u8; 32] = [37u8; 32];
/// The native balance each sender account is funded with at genesis, ample for a
/// long run at the protocol fee so no transaction ever fails on funds. Identical to
/// the baseline.
pub const FUND: u64 = 1_000_000_000_000;
/// The value each transfer moves. Nonzero so no transaction is a no op. Identical to
/// the baseline.
pub const TRANSFER_AMOUNT: u64 = 1;

/// A distinct funded sender account, one per block slot. Each sends one transfer per
/// height, so the block width is the account count and every signature is over a
/// distinct key on a distinct state leaf. Identical to the baseline.
pub fn accounts(count: usize) -> Vec<Account> {
    (0..count as u64).map(|i| derive(&ACCOUNT_SEED, i)).collect()
}

/// The recipient addresses, each account sending to the next, wrapping round.
pub fn recipients(senders: &[Account]) -> Vec<String> {
    let n = senders.len();
    (0..n).map(|i| senders[(i + 1) % n].address()).collect()
}

/// The devnet configuration: a set of real validators all at the stake floor and the
/// funded sender accounts. This is byte for byte the configuration the in process
/// baseline builds, so the genesis, the validator set, and thus the committee draw
/// are identical between the two runs and the finalized chains are byte identical.
/// The `address` field is a symbolic handle only; the node never dials it, so the
/// real socket wiring lives outside the config and the config stays identical to the
/// baseline's for the byte identity oracle to hold.
pub fn devnet_config(base: &PathBuf, validators: usize, senders: &[Account]) -> DevnetConfig {
    let funded: Vec<GenesisAccount> = senders
        .iter()
        .map(|a| GenesisAccount::from_account(a, FUND))
        .collect();
    let nodes: Vec<NodeConfig> = (0..validators)
        .map(|i| {
            let id = i as u64 + 1;
            let bootstrap = if i == 0 {
                if validators > 1 {
                    vec![2]
                } else {
                    Vec::new()
                }
            } else {
                vec![1]
            };
            NodeConfig {
                id,
                stake: qtv_bft::params::VALIDATOR_STAKE_QTOV,
                online: true,
                store_dir: base.join(format!("node-{id}")),
                bootstrap,
                address: format!("mem://{id}"),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: funded,
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: FULL_FANOUT,
    }
}

/// Build and sign the transactions for one height: every account sends one transfer
/// to the next account at its current nonce. The signing is real ML-DSA work but it
/// is client side, so a caller times it separately and keeps it out of the consensus
/// throughput, exactly as the baseline does. Returns the batch and the wall clock
/// spent signing it.
pub fn build_batch(
    senders: &[Account],
    recipients: &[String],
    nonces: &mut [u64],
    fee: u128,
) -> (Vec<Wrapper>, Duration) {
    let start = Instant::now();
    let mut batch = Vec::with_capacity(senders.len());
    for (i, from) in senders.iter().enumerate() {
        let call = transfer_call(&recipients[i], TRANSFER_AMOUNT);
        let body = Body::new(from.address(), nonces[i], TRANSFER_GAS, fee, call);
        batch.push(sign(from, &body));
        nonces[i] += 1;
    }
    (batch, start.elapsed())
}

/// The protocol transfer fee, the same the baseline funds and charges.
pub fn transfer_fee() -> u128 {
    u128::from(FeeParams::devnet().transfer_fee())
}

/// The height a wire message belongs to, when it names one. An attestation, a coded
/// proposal shard, a whole proposal, and a view change record all name a height; a
/// transaction belongs to no single height and returns None so it is admitted
/// whenever it arrives. The runtime uses this to buffer a message that arrived ahead
/// of the height the node is on rather than dropping it, since a faster peer in its
/// own process can race a height ahead over the real sockets, which the single
/// process logical clock never had to handle.
pub fn message_height(message: &Message) -> Option<u64> {
    match message {
        Message::Tx(_) => None,
        Message::Proposal(p) => Some(p.header.height()),
        Message::CodedProposal(c) => Some(c.header.height()),
        Message::Attest(a) => Some(a.height),
        Message::ViewChange(v) => Some(v.height),
        Message::Peers(_)
        | Message::Status(_)
        | Message::GetBlocks { .. }
        | Message::Blocks(_) => None,
    }
}

/// A single digest over a node's whole finalized chain, the SHA3 the driver compares
/// across processes and against the in process reference to prove every process
/// finalized the byte identical chain. Two chains hash equal exactly when every
/// finalized block, header, body, and certificate, is byte identical.
pub fn chain_digest(encoded_blocks: &[Vec<u8>]) -> [u8; 32] {
    let mut buf = Vec::new();
    for block in encoded_blocks {
        buf.extend_from_slice(&(block.len() as u64).to_le_bytes());
        buf.extend_from_slice(block);
    }
    gossip_id(&buf)
}

/// Lowercase hex of a digest, for the line protocol between the child processes and
/// the driver.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

pub mod stats;
