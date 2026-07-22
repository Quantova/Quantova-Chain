
use qtv_account::{derive, Account};
use qtv_devnet::config::{DevnetConfig, NodeConfig, FULL_FANOUT};
use qtv_devnet::wire::{gossip_id, Message};
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;
use qtv_tx::{sign, Body, Wrapper};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const GENESIS_TIME: u64 = 1_700_000_000_000;
pub const ACCOUNT_SEED: [u8; 32] = [37u8; 32];
pub const FUND: u64 = 1_000_000_000_000;
pub const TRANSFER_AMOUNT: u64 = 1;
pub const HARNESS_SLOTS: u64 = 4096;

pub fn accounts(count: usize) -> Vec<Account> {
    (0..count as u64).map(|i| derive(&ACCOUNT_SEED, i)).collect()
}

pub fn recipients(senders: &[Account]) -> Vec<String> {
    let n = senders.len();
    (0..n).map(|i| senders[(i + 1) % n].address()).collect()
}

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
                secret: qtv_node::keys::fixture_secret(id),
            }
        })
        .collect();
    DevnetConfig {
        fee_params: FeeParams::devnet(),
        accounts: funded,
        nodes,
        genesis_time: GENESIS_TIME,
        fanout: FULL_FANOUT,
        slots: HARNESS_SLOTS,
    }
}

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
        let body = Body::new(from.address(), nonces[i], TRANSFER_METER, fee, call);
        batch.push(sign(from, &body));
        nonces[i] += 1;
    }
    (batch, start.elapsed())
}

pub fn transfer_fee() -> u128 {
    u128::from(FeeParams::devnet().transfer_fee())
}

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

pub fn chain_digest(encoded_blocks: &[Vec<u8>]) -> [u8; 32] {
    let mut buf = Vec::new();
    for block in encoded_blocks {
        buf.extend_from_slice(&(block.len() as u64).to_le_bytes());
        buf.extend_from_slice(block);
    }
    gossip_id(&buf)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 15) as u32, 16).unwrap());
    }
    s
}

pub mod stats;
