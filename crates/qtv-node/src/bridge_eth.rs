// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::bridge::{Direction, Fact, FACT_VERSION};
use q_bls::Bls12381AggregateVerifier;
use qlc_ethereum::beacon::{BeaconBlockHeader, SyncAggregate, SyncCommittee};
use qlc_ethereum::bls::{BlsPubkey, BlsSignature, PUBKEY_LEN, SIGNATURE_LEN};
use qlc_ethereum::config::{
    arbitrum, avalanche, base, bnb_chain, ethereum, optimism, polygon, robinhood_chain,
    EvmChainConfig,
};
use qlc_ethereum::engine::{DepositProof, ExecutionCommit, LightClientStore, LightClientUpdate};
use qlc_ethereum::verify_trustless_deposit;
use qtv_crypto::sha3;

pub const MAX_ETH_COMMITTEE: usize = 2048;
pub const MAX_ETH_BRANCH: usize = 64;
pub const MAX_ETH_RECEIPT_NODES: usize = 256;
pub const MAX_ETH_RECEIPT_NODE_BYTES: usize = 1 << 16;
pub const MAX_ETH_MINT_BYTES: usize = 1 << 20;
pub const HEADER_BYTES: usize = 112;

pub fn eth_source_chain(config_selector: u8) -> u32 {
    0xFFFF_FE00u32 | config_selector as u32
}

fn eth_source_ref(finalized_root: &[u8; 32], receipt_index: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 8 + 16);
    buf.extend_from_slice(b"qtv/bridge/eth/ref");
    buf.extend_from_slice(finalized_root);
    buf.extend_from_slice(&receipt_index.to_le_bytes());
    sha3::sha3_256(&buf)
}

fn config_for_selector(selector: u8) -> Option<EvmChainConfig> {
    match selector {
        0 => Some(ethereum()),
        1 => Some(bnb_chain()),
        2 => Some(polygon()),
        3 => Some(avalanche()),
        4 => Some(arbitrum()),
        5 => Some(optimism()),
        6 => Some(base()),
        7 => Some(robinhood_chain()),
        _ => None,
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}

fn encode_header(out: &mut Vec<u8>, header: &BeaconBlockHeader) {
    out.extend_from_slice(&header.slot.to_le_bytes());
    out.extend_from_slice(&header.proposer_index.to_le_bytes());
    out.extend_from_slice(&header.parent_root);
    out.extend_from_slice(&header.state_root);
    out.extend_from_slice(&header.body_root);
}

fn decode_header(cursor: &mut Cursor) -> Option<BeaconBlockHeader> {
    Some(BeaconBlockHeader {
        slot: cursor.u64()?,
        proposer_index: cursor.u64()?,
        parent_root: cursor.arr32()?,
        state_root: cursor.arr32()?,
        body_root: cursor.arr32()?,
    })
}

fn encode_branch(out: &mut Vec<u8>, branch: &[[u8; 32]]) {
    put_u32(out, branch.len());
    for node in branch {
        out.extend_from_slice(node);
    }
}

fn decode_branch(cursor: &mut Cursor) -> Option<Vec<[u8; 32]>> {
    let count = cursor.u32()? as usize;
    if count > MAX_ETH_BRANCH {
        return None;
    }
    let mut branch = Vec::with_capacity(count);
    for _ in 0..count {
        branch.push(cursor.arr32()?);
    }
    Some(branch)
}

fn encode_committee(out: &mut Vec<u8>, committee: &SyncCommittee) {
    put_u32(out, committee.pubkeys.len());
    for pk in &committee.pubkeys {
        out.extend_from_slice(&pk.0);
    }
    out.extend_from_slice(&committee.aggregate_pubkey.0);
}

fn decode_committee(cursor: &mut Cursor) -> Option<SyncCommittee> {
    let count = cursor.u32()? as usize;
    if count > MAX_ETH_COMMITTEE {
        return None;
    }
    let mut pubkeys = Vec::with_capacity(count);
    for _ in 0..count {
        let pk: [u8; PUBKEY_LEN] = cursor.take(PUBKEY_LEN)?.try_into().ok()?;
        pubkeys.push(BlsPubkey(pk));
    }
    let aggregate: [u8; PUBKEY_LEN] = cursor.take(PUBKEY_LEN)?.try_into().ok()?;
    Some(SyncCommittee {
        pubkeys,
        aggregate_pubkey: BlsPubkey(aggregate),
    })
}

fn encode_aggregate(out: &mut Vec<u8>, aggregate: &SyncAggregate) {
    put_u32(out, aggregate.participation.len());
    let mut bits = vec![0u8; aggregate.participation.len().div_ceil(8)];
    for (i, present) in aggregate.participation.iter().enumerate() {
        if *present {
            bits[i / 8] |= 1 << (i % 8);
        }
    }
    out.extend_from_slice(&bits);
    out.extend_from_slice(&aggregate.signature.0);
}

fn decode_aggregate(cursor: &mut Cursor) -> Option<SyncAggregate> {
    let count = cursor.u32()? as usize;
    if count > MAX_ETH_COMMITTEE {
        return None;
    }
    let bits = cursor.take(count.div_ceil(8))?;
    let mut participation = Vec::with_capacity(count);
    for i in 0..count {
        participation.push(bits[i / 8] & (1 << (i % 8)) != 0);
    }
    let sig: [u8; SIGNATURE_LEN] = cursor.take(SIGNATURE_LEN)?.try_into().ok()?;
    Some(SyncAggregate {
        participation,
        signature: BlsSignature(sig),
    })
}

fn encode_execution(out: &mut Vec<u8>, execution: &ExecutionCommit) {
    out.extend_from_slice(&execution.receipts_root);
    out.extend_from_slice(&execution.block_number.to_le_bytes());
    encode_branch(out, &execution.execution_branch);
}

fn decode_execution(cursor: &mut Cursor) -> Option<ExecutionCommit> {
    Some(ExecutionCommit {
        receipts_root: cursor.arr32()?,
        block_number: cursor.u64()?,
        execution_branch: decode_branch(cursor)?,
    })
}

fn encode_update(out: &mut Vec<u8>, update: &LightClientUpdate) {
    encode_header(out, &update.attested_header);
    encode_header(out, &update.finalized_header);
    encode_branch(out, &update.finality_branch);
    encode_aggregate(out, &update.sync_aggregate);
    out.extend_from_slice(&update.signature_slot.to_le_bytes());
    encode_execution(out, &update.execution);
}

fn decode_update(cursor: &mut Cursor) -> Option<LightClientUpdate> {
    Some(LightClientUpdate {
        attested_header: decode_header(cursor)?,
        finalized_header: decode_header(cursor)?,
        finality_branch: decode_branch(cursor)?,
        sync_aggregate: decode_aggregate(cursor)?,
        signature_slot: cursor.u64()?,
        execution: decode_execution(cursor)?,
    })
}

fn encode_deposit(out: &mut Vec<u8>, deposit: &DepositProof) {
    out.extend_from_slice(&deposit.receipt_index.to_le_bytes());
    put_u32(out, deposit.receipt_proof.len());
    for node in &deposit.receipt_proof {
        put_u32(out, node.len());
        out.extend_from_slice(node);
    }
}

fn decode_deposit(cursor: &mut Cursor) -> Option<DepositProof> {
    let receipt_index = cursor.u64()?;
    let count = cursor.u32()? as usize;
    if count > MAX_ETH_RECEIPT_NODES {
        return None;
    }
    let mut receipt_proof = Vec::with_capacity(count);
    for _ in 0..count {
        let len = cursor.u32()? as usize;
        if len > MAX_ETH_RECEIPT_NODE_BYTES {
            return None;
        }
        receipt_proof.push(cursor.take(len)?.to_vec());
    }
    Some(DepositProof {
        receipt_index,
        receipt_proof,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthAnchor {
    pub config_selector: u8,
    pub period: u64,
    pub sync_committee_root: [u8; 32],
    pub deposit_contract: [u8; 20],
    pub asset_id: [u8; 16],
}

impl EthAnchor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 32 + 20 + 16);
        out.push(self.config_selector);
        out.extend_from_slice(&self.period.to_le_bytes());
        out.extend_from_slice(&self.sync_committee_root);
        out.extend_from_slice(&self.deposit_contract);
        out.extend_from_slice(&self.asset_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<EthAnchor> {
        let mut cursor = Cursor::new(bytes);
        let config_selector = cursor.u8()?;
        let period = cursor.u64()?;
        let sync_committee_root = cursor.arr32()?;
        let deposit_contract: [u8; 20] = cursor.take(20)?.try_into().ok()?;
        let asset_id: [u8; 16] = cursor.take(16)?.try_into().ok()?;
        cursor.done().then_some(EthAnchor {
            config_selector,
            period,
            sync_committee_root,
            deposit_contract,
            asset_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthMintProof {
    pub config_selector: u8,
    pub sync_committee: SyncCommittee,
    pub update: LightClientUpdate,
    pub deposit: DepositProof,
}

impl EthMintProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.config_selector);
        encode_committee(&mut out, &self.sync_committee);
        encode_update(&mut out, &self.update);
        encode_deposit(&mut out, &self.deposit);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<EthMintProof> {
        let mut cursor = Cursor::new(bytes);
        let config_selector = cursor.u8()?;
        let sync_committee = decode_committee(&mut cursor)?;
        let update = decode_update(&mut cursor)?;
        let deposit = decode_deposit(&mut cursor)?;
        cursor.done().then_some(EthMintProof {
            config_selector,
            sync_committee,
            update,
            deposit,
        })
    }

    pub fn source_key(&self) -> (u32, [u8; 32]) {
        let finalized_root = self.update.finalized_header.hash_tree_root();
        (
            eth_source_chain(self.config_selector),
            eth_source_ref(&finalized_root, self.deposit.receipt_index),
        )
    }
}

pub fn verify_eth_mint(anchor: &EthAnchor, proof: &EthMintProof, dest_chain: u32) -> Option<Fact> {
    if proof.config_selector != anchor.config_selector {
        return None;
    }
    let mut config = config_for_selector(anchor.config_selector)?;
    config.deposit_contract = anchor.deposit_contract;
    if proof.sync_committee.pubkeys.len() != config.sync_committee_size {
        return None;
    }
    if proof.sync_committee.hash_tree_root() != anchor.sync_committee_root {
        return None;
    }
    let finalized_root = proof.update.finalized_header.hash_tree_root();
    let store = LightClientStore::from_trusted_committee(
        config,
        anchor.period,
        proof.sync_committee.clone(),
        proof.update.finalized_header,
    );
    let verifier = Bls12381AggregateVerifier::new();
    let deposit =
        verify_trustless_deposit(&store, &proof.update, &proof.deposit, &verifier).ok()?;
    if deposit.amount() == 0 {
        return None;
    }
    if deposit.asset_id() != anchor.asset_id {
        return None;
    }
    Some(Fact {
        version: FACT_VERSION,
        source_chain: eth_source_chain(anchor.config_selector),
        dest_chain,
        route_id: 0,
        direction: Direction::Deposit,
        nonce: 0,
        source_ref: eth_source_ref(&finalized_root, proof.deposit.receipt_index),
        asset_id: anchor.asset_id,
        amount: deposit.amount(),
        recipient: deposit.recipient(),
        finality_depth: deposit.finality_depth(),
        observed_height: deposit.block_number(),
        expiry_height: u64::MAX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_header(tag: u8) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: 0x0102_0304_0506_0708,
            proposer_index: 42,
            parent_root: [tag; 32],
            state_root: [tag ^ 0x11; 32],
            body_root: [tag ^ 0x22; 32],
        }
    }

    fn dummy_committee(n: usize) -> SyncCommittee {
        SyncCommittee {
            pubkeys: (0..n).map(|i| BlsPubkey([i as u8; PUBKEY_LEN])).collect(),
            aggregate_pubkey: BlsPubkey([0xcd; PUBKEY_LEN]),
        }
    }

    fn dummy_proof() -> EthMintProof {
        EthMintProof {
            config_selector: 3,
            sync_committee: dummy_committee(5),
            update: LightClientUpdate {
                attested_header: dummy_header(0x30),
                finalized_header: dummy_header(0x40),
                finality_branch: vec![[0x51; 32], [0x52; 32]],
                sync_aggregate: SyncAggregate {
                    participation: vec![true, false, true, true, false],
                    signature: BlsSignature([0x7a; SIGNATURE_LEN]),
                },
                signature_slot: 0x00ff_00ff_00ff_00ff,
                execution: ExecutionCommit {
                    receipts_root: [0x61; 32],
                    block_number: 20_000_000,
                    execution_branch: vec![[0x71; 32], [0x72; 32], [0x73; 32]],
                },
            },
            deposit: DepositProof {
                receipt_index: 3,
                receipt_proof: vec![vec![0xa1, 0xa2], vec![], vec![0xb1; 40]],
            },
        }
    }

    #[test]
    fn anchor_round_trips_through_its_wire_encoding() {
        let anchor = EthAnchor {
            config_selector: 2,
            period: 0x1122_3344_5566_7788,
            sync_committee_root: [0x9a; 32],
            deposit_contract: [0xbc; 20],
            asset_id: [0x0e; 16],
        };
        assert_eq!(EthAnchor::decode(&anchor.encode()), Some(anchor));
    }

    #[test]
    fn a_truncated_anchor_is_refused() {
        let anchor = EthAnchor {
            config_selector: 0,
            period: 7,
            sync_committee_root: [1; 32],
            deposit_contract: [2; 20],
            asset_id: [3; 16],
        };
        let mut bytes = anchor.encode();
        bytes.pop();
        assert_eq!(EthAnchor::decode(&bytes), None);
    }

    #[test]
    fn a_trailing_byte_on_the_anchor_is_refused() {
        let anchor = EthAnchor {
            config_selector: 0,
            period: 7,
            sync_committee_root: [1; 32],
            deposit_contract: [2; 20],
            asset_id: [3; 16],
        };
        let mut bytes = anchor.encode();
        bytes.push(0);
        assert_eq!(EthAnchor::decode(&bytes), None);
    }

    #[test]
    fn a_mint_proof_round_trips_through_its_wire_encoding() {
        let proof = dummy_proof();
        assert_eq!(EthMintProof::decode(&proof.encode()), Some(proof));
    }

    #[test]
    fn a_committee_over_the_bound_is_refused() {
        let mut proof = dummy_proof();
        proof.sync_committee = dummy_committee(MAX_ETH_COMMITTEE + 1);
        proof.sync_aggregate_participation_to(MAX_ETH_COMMITTEE + 1);
        assert_eq!(EthMintProof::decode(&proof.encode()), None);
    }

    #[test]
    fn the_source_key_is_per_chain_and_per_finalized_receipt() {
        let proof = dummy_proof();
        let (chain, reference) = proof.source_key();
        assert_eq!(chain, eth_source_chain(proof.config_selector));
        let finalized_root = proof.update.finalized_header.hash_tree_root();
        assert_eq!(
            reference,
            eth_source_ref(&finalized_root, proof.deposit.receipt_index)
        );
        assert_ne!(eth_source_chain(0), eth_source_chain(1));
    }

    #[test]
    fn a_different_receipt_index_yields_a_different_reference() {
        let root = [0x5e; 32];
        assert_ne!(eth_source_ref(&root, 3), eth_source_ref(&root, 4));
    }

    impl EthMintProof {
        fn sync_aggregate_participation_to(&mut self, n: usize) {
            self.update.sync_aggregate.participation = vec![true; n];
        }
    }
}
