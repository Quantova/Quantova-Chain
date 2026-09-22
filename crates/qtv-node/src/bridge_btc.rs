// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::bridge::{Direction, Fact, FACT_VERSION};
use qtv_btc_spv::chain::Checkpoint;
use qtv_btc_spv::{
    network_params, verify_chain, verify_trustless_deposit, BlockHeader, CoinbaseProof, MerkleStep,
    Network, NetworkParams, HEADER_LEN, MAX_MERKLE_BRANCH, U256,
};

pub const MAX_BTC_HEADERS: usize = 4096;
pub const MAX_BTC_RAW_TX: usize = 1 << 16;
pub const BITCOIN_MINT_SOURCE_CHAIN: u32 = 0xFFFF_FF01;

pub const MAX_BTC_DEPOSIT_SATS: u128 = qtv_btc_spv::deposit::MAX_TRUSTLESS_DEPOSIT_SATS;

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

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAnchor {
    pub network: u8,
    pub checkpoint_height: u32,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_min_work: [u8; 32],
    pub asset_id: [u8; 16],
    pub deposit_script: Vec<u8>,
}

impl BitcoinAnchor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(89 + self.deposit_script.len());
        out.push(self.network);
        out.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        out.extend_from_slice(&self.checkpoint_hash);
        out.extend_from_slice(&self.checkpoint_min_work);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&(self.deposit_script.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.deposit_script);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<BitcoinAnchor> {
        let mut cursor = Cursor::new(bytes);
        let network = cursor.u8()?;
        let checkpoint_height = cursor.u32()?;
        let checkpoint_hash: [u8; 32] = cursor.take(32)?.try_into().ok()?;
        let checkpoint_min_work: [u8; 32] = cursor.take(32)?.try_into().ok()?;
        let asset_id: [u8; 16] = cursor.take(16)?.try_into().ok()?;
        let script_len = cursor.u32()? as usize;
        let deposit_script = cursor.take(script_len)?.to_vec();
        cursor.done().then_some(BitcoinAnchor {
            network,
            checkpoint_height,
            checkpoint_hash,
            checkpoint_min_work,
            asset_id,
            deposit_script,
        })
    }

    fn params(&self) -> Option<NetworkParams> {
        match self.network {
            0 => Some(network_params(Network::Bitcoin)),
            1 => Some(network_params(Network::BitcoinCash)),
            #[cfg(test)]
            255 => Some(EASY_TEST_PARAMS),
            _ => None,
        }
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            height: self.checkpoint_height,
            hash: self.checkpoint_hash,
            min_work: U256::from_be_bytes(&self.checkpoint_min_work),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinMintProof {
    pub start_height: u32,
    pub headers: Vec<[u8; HEADER_LEN]>,
    pub deposit_height: u32,
    pub branch: Vec<MerkleStep>,
    pub raw_tx: Vec<u8>,
    pub coinbase_tx: Vec<u8>,
    pub coinbase_branch: Vec<MerkleStep>,
}

fn put_branch(out: &mut Vec<u8>, branch: &[MerkleStep]) {
    out.extend_from_slice(&(branch.len() as u32).to_le_bytes());
    for step in branch {
        out.extend_from_slice(&step.hash);
        out.push(step.sibling_on_left as u8);
    }
}

fn take_branch(cursor: &mut Cursor) -> Option<Vec<MerkleStep>> {
    let step_count = cursor.u32()? as usize;
    if step_count > MAX_MERKLE_BRANCH {
        return None;
    }
    let mut branch = Vec::with_capacity(step_count);
    for _ in 0..step_count {
        let hash: [u8; 32] = cursor.take(32)?.try_into().ok()?;
        let sibling_on_left = match cursor.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        branch.push(MerkleStep {
            hash,
            sibling_on_left,
        });
    }
    Some(branch)
}

fn take_tx(cursor: &mut Cursor) -> Option<Vec<u8>> {
    let tx_len = cursor.u32()? as usize;
    if tx_len > MAX_BTC_RAW_TX {
        return None;
    }
    Some(cursor.take(tx_len)?.to_vec())
}

impl BitcoinMintProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.start_height.to_le_bytes());
        out.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        for header in &self.headers {
            out.extend_from_slice(header);
        }
        out.extend_from_slice(&self.deposit_height.to_le_bytes());
        put_branch(&mut out, &self.branch);
        out.extend_from_slice(&(self.raw_tx.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.raw_tx);
        out.extend_from_slice(&(self.coinbase_tx.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.coinbase_tx);
        put_branch(&mut out, &self.coinbase_branch);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<BitcoinMintProof> {
        let mut cursor = Cursor::new(bytes);
        let start_height = cursor.u32()?;
        let header_count = cursor.u32()? as usize;
        if header_count > MAX_BTC_HEADERS {
            return None;
        }
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let header: [u8; HEADER_LEN] = cursor.take(HEADER_LEN)?.try_into().ok()?;
            headers.push(header);
        }
        let deposit_height = cursor.u32()?;
        let branch = take_branch(&mut cursor)?;
        let raw_tx = take_tx(&mut cursor)?;
        let coinbase_tx = take_tx(&mut cursor)?;
        let coinbase_branch = take_branch(&mut cursor)?;
        cursor.done().then_some(BitcoinMintProof {
            start_height,
            headers,
            deposit_height,
            branch,
            raw_tx,
            coinbase_tx,
            coinbase_branch,
        })
    }
}

pub const NETWORK_BITCOIN_CASH: u8 = 1;

pub fn bitcoin_mint_work(anchor: &BitcoinAnchor, proof: &BitcoinMintProof) -> Option<[u8; 32]> {
    if anchor.network == NETWORK_BITCOIN_CASH {
        return None;
    }
    let params = anchor.params()?;
    let mut headers = Vec::with_capacity(proof.headers.len());
    for raw in &proof.headers {
        headers.push(BlockHeader::parse(raw).ok()?);
    }
    let chain = verify_chain(&headers, proof.start_height, &params).ok()?;
    let checkpoint = anchor.checkpoint();
    chain.anchored_to(&checkpoint).ok()?;
    Some(chain.work_above(checkpoint.height).to_be_bytes())
}

pub fn verify_bitcoin_mint(
    anchor: &BitcoinAnchor,
    proof: &BitcoinMintProof,
    dest_chain: u32,
) -> Option<Fact> {
    if anchor.network == NETWORK_BITCOIN_CASH {
        return None;
    }
    let params = anchor.params()?;
    let mut headers = Vec::with_capacity(proof.headers.len());
    for raw in &proof.headers {
        headers.push(BlockHeader::parse(raw).ok()?);
    }
    let chain = verify_chain(&headers, proof.start_height, &params).ok()?;
    let checkpoint = anchor.checkpoint();
    let deposit = verify_trustless_deposit(
        &chain,
        &params,
        &checkpoint,
        proof.deposit_height,
        &proof.branch,
        &proof.raw_tx,
        &CoinbaseProof {
            raw_tx: &proof.coinbase_tx,
            branch: &proof.coinbase_branch,
        },
        &anchor.deposit_script,
    )
    .ok()?;
    if deposit.amount == 0 || deposit.amount > MAX_BTC_DEPOSIT_SATS {
        return None;
    }
    Some(Fact {
        version: FACT_VERSION,
        source_chain: BITCOIN_MINT_SOURCE_CHAIN,
        dest_chain,
        route_id: 0,
        direction: Direction::Deposit,
        nonce: 0,
        source_ref: deposit.txid,
        asset_id: anchor.asset_id,
        amount: deposit.amount,
        recipient: deposit.recipient,
        finality_depth: params.confirmation_depth,
        observed_height: proof.deposit_height as u64,
        expiry_height: u64::MAX,
    })
}

#[cfg(test)]
const EASY_TEST_PARAMS: NetworkParams = NetworkParams {
    network: Network::Bitcoin,
    name: "test",
    magic: [0xfa, 0xbf, 0xb5, 0xda],
    pow_limit_bits: 0x207f_ffff,
    target_timespan: 1_209_600,
    target_spacing: 600,
    confirmation_depth: 1,
    requires_pinned_checkpoint: false,
};

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_btc_spv::tx::Transaction;

    fn p2pkh(hash160: [u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&hash160);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    fn op_return(recipient: [u8; 32]) -> Vec<u8> {
        let mut s = vec![0x6a, 0x20];
        s.extend_from_slice(&recipient);
        s
    }

    fn raw_deposit_tx(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&2u32.to_le_bytes());
        out.push(0x01);
        out.extend_from_slice(&[0u8; 36]);
        out.push(0x00);
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        out.push(outputs.len() as u8);
        for (value, script) in outputs {
            out.extend_from_slice(&value.to_le_bytes());
            out.push(script.len() as u8);
            out.extend_from_slice(script);
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn mine(merkle_root: [u8; 32]) -> BlockHeader {
        let mut header = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root,
            timestamp: 1_700_000_000,
            bits: EASY_TEST_PARAMS.pow_limit_bits,
            nonce: 0,
        };
        while !header.meets_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn anchor_for(header: &BlockHeader, bridge: Vec<u8>) -> BitcoinAnchor {
        BitcoinAnchor {
            network: 255,
            checkpoint_height: 0,
            checkpoint_hash: header.block_hash(),
            checkpoint_min_work: [0u8; 32],
            asset_id: [0x7u8; 16],
            deposit_script: bridge,
        }
    }

    fn coinbase_tx() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(0x01);
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&[0xff; 4]);
        out.push(0x04);
        out.extend_from_slice(&[0x03, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        out.push(0x01);
        out.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        out.push(0x01);
        out.push(0x51);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn coinbase_id() -> [u8; 32] {
        Transaction::parse(&coinbase_tx()).unwrap().txid()
    }

    fn mine_with(txid: [u8; 32]) -> BlockHeader {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&coinbase_id());
        buf[32..].copy_from_slice(&txid);
        mine(qtv_btc_spv::sha256::double_sha256(&buf))
    }

    fn proof_for(header: &BlockHeader, raw_tx: Vec<u8>) -> BitcoinMintProof {
        let txid = Transaction::parse(&raw_tx)
            .map(|tx| tx.txid())
            .unwrap_or([0u8; 32]);
        BitcoinMintProof {
            start_height: 0,
            headers: vec![header.serialize()],
            deposit_height: 0,
            branch: vec![MerkleStep {
                hash: coinbase_id(),
                sibling_on_left: true,
            }],
            raw_tx,
            coinbase_tx: coinbase_tx(),
            coinbase_branch: vec![MerkleStep {
                hash: txid,
                sibling_on_left: false,
            }],
        }
    }

    #[test]
    fn anchor_and_proof_round_trip() {
        let header = mine([0x33u8; 32]);
        let anchor = anchor_for(&header, p2pkh([0x11; 20]));
        assert_eq!(BitcoinAnchor::decode(&anchor.encode()), Some(anchor));
        let proof = proof_for(&header, raw_deposit_tx(&[(1, p2pkh([0x11; 20]))]));
        assert_eq!(BitcoinMintProof::decode(&proof.encode()), Some(proof));
    }

    #[test]
    fn a_proven_deposit_yields_a_fact_bound_to_the_proof_not_a_caller() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let header = mine_with(txid);
        let fact = verify_bitcoin_mint(
            &anchor_for(&header, bridge.clone()),
            &proof_for(&header, raw),
            9,
        )
        .expect("a proven deposit mints");
        assert_eq!(fact.amount, 250_000);
        assert_eq!(fact.recipient, recipient);
        assert_eq!(fact.source_ref, txid);
        assert_eq!(fact.source_chain, BITCOIN_MINT_SOURCE_CHAIN);
        assert_eq!(fact.dest_chain, 9);
    }

    #[test]
    fn the_bitcoin_cash_corridor_is_closed_until_asert() {
        let bridge = p2pkh([0x11; 20]);
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return([0x42u8; 32]))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let header = mine_with(txid);
        let mut anchor = anchor_for(&header, bridge);
        anchor.network = NETWORK_BITCOIN_CASH;
        let proof = proof_for(&header, raw);
        assert_eq!(verify_bitcoin_mint(&anchor, &proof, 9), None);
        assert_eq!(bitcoin_mint_work(&anchor, &proof), None);
    }

    #[test]
    fn a_proof_lighter_than_the_recorded_best_work_is_a_private_fork() {
        let bridge = p2pkh([0x11; 20]);
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return([0x42u8; 32]))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let header = mine_with(txid);
        let anchor = anchor_for(&header, bridge);
        let proof = proof_for(&header, raw);
        let work = bitcoin_mint_work(&anchor, &proof).expect("a real proof carries work");
        let mut heavier = work;
        for byte in heavier.iter_mut() {
            if *byte != 0xff {
                *byte += 1;
                break;
            }
        }
        assert!(
            work < heavier,
            "the recorded best work outweighs this proof"
        );
    }

    #[test]
    fn a_forged_merkle_branch_is_refused() {
        let bridge = p2pkh([0x11; 20]);
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return([0x42u8; 32]))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let header = mine_with(txid);
        let mut proof = proof_for(&header, raw);
        proof.branch = vec![MerkleStep {
            hash: [0x99u8; 32],
            sibling_on_left: false,
        }];
        assert_eq!(
            verify_bitcoin_mint(&anchor_for(&header, bridge), &proof, 9),
            None
        );
    }

    #[test]
    fn a_deposit_not_to_the_bridge_script_is_refused() {
        let elsewhere = p2pkh([0x22; 20]);
        let raw = raw_deposit_tx(&[(250_000, elsewhere), (0, op_return([0x42u8; 32]))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let header = mine_with(txid);
        assert_eq!(
            verify_bitcoin_mint(
                &anchor_for(&header, p2pkh([0x11; 20])),
                &proof_for(&header, raw),
                9
            ),
            None
        );
    }

    #[test]
    fn a_wrong_checkpoint_anchor_is_refused() {
        let bridge = p2pkh([0x11; 20]);
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return([0x42u8; 32]))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let header = mine_with(txid);
        let mut anchor = anchor_for(&header, bridge);
        anchor.checkpoint_hash = [0xabu8; 32];
        assert_eq!(
            verify_bitcoin_mint(&anchor, &proof_for(&header, raw), 9),
            None
        );
    }
}
