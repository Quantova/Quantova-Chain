// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::chain::{Checkpoint, VerifiedChain};
use crate::params::NetworkParams;
use crate::tx::Transaction;
use crate::{MerkleStep, SpvError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustlessDeposit {
    pub txid: [u8; 32],
    pub amount: u128,
    pub recipient: [u8; 32],
    pub confirmations: u32,
}

pub struct CoinbaseProof<'a> {
    pub raw_tx: &'a [u8],
    pub branch: &'a [MerkleStep],
}

const SATS_PER_BTC: u128 = 100_000_000;

pub const MAX_TRUSTLESS_DEPOSIT_SATS: u128 = 100 * SATS_PER_BTC;

pub fn confirmations_for(amount: u128, base: u32) -> u32 {
    let scaled = amount.div_ceil(SATS_PER_BTC / 2);
    base.max(u32::try_from(scaled).unwrap_or(u32::MAX))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_trustless_deposit(
    chain: &VerifiedChain,
    params: &NetworkParams,
    checkpoint: &Checkpoint,
    deposit_height: u32,
    branch: &[MerkleStep],
    raw_tx: &[u8],
    coinbase: &CoinbaseProof<'_>,
    deposit_script: &[u8],
) -> Result<TrustlessDeposit, SpvError> {
    let pinned;
    let anchor = if params.requires_pinned_checkpoint {
        pinned =
            crate::chain::pinned_checkpoint(params.network).ok_or(SpvError::CheckpointNotArmed)?;
        &pinned
    } else {
        checkpoint
    };
    chain.anchored_to(anchor)?;
    let first = Transaction::parse(coinbase.raw_tx)?;
    if !first.is_coinbase() || coinbase.branch.iter().any(|step| step.sibling_on_left) {
        return Err(SpvError::TransactionMismatch);
    }
    chain.verify_deposit(
        deposit_height,
        first.txid(),
        coinbase.branch,
        params.confirmation_depth,
    )?;
    if branch.len() != coinbase.branch.len() {
        return Err(SpvError::MerkleMismatch);
    }
    let tx = Transaction::parse(raw_tx)?;
    if tx.is_coinbase() {
        return Err(SpvError::TransactionMismatch);
    }
    let txid = tx.txid();
    let (amount, recipient) = tx
        .deposit_to(deposit_script)
        .ok_or(SpvError::TransactionMismatch)?;
    if amount > MAX_TRUSTLESS_DEPOSIT_SATS {
        return Err(SpvError::DepositTooLarge);
    }
    let confirmed = chain.verify_deposit(
        deposit_height,
        txid,
        branch,
        confirmations_for(amount, params.confirmation_depth),
    )?;
    Ok(TrustlessDeposit {
        txid,
        amount,
        recipient,
        confirmations: confirmed.confirmations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_chain;
    use crate::params::Network;
    use crate::tx::check_deposit_tx;
    use crate::BlockHeader;

    const EASY: NetworkParams = NetworkParams {
        network: Network::Bitcoin,
        name: "Crafted",
        magic: [0xfa, 0xbf, 0xb5, 0xda],
        pow_limit_bits: 0x207f_ffff,
        target_timespan: 1_209_600,
        target_spacing: 600,
        confirmation_depth: 1,
        requires_pinned_checkpoint: false,
    };

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

    struct Block {
        header: BlockHeader,
        coinbase: Vec<u8>,
        coinbase_branch: Vec<MerkleStep>,
        branch: Vec<MerkleStep>,
    }

    impl Block {
        fn coinbase(&self) -> CoinbaseProof<'_> {
            CoinbaseProof {
                raw_tx: &self.coinbase,
                branch: &self.coinbase_branch,
            }
        }
    }

    fn pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        crate::sha256::double_sha256(&buf)
    }

    fn block_with(txid: [u8; 32]) -> Block {
        let coinbase = coinbase_tx();
        let coinbase_id = Transaction::parse(&coinbase).unwrap().txid();
        Block {
            header: mined_block(pair(&coinbase_id, &txid)),
            coinbase,
            coinbase_branch: vec![MerkleStep {
                hash: txid,
                sibling_on_left: false,
            }],
            branch: vec![MerkleStep {
                hash: coinbase_id,
                sibling_on_left: true,
            }],
        }
    }

    fn mined_block(root: [u8; 32]) -> BlockHeader {
        let mut header = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: root,
            timestamp: 1_700_000_000,
            bits: EASY.pow_limit_bits,
            nonce: 0,
        };
        while !header.meets_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    #[test]
    fn a_crafted_deposit_in_a_crafted_block_verifies_end_to_end() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();

        let proven = verify_trustless_deposit(
            &chain,
            &EASY,
            &Checkpoint::accepting(&chain),
            0,
            &block.branch,
            &raw,
            &block.coinbase(),
            &bridge,
        )
        .unwrap();
        assert_eq!(proven.txid, txid);
        assert_eq!(proven.amount, 250_000);
        assert_eq!(proven.recipient, recipient);
        assert_eq!(proven.confirmations, 1);
    }

    #[test]
    fn a_mainnet_deposit_is_refused_until_the_checkpoint_is_armed() {
        let armed = NetworkParams {
            requires_pinned_checkpoint: true,
            ..EASY
        };
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &armed).unwrap();

        assert_eq!(
            verify_trustless_deposit(&chain, &armed, &Checkpoint::accepting(&chain), 0, &block.branch, &raw, &block.coinbase(), &bridge),
            Err(SpvError::CheckpointNotArmed),
            "a checkpoint requiring network anchors only to its pinned block, never a caller supplied one"
        );
    }

    #[test]
    fn a_deposit_on_a_chain_off_the_pinned_checkpoint_is_rejected() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();

        let foreign = Checkpoint {
            height: 0,
            hash: [0x99u8; 32],
            min_work: crate::work::U256::ZERO,
        };
        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &EASY,
                &foreign,
                0,
                &block.branch,
                &raw,
                &block.coinbase(),
                &bridge
            ),
            Err(SpvError::CheckpointMismatch),
            "a proof on a chain the caller mined off its own history cannot admit"
        );
    }

    #[test]
    fn a_split_deposit_in_a_crafted_block_sums_to_the_full_amount() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[
            (100_000, bridge.clone()),
            (150_000, bridge.clone()),
            (0, op_return(recipient)),
        ]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();

        let proven = verify_trustless_deposit(
            &chain,
            &EASY,
            &Checkpoint::accepting(&chain),
            0,
            &block.branch,
            &raw,
            &block.coinbase(),
            &bridge,
        )
        .unwrap();
        assert_eq!(proven.amount, 250_000);
        assert_eq!(proven.recipient, recipient);
    }

    #[test]
    fn a_deposit_that_pays_a_different_script_is_rejected() {
        let bridge = p2pkh([0x11; 20]);
        let elsewhere = p2pkh([0x22; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, elsewhere), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();

        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &EASY,
                &Checkpoint::accepting(&chain),
                0,
                &block.branch,
                &raw,
                &block.coinbase(),
                &bridge
            ),
            Err(SpvError::TransactionMismatch)
        );
    }

    #[test]
    fn a_claimed_value_the_transaction_does_not_carry_is_rejected() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();

        let proven = verify_trustless_deposit(
            &chain,
            &EASY,
            &Checkpoint::accepting(&chain),
            0,
            &block.branch,
            &raw,
            &block.coinbase(),
            &bridge,
        )
        .unwrap();
        assert_eq!(proven.amount, 250_000);
        assert!(check_deposit_tx(&raw, &bridge, proven.txid, 250_000, recipient).is_ok());
        assert_eq!(
            check_deposit_tx(&raw, &bridge, proven.txid, 999_999, recipient),
            Err(SpvError::TransactionMismatch)
        );
        assert_eq!(
            check_deposit_tx(&raw, &bridge, proven.txid, 250_000, [0x43u8; 32]),
            Err(SpvError::TransactionMismatch)
        );
    }

    #[test]
    fn a_deposit_short_of_the_confirmation_depth_is_rejected() {
        let deep = NetworkParams {
            confirmation_depth: 3,
            ..EASY
        };
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &deep).unwrap();

        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &deep,
                &Checkpoint::accepting(&chain),
                0,
                &block.branch,
                &raw,
                &block.coinbase(),
                &bridge
            ),
            Err(SpvError::InsufficientConfirmations { have: 1, need: 3 })
        );
    }

    #[test]
    fn a_transaction_absent_from_the_block_is_rejected() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let other = raw_deposit_tx(&[(999, bridge.clone()), (0, op_return([0x7u8; 32]))]);
        let other_txid = Transaction::parse(&other).unwrap().txid();
        let block = block_with(other_txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();

        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &EASY,
                &Checkpoint::accepting(&chain),
                0,
                &block.branch,
                &raw,
                &block.coinbase(),
                &bridge
            ),
            Err(SpvError::MerkleMismatch)
        );
    }

    #[test]
    fn a_fake_transaction_hung_under_a_64_byte_one_is_refused() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let fake = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let fake_id = Transaction::parse(&fake).unwrap().txid();
        let left = [0x5au8; 32];
        let sixty_four_byte_node = pair(&left, &fake_id);
        let coinbase = coinbase_tx();
        let coinbase_id = Transaction::parse(&coinbase).unwrap().txid();
        let header = mined_block(pair(&coinbase_id, &sixty_four_byte_node));
        let chain = verify_chain(&[header], 0, &EASY).unwrap();
        let coinbase_branch = vec![MerkleStep {
            hash: sixty_four_byte_node,
            sibling_on_left: false,
        }];
        let branch = vec![
            MerkleStep {
                hash: left,
                sibling_on_left: true,
            },
            MerkleStep {
                hash: coinbase_id,
                sibling_on_left: true,
            },
        ];
        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &EASY,
                &Checkpoint::accepting(&chain),
                0,
                &branch,
                &fake,
                &CoinbaseProof {
                    raw_tx: &coinbase,
                    branch: &coinbase_branch,
                },
                &bridge
            ),
            Err(SpvError::MerkleMismatch),
            "the branch is one level deeper than the tree the coinbase proves"
        );
    }

    #[test]
    fn a_coinbase_proof_must_carry_a_coinbase() {
        let bridge = p2pkh([0x11; 20]);
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return([0x42; 32]))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();
        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &EASY,
                &Checkpoint::accepting(&chain),
                0,
                &block.branch,
                &raw,
                &CoinbaseProof {
                    raw_tx: &raw,
                    branch: &block.coinbase_branch,
                },
                &bridge
            ),
            Err(SpvError::TransactionMismatch)
        );
    }

    #[test]
    fn a_larger_deposit_waits_for_more_confirmations() {
        let bridge = p2pkh([0x11; 20]);
        let raw = raw_deposit_tx(&[
            (5 * 100_000_000, bridge.clone()),
            (0, op_return([0x42; 32])),
        ]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let block = block_with(txid);
        let chain = verify_chain(&[block.header], 0, &EASY).unwrap();
        assert_eq!(
            verify_trustless_deposit(
                &chain,
                &EASY,
                &Checkpoint::accepting(&chain),
                0,
                &block.branch,
                &raw,
                &block.coinbase(),
                &bridge
            ),
            Err(SpvError::InsufficientConfirmations { have: 1, need: 10 })
        );
        assert_eq!(confirmations_for(100_000_000, 6), 6);
        assert_eq!(confirmations_for(10 * 100_000_000, 6), 20);
        assert_eq!(confirmations_for(100 * 100_000_000, 6), 200);
    }
}
