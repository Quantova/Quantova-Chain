// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::params::NetworkParams;
use crate::retarget::compute_retarget;
use crate::work::{block_work, U256};
use crate::{compact_to_target, fold_merkle_branch, BlockHeader, MerkleStep, SpvError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    pub start_height: u32,
    pub tip_height: u32,
    pub tip_hash: [u8; 32],
    pub work: U256,
    headers: Vec<BlockHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: [u8; 32],
    pub min_work: U256,
}

impl Checkpoint {
    #[cfg(test)]
    pub fn accepting(chain: &VerifiedChain) -> Checkpoint {
        Checkpoint {
            height: chain.start_height,
            hash: chain
                .header_at(chain.start_height)
                .map(|h| h.block_hash())
                .unwrap_or([0u8; 32]),
            min_work: U256::ZERO,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedDeposit {
    pub block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub deposit_height: u32,
    pub confirmations: u32,
}

pub fn bits_expectation(
    height: u32,
    prev_bits: u32,
    this_bits: u32,
    params: &NetworkParams,
    index: usize,
) -> Result<(), SpvError> {
    if height % params.retarget_interval() == 0 {
        let prev = U256::from_compact(prev_bits);
        let next = U256::from_compact(this_bits);
        if next > prev.mul_u64(4) || next < prev.div_u64(4) {
            return Err(SpvError::RetargetMismatch { index });
        }
        Ok(())
    } else if this_bits == prev_bits {
        Ok(())
    } else {
        Err(SpvError::RetargetOnANonBoundary { index })
    }
}

pub fn verify_chain(
    headers: &[BlockHeader],
    start_height: u32,
    params: &NetworkParams,
) -> Result<VerifiedChain, SpvError> {
    if headers.is_empty() {
        return Err(SpvError::EmptyChain);
    }
    let pow_limit = compact_to_target(params.pow_limit_bits);
    let mut work = U256::ZERO;
    for (i, h) in headers.iter().enumerate() {
        if !h.meets_pow() {
            return Err(SpvError::PowNotMet);
        }
        if h.target() > pow_limit {
            return Err(SpvError::TargetBelowFloor { index: i });
        }
        let height = start_height
            .checked_add(i as u32)
            .ok_or(SpvError::HeightOverflow)?;
        if i > 0 {
            let prev = &headers[i - 1];
            if h.prev_block != prev.block_hash() {
                return Err(SpvError::BrokenLink { index: i });
            }
            let interval = params.retarget_interval() as usize;
            if height % params.retarget_interval() == 0 && i >= interval {
                check_retarget_boundary(&headers[i - interval], prev, h, params)?;
            } else {
                bits_expectation(height, prev.bits, h.bits, params, i)?;
            }
        }
        work = work.wrapping_add(&block_work(h.bits));
    }
    let last = headers[headers.len() - 1];
    let tip_height = start_height
        .checked_add(headers.len() as u32 - 1)
        .ok_or(SpvError::HeightOverflow)?;
    Ok(VerifiedChain {
        start_height,
        tip_height,
        tip_hash: last.block_hash(),
        work,
        headers: headers.to_vec(),
    })
}

pub fn check_retarget_boundary(
    period_first: &BlockHeader,
    period_last: &BlockHeader,
    boundary: &BlockHeader,
    params: &NetworkParams,
) -> Result<(), SpvError> {
    if !boundary.meets_pow() {
        return Err(SpvError::PowNotMet);
    }
    if boundary.prev_block != period_last.block_hash() {
        return Err(SpvError::BrokenLink { index: 0 });
    }
    let actual = period_last.timestamp.saturating_sub(period_first.timestamp);
    let expected = compute_retarget(period_last.bits, actual, params);
    if boundary.bits != expected {
        return Err(SpvError::RetargetMismatch { index: 0 });
    }
    Ok(())
}

pub fn heavier<'a>(a: &'a VerifiedChain, b: &'a VerifiedChain) -> &'a VerifiedChain {
    if b.work > a.work {
        b
    } else {
        a
    }
}

pub fn pinned_checkpoint(network: crate::params::Network) -> Option<Checkpoint> {
    match network {
        crate::params::Network::Bitcoin => None,
        crate::params::Network::BitcoinCash => None,
    }
}

impl VerifiedChain {
    pub fn anchored_to(&self, checkpoint: &Checkpoint) -> Result<(), SpvError> {
        let header = self
            .header_at(checkpoint.height)
            .ok_or(SpvError::CheckpointNotInChain)?;
        if header.block_hash() != checkpoint.hash {
            return Err(SpvError::CheckpointMismatch);
        }
        if self.work < checkpoint.min_work {
            return Err(SpvError::InsufficientWork);
        }
        Ok(())
    }

    pub fn header_at(&self, height: u32) -> Option<&BlockHeader> {
        if height < self.start_height || height > self.tip_height {
            return None;
        }
        self.headers.get((height - self.start_height) as usize)
    }

    pub fn confirmations(&self, height: u32) -> Option<u32> {
        if height < self.start_height || height > self.tip_height {
            return None;
        }
        Some(self.tip_height - height + 1)
    }

    pub fn verify_deposit(
        &self,
        deposit_height: u32,
        txid: [u8; 32],
        branch: &[MerkleStep],
        required_confirmations: u32,
    ) -> Result<ConfirmedDeposit, SpvError> {
        let header = self
            .header_at(deposit_height)
            .ok_or(SpvError::HeightOutOfRange)?;
        if fold_merkle_branch(txid, branch)? != header.merkle_root {
            return Err(SpvError::MerkleMismatch);
        }
        let confirmations = self.tip_height - deposit_height + 1;
        if confirmations < required_confirmations {
            return Err(SpvError::InsufficientConfirmations {
                have: confirmations,
                need: required_confirmations,
            });
        }
        Ok(ConfirmedDeposit {
            block_hash: header.block_hash(),
            merkle_root: header.merkle_root,
            deposit_height,
            confirmations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{BITCOIN, BITCOIN_CASH};

    fn from_hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn reversed(s: &str) -> [u8; 32] {
        let mut bytes = from_hex(s);
        bytes.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    const B0: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    const B1: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    const B2: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61";
    const B3: &str = "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d";
    const B4: &str = "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9";
    const B5: &str = "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477";
    const B6: &str = "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97";

    const B170: &str = "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70";
    const B171: &str = "01000000eea2d48d2fced4346842835c659e493d323f06d4034469a8905714d100000000f293c86973e758ccd11975fa464d4c3e8500979c95425c7be6f0a65314d2f2d5c9ba6a49ffff001d07a8f226";
    const B172: &str = "01000000e0b4bf8d80026bbec5370a7bb06af54257a9679cef387fab8c53ecc900000000d578b0399b91624a8da53552035fecdd8f4ba2b9c69dfbda68d651fcb9f99c388dbc6a49ffff001d35464c5d";
    const B173: &str = "0100000054686892dd112de389acc225accc0118765f9c51c2ec9306f6abefe3000000005209a3e77e3679703f6b7f039fb9e054d7862e6eaad617e8e3f3d81d297e966015be6a49ffff001d21ac0323";
    const B174: &str = "01000000c585ac476b5878f0f1917826430b3daec278ef28c121c2ec9dd6e9dc000000008195110f0743ab43d4146798c962b8d101e325f4afdf8e936d15c2d51371b9cc7dc06a49ffff001d32915d0f";
    const B175: &str = "01000000c052286e779e7e48397d8c39fee98a3a5718c82dd6bc5b71eebed8a700000000903bb52cc35576a52e9d8f35a901073d33145b6f7be16aab1aa328e8153dfb4874c46a49ffff001d227dd986";
    const B176: &str = "01000000089d2d7196d00f737762fe82cfd86820c6e44bb2a9dd0f5fc1fc4afd000000005c3de10cb7cb6934b0050360980f9a37a95a8bf705edfbcbd3541591ad95c16466c96a49ffff001d09338966";
    const B177: &str = "01000000586ebdf7f1df4885ca322a3021773c6281691f9450e8b8edddf3a91600000000885e36844a21fc6078813daa25b0c331523374924d21fd63b2e939ca3fb2b407edce6a49ffff001d0931f108";
    const B178: &str = "01000000b17df64200cd007eea9b6ac2760f69693f83f19f00352bdd99970c48000000006bf4f1083c14982eee4239a9ac2c94c5672f7da3d763bb88488936a4ac7827672bd16a49ffff001d31f068f5";
    const B179: &str = "010000000d5ba629a32522334a8d40374b82505533f1f6117c8a906cbee06dca000000006bc3cfaf5339c2989f4892ab10bbbd5ed3db490712b5b72dfd29390ca89178c795d46a49ffff001d37f7ca97";
    const B180: &str = "0100000070e12562bd8d2d8b2c1d298fbaa3bc4f005b4c41692850276b5aabc0000000004f1d6988f3aed27c24bcdd92ed9296afb0d58073f77da34caa8cc83718fe8cbd3cda6a49ffff001d13bfb72f";
    const B181: &str = "01000000f2c8a8d2af43a9cd05142654e56f41d159ce0274d9cabe15a20eefb500000000366c2a0915f05db4b450c050ce7165acd55f823fee51430a8c993e0bdbb192ede5dc6a49ffff001d192d3f2f";
    const B182: &str = "01000000e5c6af65c46bd826723a83c1c29d9efa189320458dc5298a0c8655dc0000000030c2a0d34bfb4a10d35e8166e0f5a37bce02fc1b85ff983739a191197f010f2f40df6a49ffff001d2ce7ac9e";
    const B183: &str = "010000005dad27b228dac0272b484c390c32d95aaa38e75ba9f74ffc1178485400000000292571e03a414e493790a4bc212dac24d5d6cd5655cbefb4404dd8513b9825df6ee46a49ffff001d13fdd3c0";
    const B184: &str = "010000008898a2630f7fe0b924cf5b986c8a8da2b2959a2d6faf8b033f516ef400000000bf20f3ca28996db0f2f884ef15a03ff53ba6ad5669ed4e14c861d5dd56a16172e5e76a49ffff001d2e11190a";

    const B30240: &str = "01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355b1512b4bffff001dbfb02519";
    const B32255: &str = "0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b48923ec3a4bffff001dbd5fa412";
    const B32256: &str = "010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f980000000027b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564f8ee3a4b6ad8001dd3a43707";

    const TXID0_170: &str = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082";
    const TXID1_170: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    fn header(hex: &str) -> BlockHeader {
        BlockHeader::parse(&from_hex(hex)).unwrap()
    }

    fn early_chain() -> Vec<BlockHeader> {
        [B0, B1, B2, B3, B4, B5, B6]
            .iter()
            .map(|h| header(h))
            .collect()
    }

    #[test]
    fn a_real_seven_block_bitcoin_chain_verifies_and_accumulates_work() {
        let chain = verify_chain(&early_chain(), 0, &BITCOIN).unwrap();
        assert_eq!(chain.tip_height, 6);
        assert_eq!(chain.work, U256::from_u64(7 * 4_295_032_833));
        assert_eq!(chain.tip_hash, header(B6).block_hash());
    }

    #[test]
    fn a_header_that_fails_its_proof_of_work_is_rejected() {
        let mut headers = early_chain();
        headers[3].nonce = headers[3].nonce.wrapping_add(1);
        assert_eq!(
            verify_chain(&headers, 0, &BITCOIN),
            Err(SpvError::PowNotMet)
        );
    }

    #[test]
    fn a_gap_in_the_chain_breaks_the_prev_link() {
        let headers = vec![header(B0), header(B1), header(B3)];
        assert_eq!(
            verify_chain(&headers, 0, &BITCOIN),
            Err(SpvError::BrokenLink { index: 2 })
        );
    }

    #[test]
    fn a_trivial_difficulty_header_is_rejected_below_the_pow_floor() {
        let mut trivial = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0x11u8; 32],
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        while !trivial.meets_pow() {
            trivial.nonce = trivial.nonce.wrapping_add(1);
        }
        assert_eq!(
            verify_chain(&[trivial], 0, &BITCOIN),
            Err(SpvError::TargetBelowFloor { index: 0 }),
            "a header easier than the network pow limit cannot forge a chain"
        );
    }

    #[test]
    fn a_start_height_near_the_u32_ceiling_errors_instead_of_wrapping() {
        let easy = NetworkParams {
            pow_limit_bits: 0x207f_ffff,
            ..BITCOIN
        };
        let mined = |root: [u8; 32]| {
            let mut h = BlockHeader {
                version: 1,
                prev_block: [0u8; 32],
                merkle_root: root,
                timestamp: 1_700_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            };
            while !h.meets_pow() {
                h.nonce = h.nonce.wrapping_add(1);
            }
            h
        };
        let headers = vec![mined([0x11; 32]), mined([0x22; 32])];
        assert_eq!(
            verify_chain(&headers, u32::MAX, &easy),
            Err(SpvError::HeightOverflow),
            "a proof-supplied start height at the u32 ceiling must error not wrap"
        );
    }

    #[test]
    fn a_chain_that_does_not_descend_from_the_checkpoint_is_rejected() {
        let chain = verify_chain(&early_chain(), 0, &BITCOIN).unwrap();

        let good = Checkpoint {
            height: 0,
            hash: header(B0).block_hash(),
            min_work: U256::ZERO,
        };
        assert!(
            chain.anchored_to(&good).is_ok(),
            "the genuine anchored chain verifies"
        );

        let wrong_hash = Checkpoint {
            height: 0,
            hash: [0x99u8; 32],
            min_work: U256::ZERO,
        };
        assert_eq!(
            chain.anchored_to(&wrong_hash),
            Err(SpvError::CheckpointMismatch)
        );

        let out_of_range = Checkpoint {
            height: 999,
            hash: header(B0).block_hash(),
            min_work: U256::ZERO,
        };
        assert_eq!(
            chain.anchored_to(&out_of_range),
            Err(SpvError::CheckpointNotInChain)
        );

        let too_light = Checkpoint {
            height: 0,
            hash: header(B0).block_hash(),
            min_work: U256::from_u64(u64::MAX),
        };
        assert_eq!(
            chain.anchored_to(&too_light),
            Err(SpvError::InsufficientWork)
        );
    }

    #[test]
    fn the_test_only_accepting_checkpoint_anchors_its_own_chain_with_zero_work() {
        let chain = verify_chain(&early_chain(), 0, &BITCOIN).unwrap();
        let checkpoint = Checkpoint::accepting(&chain);
        assert_eq!(checkpoint.height, chain.start_height);
        assert_eq!(checkpoint.min_work, U256::ZERO);
        assert!(chain.anchored_to(&checkpoint).is_ok());
    }

    #[test]
    fn a_lighter_real_chain_loses_to_the_heavier_real_chain() {
        let heavy = verify_chain(&early_chain(), 0, &BITCOIN).unwrap();
        let light = verify_chain(&[header(B0), header(B1)], 0, &BITCOIN).unwrap();
        assert!(heavy.work > light.work);
        assert_eq!(heavier(&heavy, &light).tip_hash, heavy.tip_hash);
        assert_eq!(heavier(&light, &heavy).tip_hash, heavy.tip_hash);
    }

    #[test]
    fn selection_is_by_cumulative_work_not_by_length() {
        let heavy_short = VerifiedChain {
            start_height: 0,
            tip_height: 0,
            tip_hash: [0x11u8; 32],
            work: U256::from_u64(9_000_000_000),
            headers: vec![header(B0)],
        };
        let light_long = VerifiedChain {
            start_height: 0,
            tip_height: 6,
            tip_hash: [0x22u8; 32],
            work: U256::from_u64(4_000_000_000),
            headers: early_chain(),
        };
        assert!(light_long.headers.len() > heavy_short.headers.len());
        assert_eq!(
            heavier(&heavy_short, &light_long).tip_hash,
            heavy_short.tip_hash
        );
    }

    #[test]
    fn the_real_difficulty_retarget_boundary_verifies() {
        assert!(check_retarget_boundary(
            &header(B30240),
            &header(B32255),
            &header(B32256),
            &BITCOIN
        )
        .is_ok());
    }

    #[test]
    fn a_boundary_whose_target_does_not_match_the_period_is_rejected() {
        let mut first = header(B30240);
        first.timestamp -= 500_000;
        assert_eq!(
            check_retarget_boundary(&first, &header(B32255), &header(B32256), &BITCOIN),
            Err(SpvError::RetargetMismatch { index: 0 })
        );
    }

    #[test]
    fn a_bits_change_off_a_retarget_boundary_is_rejected() {
        assert_eq!(
            bits_expectation(3, 0x1d00ffff, 0x1d00fffe, &BITCOIN, 1),
            Err(SpvError::RetargetOnANonBoundary { index: 1 })
        );
    }

    #[test]
    fn bits_may_change_on_a_retarget_boundary() {
        assert!(bits_expectation(2016, 0x1d00ffff, 0x1d00d86a, &BITCOIN, 1).is_ok());
    }

    #[test]
    fn bits_hold_constant_within_a_retarget_period() {
        assert!(bits_expectation(5, 0x1d00ffff, 0x1d00ffff, &BITCOIN, 1).is_ok());
    }

    #[test]
    fn a_boundary_that_eases_difficulty_beyond_the_four_times_band_is_rejected() {
        assert_eq!(
            bits_expectation(2016, 0x1b0404cb, 0x1d00ffff, &BITCOIN, 3),
            Err(SpvError::RetargetMismatch { index: 3 })
        );
    }

    #[test]
    fn a_boundary_within_the_four_times_band_is_accepted() {
        assert!(bits_expectation(2016, 0x1d00d86a, 0x1d00ffff, &BITCOIN, 0).is_ok());
    }

    #[test]
    fn a_deposit_with_a_real_merkle_branch_verifies_at_the_confirmation_depth() {
        let headers: Vec<BlockHeader> = [B170, B171, B172, B173, B174, B175]
            .iter()
            .map(|h| header(h))
            .collect();
        let chain = verify_chain(&headers, 170, &BITCOIN).unwrap();
        assert_eq!(chain.confirmations(170), Some(6));

        let txid0 = reversed(TXID0_170);
        let branch = [MerkleStep {
            hash: reversed(TXID1_170),
            sibling_on_left: false,
        }];
        let deposit = chain
            .verify_deposit(170, txid0, &branch, BITCOIN.confirmation_depth)
            .unwrap();
        assert_eq!(deposit.confirmations, 6);
        assert_eq!(deposit.block_hash, header(B170).block_hash());
    }

    #[test]
    fn a_deposit_below_the_confirmation_depth_is_rejected() {
        let headers: Vec<BlockHeader> = [B170, B171, B172].iter().map(|h| header(h)).collect();
        let chain = verify_chain(&headers, 170, &BITCOIN).unwrap();
        let txid0 = reversed(TXID0_170);
        let branch = [MerkleStep {
            hash: reversed(TXID1_170),
            sibling_on_left: false,
        }];
        assert_eq!(
            chain.verify_deposit(170, txid0, &branch, BITCOIN.confirmation_depth),
            Err(SpvError::InsufficientConfirmations { have: 3, need: 6 })
        );
    }

    #[test]
    fn a_merkle_branch_to_a_different_root_fails() {
        let headers: Vec<BlockHeader> = [B170, B171, B172, B173, B174, B175]
            .iter()
            .map(|h| header(h))
            .collect();
        let chain = verify_chain(&headers, 170, &BITCOIN).unwrap();
        let txid0 = reversed(TXID0_170);
        let wrong_sibling = [MerkleStep {
            hash: [0x99u8; 32],
            sibling_on_left: false,
        }];
        assert_eq!(
            chain.verify_deposit(170, txid0, &wrong_sibling, BITCOIN.confirmation_depth),
            Err(SpvError::MerkleMismatch)
        );
    }

    fn real_early_chain_through_184() -> Vec<BlockHeader> {
        [
            B170, B171, B172, B173, B174, B175, B176, B177, B178, B179, B180, B181, B182, B183,
            B184,
        ]
        .iter()
        .map(|h| header(h))
        .collect()
    }

    #[test]
    fn a_real_bitcoin_cash_deposit_verifies_at_its_confirmation_depth() {
        let chain = verify_chain(&real_early_chain_through_184(), 170, &BITCOIN_CASH).unwrap();
        assert_eq!(
            chain.confirmations(170),
            Some(BITCOIN_CASH.confirmation_depth)
        );

        let txid0 = reversed(TXID0_170);
        let branch = [MerkleStep {
            hash: reversed(TXID1_170),
            sibling_on_left: false,
        }];
        let deposit = chain
            .verify_deposit(170, txid0, &branch, BITCOIN_CASH.confirmation_depth)
            .unwrap();
        assert_eq!(deposit.confirmations, BITCOIN_CASH.confirmation_depth);
        assert_eq!(deposit.block_hash, header(B170).block_hash());
    }

    #[test]
    fn a_bitcoin_cash_deposit_short_of_its_confirmation_depth_is_rejected() {
        let mut headers = real_early_chain_through_184();
        headers.pop();
        let chain = verify_chain(&headers, 170, &BITCOIN_CASH).unwrap();
        let txid0 = reversed(TXID0_170);
        let branch = [MerkleStep {
            hash: reversed(TXID1_170),
            sibling_on_left: false,
        }];
        assert_eq!(
            chain.verify_deposit(170, txid0, &branch, BITCOIN_CASH.confirmation_depth),
            Err(SpvError::InsufficientConfirmations {
                have: BITCOIN_CASH.confirmation_depth - 1,
                need: BITCOIN_CASH.confirmation_depth
            })
        );
    }
}
