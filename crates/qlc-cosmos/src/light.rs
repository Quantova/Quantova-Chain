// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::chain::ChainConfig;
use crate::commit::{tally_signed_power, verify_commit, Commit, CommitError, Header};
use crate::proto::Timestamp;
use crate::validator::{overlap_meets, ValidatorSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedState {
    pub height: i64,
    pub time: Timestamp,
    pub header_hash: [u8; 32],
    pub validators: ValidatorSet,
    pub next_validators_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightError {
    ChainMismatch,
    NotProgressing,
    UntrustedValidatorSet,
    InsufficientOverlap { overlap: u128, trusted_total: u128 },
    InsufficientTrustedSignatures { signed: u128, trusted_total: u128 },
    TrustedStateExpired { elapsed_secs: i64, trusting_period_secs: u64 },
    NonMonotonicHeaderTime,
    HeaderTimeInFuture,
    NotAdjacent,
    NextValidatorMismatch,
    Commit(CommitError),
}

fn total_nanos(ts: &Timestamp) -> i128 {
    ts.seconds as i128 * 1_000_000_000 + ts.nanos as i128
}

fn check_time(cfg: &ChainConfig, trusted: &TrustedState, new_header: &Header, now: Timestamp) -> Result<(), LightError> {
    let trusted_ns = total_nanos(&trusted.time);
    let new_ns = total_nanos(&new_header.time);
    let now_ns = total_nanos(&now);
    let trusting_ns = cfg.trusting_period_secs as i128 * 1_000_000_000;
    let drift_ns = cfg.max_clock_drift_secs as i128 * 1_000_000_000;

    if now_ns - trusted_ns >= trusting_ns {
        return Err(LightError::TrustedStateExpired {
            elapsed_secs: now.seconds - trusted.time.seconds,
            trusting_period_secs: cfg.trusting_period_secs,
        });
    }
    if new_ns <= trusted_ns {
        return Err(LightError::NonMonotonicHeaderTime);
    }
    if new_ns > now_ns + drift_ns {
        return Err(LightError::HeaderTimeInFuture);
    }
    Ok(())
}

fn check_header(cfg: &ChainConfig, trusted: &TrustedState, new_header: &Header, new_set: &ValidatorSet, now: Timestamp) -> Result<(), LightError> {
    if new_set.validators.len() > crate::validator::MAX_VALIDATORS {
        return Err(LightError::UntrustedValidatorSet);
    }
    if new_header.chain_id != cfg.chain_id {
        return Err(LightError::ChainMismatch);
    }
    if new_header.height <= trusted.height {
        return Err(LightError::NotProgressing);
    }
    if new_header.validators_hash != new_set.hash().to_vec() {
        return Err(LightError::UntrustedValidatorSet);
    }
    check_time(cfg, trusted, new_header, now)?;
    Ok(())
}

pub fn check_trusting_commit(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    new_header: &Header,
    new_commit: &Commit,
) -> Result<(), LightError> {
    let signed = tally_signed_power(cfg.chain_id, new_header, new_commit, &trusted.validators)
        .map_err(LightError::Commit)?;
    let trusted_total = trusted.validators.total_power();
    if cfg.overlap_numerator > 0
        && signed * (cfg.overlap_denominator as u128) > trusted_total * (cfg.overlap_numerator as u128)
    {
        Ok(())
    } else {
        Err(LightError::InsufficientTrustedSignatures { signed, trusted_total })
    }
}

fn adopt(new_header: &Header, new_set: &ValidatorSet) -> TrustedState {
    TrustedState {
        height: new_header.height,
        time: new_header.time,
        header_hash: new_header.hash(),
        validators: new_set.clone(),
        next_validators_hash: new_header.next_validators_hash.clone(),
    }
}

pub fn verify_transition(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    new_header: &Header,
    new_commit: &Commit,
    new_set: &ValidatorSet,
    now: Timestamp,
) -> Result<TrustedState, LightError> {
    check_header(cfg, trusted, new_header, new_set, now)?;

    if !overlap_meets(&trusted.validators, new_set, cfg.overlap_numerator, cfg.overlap_denominator) {
        return Err(LightError::InsufficientOverlap {
            overlap: crate::validator::overlap_power(&trusted.validators, new_set),
            trusted_total: trusted.validators.total_power(),
        });
    }

    verify_commit(cfg.chain_id, new_header, new_commit, new_set).map_err(LightError::Commit)?;
    check_trusting_commit(cfg, trusted, new_header, new_commit)?;

    Ok(adopt(new_header, new_set))
}

pub fn check_anchor(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    new_header: &Header,
    new_set: &ValidatorSet,
    now: Timestamp,
) -> Result<(), LightError> {
    check_header(cfg, trusted, new_header, new_set, now)?;

    if !overlap_meets(&trusted.validators, new_set, cfg.overlap_numerator, cfg.overlap_denominator) {
        return Err(LightError::InsufficientOverlap {
            overlap: crate::validator::overlap_power(&trusted.validators, new_set),
            trusted_total: trusted.validators.total_power(),
        });
    }

    Ok(())
}

pub fn verify_adjacent(
    cfg: &ChainConfig,
    trusted: &TrustedState,
    new_header: &Header,
    new_commit: &Commit,
    new_set: &ValidatorSet,
    now: Timestamp,
) -> Result<TrustedState, LightError> {
    check_header(cfg, trusted, new_header, new_set, now)?;

    if new_header.height != trusted.height + 1 {
        return Err(LightError::NotAdjacent);
    }
    if new_header.validators_hash != trusted.next_validators_hash {
        return Err(LightError::NextValidatorMismatch);
    }

    verify_commit(cfg.chain_id, new_header, new_commit, new_set).map_err(LightError::Commit)?;

    Ok(adopt(new_header, new_set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::COSMOS_HUB;
    use crate::commit::{BlockIdFlag, CommitSig};
    use crate::ed25519::{public_key_from_seed, sign};
    use crate::proto::{vote_sign_bytes, BlockId, CanonicalVote, Timestamp, PRECOMMIT_TYPE};
    use crate::validator::ValidatorInfo;

    struct Keyed {
        seed: [u8; 32],
        info: ValidatorInfo,
    }

    fn keyed(byte: u8, power: u64) -> Keyed {
        let seed = [byte; 32];
        Keyed {
            seed,
            info: ValidatorInfo {
                pubkey: public_key_from_seed(&seed),
                voting_power: power,
            },
        }
    }

    fn make_set(members: &[&Keyed]) -> ValidatorSet {
        ValidatorSet::new(members.iter().map(|k| k.info).collect())
    }

    fn header_for(height: i64, set: &ValidatorSet, next: &ValidatorSet) -> Header {
        Header {
            version_block: 11,
            version_app: 0,
            chain_id: COSMOS_HUB.chain_id.to_string(),
            height,
            time: Timestamp { seconds: 1_700_000_000 + height, nanos: 7 },
            last_block_id: BlockId { hash: vec![0xaa; 32], part_total: 1, part_hash: vec![0xbb; 32] },
            last_commit_hash: vec![0x01; 32],
            data_hash: vec![0x02; 32],
            validators_hash: set.hash().to_vec(),
            next_validators_hash: next.hash().to_vec(),
            consensus_hash: vec![0x03; 32],
            app_hash: vec![0x04; 32],
            last_results_hash: vec![0x05; 32],
            evidence_hash: vec![0x06; 32],
            proposer_address: set.validators[0].address().to_vec(),
        }
    }

    fn signed_commit(header: &Header, signers: &[&Keyed]) -> Commit {
        let block_id = BlockId { hash: header.hash().to_vec(), part_total: 1, part_hash: vec![0xcc; 32] };
        let mut signatures = Vec::new();
        for k in signers {
            let timestamp = Timestamp { seconds: 1_700_000_500, nanos: k.seed[0] as i32 };
            let vote = CanonicalVote {
                vote_type: PRECOMMIT_TYPE,
                height: header.height,
                round: 0,
                block_id: block_id.clone(),
                timestamp,
                chain_id: COSMOS_HUB.chain_id.to_string(),
            };
            signatures.push(CommitSig {
                flag: BlockIdFlag::Commit,
                validator_address: k.info.address(),
                timestamp,
                signature: sign(&k.seed, &vote_sign_bytes(&vote)).to_vec(),
            });
        }
        Commit { height: header.height, round: 0, block_id, signatures }
    }

    fn trusted_from(height: i64, set: &ValidatorSet, next: &ValidatorSet) -> TrustedState {
        TrustedState {
            height,
            time: Timestamp { seconds: 1_700_000_000 + height, nanos: 7 },
            header_hash: [0u8; 32],
            validators: set.clone(),
            next_validators_hash: next.hash().to_vec(),
        }
    }

    #[test]
    fn a_transition_with_more_than_two_thirds_overlap_verifies() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let header = header_for(150, &new, &new);
        let commit = signed_commit(&header, &[&a, &b, &d]);

        let result = verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, header.time).unwrap();
        assert_eq!(result.height, 150);
        assert_eq!(result.validators, new);
    }

    #[test]
    fn a_zero_overlap_numerator_config_fails_closed() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let header = header_for(150, &new, &new);
        let commit = signed_commit(&header, &[&a, &b, &d]);
        let cfg = ChainConfig { overlap_numerator: 0, ..COSMOS_HUB };

        assert!(
            matches!(
                verify_transition(&cfg, &trusted, &header, &commit, &new, header.time),
                Err(LightError::InsufficientOverlap { .. })
            ),
            "a zero overlap numerator must not fail open at the transition gate"
        );
        assert!(
            matches!(
                check_trusting_commit(&cfg, &trusted, &header, &commit),
                Err(LightError::InsufficientTrustedSignatures { .. })
            ),
            "a zero overlap numerator must not fail open at the trusting-commit gate"
        );
    }

    #[test]
    fn a_transition_with_two_thirds_or_less_overlap_fails() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 30);
        let e = keyed(5, 30);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &d, &e]);
        let trusted = trusted_from(100, &old, &old);
        let header = header_for(150, &new, &new);
        let commit = signed_commit(&header, &[&a, &d, &e]);

        assert_eq!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, header.time),
            Err(LightError::InsufficientOverlap { overlap: 40, trusted_total: 100 })
        );
    }

    #[test]
    fn a_transition_whose_new_commit_is_short_fails_at_the_commit() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let header = header_for(150, &new, &new);
        let commit = signed_commit(&header, &[&a]);

        assert!(matches!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, header.time),
            Err(LightError::Commit(CommitError::NotEnoughVotingPower { .. }))
        ));
    }

    #[test]
    fn a_header_that_does_not_progress_is_refused() {
        let a = keyed(1, 100);
        let old = make_set(&[&a]);
        let trusted = trusted_from(150, &old, &old);
        let header = header_for(150, &old, &old);
        let commit = signed_commit(&header, &[&a]);
        assert_eq!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &old, header.time),
            Err(LightError::NotProgressing)
        );
    }

    #[test]
    fn a_header_from_another_chain_is_refused() {
        let a = keyed(1, 100);
        let old = make_set(&[&a]);
        let trusted = trusted_from(100, &old, &old);
        let mut header = header_for(150, &old, &old);
        header.chain_id = "osmosis-1".to_string();
        let commit = signed_commit(&header, &[&a]);
        assert_eq!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &old, header.time),
            Err(LightError::ChainMismatch)
        );
    }

    #[test]
    fn a_superset_signed_only_by_intruders_does_not_transition() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let trusted_set = make_set(&[&a, &b, &c]);
        let x = keyed(9, 1000);
        let y = keyed(10, 1000);
        let forged = make_set(&[&a, &b, &c, &x, &y]);
        let trusted = trusted_from(100, &trusted_set, &trusted_set);
        let header = header_for(150, &forged, &forged);
        let commit = signed_commit(&header, &[&x, &y]);

        assert_eq!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &forged, header.time),
            Err(LightError::InsufficientTrustedSignatures { signed: 0, trusted_total: 100 })
        );

        let d = keyed(4, 20);
        let new = make_set(&[&a, &b, &d]);
        let header2 = header_for(150, &new, &new);
        let commit2 = signed_commit(&header2, &[&a, &b, &d]);
        let ok = verify_transition(&COSMOS_HUB, &trusted, &header2, &commit2, &new, header2.time).unwrap();
        assert_eq!(ok.height, 150);
    }

    #[test]
    fn an_adjacent_step_follows_the_next_validator_hash() {
        let a = keyed(1, 60);
        let b = keyed(2, 40);
        let set = make_set(&[&a, &b]);
        let trusted = trusted_from(149, &set, &set);
        let header = header_for(150, &set, &set);
        let commit = signed_commit(&header, &[&a, &b]);

        let ok = verify_adjacent(&COSMOS_HUB, &trusted, &header, &commit, &set, header.time).unwrap();
        assert_eq!(ok.height, 150);

        let mut wrong = trusted.clone();
        wrong.next_validators_hash = vec![0x00; 32];
        assert_eq!(
            verify_adjacent(&COSMOS_HUB, &wrong, &header, &commit, &set, header.time),
            Err(LightError::NextValidatorMismatch)
        );
    }

    #[test]
    fn an_in_period_header_still_verifies() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let header = header_for(150, &new, &new);
        let commit = signed_commit(&header, &[&a, &b, &d]);
        let now = Timestamp { seconds: header.time.seconds + 5, nanos: 0 };

        let result = verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, now).unwrap();
        assert_eq!(result.height, 150);
        assert_eq!(result.time, header.time);
    }

    #[test]
    fn an_out_of_trusting_period_trusted_anchor_is_rejected() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let mut header = header_for(150, &new, &new);
        header.time = Timestamp {
            seconds: trusted.time.seconds + COSMOS_HUB.trusting_period_secs as i64 + 100,
            nanos: 0,
        };
        let commit = signed_commit(&header, &[&a, &b, &d]);
        let now = header.time;

        assert!(
            matches!(
                verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, now),
                Err(LightError::TrustedStateExpired { .. })
            ),
            "an anchor older than the trusting period must not advance on overlap alone"
        );
    }

    #[test]
    fn a_non_monotonic_header_time_is_rejected() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let mut header = header_for(150, &new, &new);
        header.time = Timestamp { seconds: trusted.time.seconds - 50, nanos: 0 };
        let commit = signed_commit(&header, &[&a, &b, &d]);
        let now = trusted.time;

        assert_eq!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, now),
            Err(LightError::NonMonotonicHeaderTime)
        );
    }

    #[test]
    fn a_far_future_header_time_is_rejected() {
        let a = keyed(1, 40);
        let b = keyed(2, 40);
        let c = keyed(3, 20);
        let d = keyed(4, 20);
        let old = make_set(&[&a, &b, &c]);
        let new = make_set(&[&a, &b, &d]);
        let trusted = trusted_from(100, &old, &old);
        let now = Timestamp { seconds: trusted.time.seconds + 50, nanos: 0 };
        let mut header = header_for(150, &new, &new);
        header.time = Timestamp {
            seconds: now.seconds + COSMOS_HUB.max_clock_drift_secs as i64 + 3600,
            nanos: 0,
        };
        let commit = signed_commit(&header, &[&a, &b, &d]);

        assert_eq!(
            verify_transition(&COSMOS_HUB, &trusted, &header, &commit, &new, now),
            Err(LightError::HeaderTimeInFuture)
        );
    }
}
