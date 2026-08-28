#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationTier {
    Federated,
    Spv,
    LightClient,
    Native,
}

impl VerificationTier {
    // an explicit trust rank so the one-way ratchet never depends on enum declaration order
    fn rank(self) -> u8 {
        match self {
            VerificationTier::Federated => 0,
            VerificationTier::Spv => 1,
            VerificationTier::LightClient => 2,
            VerificationTier::Native => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustGrade {
    Relayer,
    NearTrustless,
    ProvenLightClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierError {
    Downgrade { from: VerificationTier, to: VerificationTier },
}

pub fn ratchet(current: VerificationTier, proposed: VerificationTier) -> Result<VerificationTier, TierError> {
    if proposed.rank() >= current.rank() {
        Ok(proposed)
    } else {
        Err(TierError::Downgrade {
            from: current,
            to: proposed,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignError {
    NotFinal,
    BadProof,
    Malformed,
    SourceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignEvent {
    pub source_chain: u32,
    pub raw: Vec<u8>,
    pub confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvent {
    pub source_chain: u32,
    pub source_ref: [u8; 32],
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub recipient: [u8; 32],
    pub height: u64,
    pub confirmations: u32,
}

pub trait ForeignVerifier {
    fn source_chain(&self) -> u32;
    fn required_confirmations(&self) -> u32;
    fn verify_finalized(&self, event: &ForeignEvent) -> Result<VerifiedEvent, ForeignError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowState {
    pub trusted_height: u64,
    pub trusted_digest: [u8; 32],
}

impl FollowState {
    pub fn genesis(height: u64, digest: [u8; 32]) -> FollowState {
        FollowState {
            trusted_height: height,
            trusted_digest: digest,
        }
    }

    pub fn advance(
        &mut self,
        next_height: u64,
        next_prev: [u8; 32],
        next_digest: [u8; 32],
    ) -> Result<(), ForeignError> {
        let expected_height = match self.trusted_height.checked_add(1) {
            Some(h) => h,
            None => return Err(ForeignError::Malformed),
        };
        if next_height != expected_height {
            return Err(ForeignError::Malformed);
        }
        if next_prev != self.trusted_digest {
            return Err(ForeignError::BadProof);
        }
        self.trusted_height = next_height;
        self.trusted_digest = next_digest;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tier_rank_pins_the_trust_order_so_a_reorder_cannot_silently_invert_the_ratchet() {
        assert!(VerificationTier::Federated.rank() < VerificationTier::Spv.rank());
        assert!(VerificationTier::Spv.rank() < VerificationTier::LightClient.rank());
        assert!(VerificationTier::LightClient.rank() < VerificationTier::Native.rank());
    }

    #[test]
    fn tier_ratchet_upgrades_but_never_downgrades() {
        assert_eq!(
            ratchet(VerificationTier::Federated, VerificationTier::LightClient),
            Ok(VerificationTier::LightClient)
        );
        assert_eq!(
            ratchet(VerificationTier::LightClient, VerificationTier::Federated),
            Err(TierError::Downgrade {
                from: VerificationTier::LightClient,
                to: VerificationTier::Federated
            })
        );
    }

    #[test]
    fn follow_state_rejects_a_broken_prev_link() {
        let mut s = FollowState::genesis(100, [1u8; 32]);
        assert_eq!(s.advance(101, [9u8; 32], [2u8; 32]), Err(ForeignError::BadProof));
        assert_eq!(s.trusted_height, 100);
    }

    #[test]
    fn follow_state_advances_on_a_good_link() {
        let mut s = FollowState::genesis(100, [1u8; 32]);
        assert!(s.advance(101, [1u8; 32], [2u8; 32]).is_ok());
        assert_eq!(s.trusted_height, 101);
        assert_eq!(s.trusted_digest, [2u8; 32]);
    }

    #[test]
    fn follow_state_at_the_max_height_refuses_without_overflow() {
        let mut s = FollowState::genesis(u64::MAX, [1u8; 32]);
        assert_eq!(s.advance(0, [1u8; 32], [2u8; 32]), Err(ForeignError::Malformed));
        assert_eq!(s.trusted_height, u64::MAX, "a rejected advance leaves the height untouched");
        assert_eq!(s.trusted_digest, [1u8; 32]);
    }
}
