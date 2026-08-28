// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityKind {
    Deterministic,
    Probabilistic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityConfig {
    pub confirmation_depth: u32,
    pub kind: FinalityKind,
    pub reorg_depth: u32,
}

impl FinalityConfig {
    pub fn deterministic(confirmation_depth: u32) -> FinalityConfig {
        FinalityConfig {
            confirmation_depth,
            kind: FinalityKind::Deterministic,
            reorg_depth: 0,
        }
    }

    pub fn probabilistic(confirmation_depth: u32, reorg_depth: u32) -> FinalityConfig {
        FinalityConfig {
            confirmation_depth,
            kind: FinalityKind::Probabilistic,
            reorg_depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_finality_carries_no_reorg_window() {
        let f = FinalityConfig::deterministic(64);
        assert_eq!(f.confirmation_depth, 64);
        assert_eq!(f.kind, FinalityKind::Deterministic);
        assert_eq!(f.reorg_depth, 0);
    }

    #[test]
    fn probabilistic_finality_carries_its_own_reorg_window() {
        let f = FinalityConfig::probabilistic(6, 6);
        assert_eq!(f.confirmation_depth, 6);
        assert_eq!(f.kind, FinalityKind::Probabilistic);
        assert_eq!(f.reorg_depth, 6);
    }

    #[test]
    fn deterministic_and_probabilistic_are_distinct_kinds() {
        assert_ne!(FinalityKind::Deterministic, FinalityKind::Probabilistic);
    }
}
