// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainConfig {
    pub chain_id: &'static str,
    pub corridor_id: u32,
    pub confirmation_depth: u32,
    pub overlap_numerator: u64,
    pub overlap_denominator: u64,
    pub trusting_period_secs: u64,
    pub max_clock_drift_secs: u64,
    pub bridge_store_prefix: &'static [u8],
    pub bridge_store_name: &'static [u8],
}

pub const BRIDGE_STORE_PREFIX: &[u8] = b"bridge/deposits/";

pub const BRIDGE_STORE_NAME: &[u8] = b"bridge";

pub const DEFAULT_TRUSTING_PERIOD_SECS: u64 = 1_209_600;

pub const DEFAULT_MAX_CLOCK_DRIFT_SECS: u64 = 10;

impl ChainConfig {
    pub const fn new(
        chain_id: &'static str,
        corridor_id: u32,
        confirmation_depth: u32,
    ) -> ChainConfig {
        ChainConfig {
            chain_id,
            corridor_id,
            confirmation_depth,
            overlap_numerator: 2,
            overlap_denominator: 3,
            trusting_period_secs: DEFAULT_TRUSTING_PERIOD_SECS,
            max_clock_drift_secs: DEFAULT_MAX_CLOCK_DRIFT_SECS,
            bridge_store_prefix: BRIDGE_STORE_PREFIX,
            bridge_store_name: BRIDGE_STORE_NAME,
        }
    }
}

pub const COSMOS_HUB: ChainConfig = ChainConfig::new("cosmoshub-4", 16, 2);
pub const OSMOSIS: ChainConfig = ChainConfig::new("osmosis-1", 17, 2);
pub const CELESTIA: ChainConfig = ChainConfig::new("celestia", 18, 2);
pub const INJECTIVE: ChainConfig = ChainConfig::new("injective-1", 19, 2);
pub const SEI: ChainConfig = ChainConfig::new("pacific-1", 20, 2);

pub const FAMILY: [ChainConfig; 5] = [COSMOS_HUB, OSMOSIS, CELESTIA, INJECTIVE, SEI];

pub fn by_chain_id(chain_id: &str) -> Option<ChainConfig> {
    FAMILY.into_iter().find(|c| c.chain_id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn cosmos_hub_matches_the_registry_corridor() {
        assert_eq!(COSMOS_HUB.corridor_id, 16);
        assert_eq!(COSMOS_HUB.chain_id, "cosmoshub-4");
    }

    #[test]
    fn the_whole_family_shares_one_engine_through_config() {
        for c in FAMILY {
            assert_eq!(c.overlap_numerator, 2);
            assert_eq!(c.overlap_denominator, 3);
            assert!(c.confirmation_depth > 0);
        }
    }

    #[test]
    fn each_family_member_carries_a_distinct_corridor() {
        let ids: BTreeSet<u32> = FAMILY.iter().map(|c| c.corridor_id).collect();
        assert_eq!(ids.len(), FAMILY.len());
    }

    #[test]
    fn a_chain_id_resolves_to_its_config() {
        assert_eq!(by_chain_id("osmosis-1"), Some(OSMOSIS));
        assert_eq!(by_chain_id("celestia"), Some(CELESTIA));
        assert_eq!(by_chain_id("injective-1"), Some(INJECTIVE));
        assert_eq!(by_chain_id("pacific-1"), Some(SEI));
        assert_eq!(by_chain_id("not-a-cosmos-chain"), None);
    }

    #[test]
    fn any_chain_can_be_configured_without_new_code() {
        let dydx = ChainConfig::new("dydx-mainnet-1", 13, 2);
        assert_eq!(dydx.chain_id, "dydx-mainnet-1");
        assert_eq!(dydx.overlap_denominator, 3);
    }

    #[test]
    fn every_family_member_pins_a_non_empty_bridge_store_prefix() {
        for c in FAMILY {
            assert!(!c.bridge_store_prefix.is_empty());
            assert_eq!(c.bridge_store_prefix, BRIDGE_STORE_PREFIX);
        }
    }
}
