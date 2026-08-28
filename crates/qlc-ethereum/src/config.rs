// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkVersion(pub [u8; 4]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    pub epoch: u64,
    pub version: ForkVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusKind {
    BeaconSyncCommittee,
    SettlesToEthereum,
    ForeignConsensus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmChainConfig {
    pub chain_id: u64,
    pub corridor_id: u32,
    pub name: &'static str,
    pub consensus: ConsensusKind,
    pub genesis_validators_root: [u8; 32],
    pub forks: Vec<Fork>,
    pub sync_committee_size: usize,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub finality_depth: u32,
    pub deposit_contract: [u8; 20],
    pub max_deposit_base_units: u128,
    pub electra_epoch: Option<u64>,
}

impl EvmChainConfig {
    pub fn epoch_at_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    pub fn is_electra_at_slot(&self, slot: u64) -> bool {
        match self.electra_epoch {
            Some(epoch) => self.epoch_at_slot(slot) >= epoch,
            None => false,
        }
    }

    pub fn sync_committee_period(&self, slot: u64) -> u64 {
        let period_slots = self.slots_per_epoch * self.epochs_per_sync_committee_period;
        slot / period_slots
    }

    pub fn fork_version_at_epoch(&self, epoch: u64) -> ForkVersion {
        let mut chosen = self.forks[0].version;
        for fork in &self.forks {
            if fork.epoch <= epoch {
                chosen = fork.version;
            }
        }
        chosen
    }

    pub fn fork_version_at_slot(&self, slot: u64) -> ForkVersion {
        self.fork_version_at_epoch(self.epoch_at_slot(slot))
    }

    pub fn supermajority_threshold(&self) -> usize {
        (self.sync_committee_size * 2) / 3 + 1
    }

    pub fn verifies_beacon_sync_committee(&self) -> bool {
        matches!(
            self.consensus,
            ConsensusKind::BeaconSyncCommittee | ConsensusKind::SettlesToEthereum
        )
    }
}

pub const MAINNET_ELECTRA_EPOCH: u64 = 364_032;

fn beacon_forks() -> Vec<Fork> {
    vec![
        Fork {
            epoch: 0,
            version: ForkVersion([0x00, 0x00, 0x00, 0x00]),
        },
        Fork {
            epoch: 74240,
            version: ForkVersion([0x01, 0x00, 0x00, 0x00]),
        },
        Fork {
            epoch: 144896,
            version: ForkVersion([0x02, 0x00, 0x00, 0x00]),
        },
        Fork {
            epoch: 194048,
            version: ForkVersion([0x03, 0x00, 0x00, 0x00]),
        },
        Fork {
            epoch: 269568,
            version: ForkVersion([0x04, 0x00, 0x00, 0x00]),
        },
        Fork {
            epoch: MAINNET_ELECTRA_EPOCH,
            version: ForkVersion([0x05, 0x00, 0x00, 0x00]),
        },
    ]
}

fn no_forks() -> Vec<Fork> {
    vec![Fork {
        epoch: 0,
        version: ForkVersion([0x00, 0x00, 0x00, 0x00]),
    }]
}

pub fn ethereum() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 1,
        corridor_id: 2,
        name: "Ethereum",
        consensus: ConsensusKind::BeaconSyncCommittee,
        genesis_validators_root: [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ],
        forks: beacon_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 64,
        deposit_contract: [0x11; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: Some(MAINNET_ELECTRA_EPOCH),
    }
}

pub fn bnb_chain() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 56,
        corridor_id: 3,
        name: "BNB Smart Chain",
        consensus: ConsensusKind::ForeignConsensus,
        genesis_validators_root: [0u8; 32],
        forks: no_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 15,
        deposit_contract: [0x22; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: None,
    }
}

pub fn polygon() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 137,
        corridor_id: 4,
        name: "Polygon",
        consensus: ConsensusKind::ForeignConsensus,
        genesis_validators_root: [0u8; 32],
        forks: no_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 128,
        deposit_contract: [0x33; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: None,
    }
}

pub fn avalanche() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 43114,
        corridor_id: 5,
        name: "Avalanche",
        consensus: ConsensusKind::ForeignConsensus,
        genesis_validators_root: [0u8; 32],
        forks: no_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 1,
        deposit_contract: [0x44; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: None,
    }
}

pub fn arbitrum() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 42161,
        corridor_id: 6,
        name: "Arbitrum",
        consensus: ConsensusKind::SettlesToEthereum,
        genesis_validators_root: ethereum().genesis_validators_root,
        forks: beacon_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 64,
        deposit_contract: [0x55; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: Some(MAINNET_ELECTRA_EPOCH),
    }
}

pub fn optimism() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 10,
        corridor_id: 7,
        name: "Optimism",
        consensus: ConsensusKind::SettlesToEthereum,
        genesis_validators_root: ethereum().genesis_validators_root,
        forks: beacon_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 64,
        deposit_contract: [0x66; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: Some(MAINNET_ELECTRA_EPOCH),
    }
}

pub fn base() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 8453,
        corridor_id: 8,
        name: "Base",
        consensus: ConsensusKind::SettlesToEthereum,
        genesis_validators_root: ethereum().genesis_validators_root,
        forks: beacon_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 64,
        deposit_contract: [0x77; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: Some(MAINNET_ELECTRA_EPOCH),
    }
}

pub fn robinhood_chain() -> EvmChainConfig {
    EvmChainConfig {
        chain_id: 0,
        corridor_id: 33,
        name: "Robinhood Chain",
        consensus: ConsensusKind::SettlesToEthereum,
        genesis_validators_root: ethereum().genesis_validators_root,
        forks: beacon_forks(),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        finality_depth: 64,
        deposit_contract: [0x88; 20],
        max_deposit_base_units: 1_000_000_000_000_000_000_000_000u128,
        electra_epoch: Some(MAINNET_ELECTRA_EPOCH),
    }
}

pub fn all_presets() -> Vec<EvmChainConfig> {
    vec![
        ethereum(),
        bnb_chain(),
        polygon(),
        avalanche(),
        arbitrum(),
        optimism(),
        base(),
        robinhood_chain(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_period_advances_every_two_hundred_fifty_six_epochs() {
        let eth = ethereum();
        let period_slots = eth.slots_per_epoch * eth.epochs_per_sync_committee_period;
        assert_eq!(eth.sync_committee_period(0), 0);
        assert_eq!(eth.sync_committee_period(period_slots - 1), 0);
        assert_eq!(eth.sync_committee_period(period_slots), 1);
        assert_eq!(eth.sync_committee_period(period_slots * 3 + 5), 3);
    }

    #[test]
    fn the_fork_version_tracks_the_schedule() {
        let eth = ethereum();
        assert_eq!(eth.fork_version_at_epoch(0), ForkVersion([0, 0, 0, 0]));
        assert_eq!(eth.fork_version_at_epoch(74240), ForkVersion([1, 0, 0, 0]));
        assert_eq!(eth.fork_version_at_epoch(200000), ForkVersion([3, 0, 0, 0]));
        assert_eq!(eth.fork_version_at_epoch(300000), ForkVersion([4, 0, 0, 0]));
        assert_eq!(eth.fork_version_at_epoch(999999), ForkVersion([5, 0, 0, 0]));
    }

    #[test]
    fn a_post_electra_slot_resolves_to_the_electra_fork_version() {
        let eth = ethereum();
        assert_eq!(
            eth.fork_version_at_epoch(MAINNET_ELECTRA_EPOCH - 1),
            ForkVersion([4, 0, 0, 0])
        );
        assert_eq!(
            eth.fork_version_at_epoch(MAINNET_ELECTRA_EPOCH),
            ForkVersion([5, 0, 0, 0])
        );
        let post_electra_slot = MAINNET_ELECTRA_EPOCH * eth.slots_per_epoch + 100;
        assert_eq!(
            eth.fork_version_at_slot(post_electra_slot),
            ForkVersion([5, 0, 0, 0])
        );
    }

    #[test]
    fn a_supermajority_is_more_than_two_thirds() {
        let eth = ethereum();
        assert_eq!(eth.supermajority_threshold(), 342);
    }

    #[test]
    fn one_engine_serves_every_preset_chain() {
        let presets = all_presets();
        assert_eq!(presets.len(), 8);
        for c in &presets {
            assert!(c.sync_committee_size > 0);
            assert!(c.slots_per_epoch > 0);
            assert!(c.max_deposit_base_units > 0);
        }
    }

    #[test]
    fn every_preset_has_a_distinct_chain_id_and_corridor() {
        let presets = all_presets();
        for i in 0..presets.len() {
            for j in (i + 1)..presets.len() {
                assert_ne!(presets[i].chain_id, presets[j].chain_id);
                assert_ne!(presets[i].corridor_id, presets[j].corridor_id);
            }
        }
    }

    #[test]
    fn only_ethereum_and_its_settlements_carry_the_genesis_validators_root() {
        assert_ne!(ethereum().genesis_validators_root, [0u8; 32]);
        assert_eq!(
            base().genesis_validators_root,
            ethereum().genesis_validators_root
        );
        assert_eq!(bnb_chain().genesis_validators_root, [0u8; 32]);
    }

    #[test]
    fn the_consensus_kind_selects_the_sync_committee_path() {
        assert!(ethereum().verifies_beacon_sync_committee());
        assert!(arbitrum().verifies_beacon_sync_committee());
        assert!(optimism().verifies_beacon_sync_committee());
        assert!(base().verifies_beacon_sync_committee());
        assert!(robinhood_chain().verifies_beacon_sync_committee());
        assert!(!bnb_chain().verifies_beacon_sync_committee());
        assert!(!polygon().verifies_beacon_sync_committee());
        assert!(!avalanche().verifies_beacon_sync_committee());
    }

    #[test]
    fn the_electra_boundary_comes_from_the_pinned_config_and_is_fail_closed_when_unset() {
        let eth = ethereum();
        let boundary = eth.electra_epoch.expect("a beacon chain pins its electra epoch");
        let slots_per_epoch = eth.slots_per_epoch;
        assert!(!eth.is_electra_at_slot(boundary * slots_per_epoch - 1));
        assert!(eth.is_electra_at_slot(boundary * slots_per_epoch));
        assert!(!bnb_chain().is_electra_at_slot(u64::MAX));
    }

    #[test]
    fn the_orbit_rollup_anchors_to_the_ethereum_beacon_parameters() {
        let rh = robinhood_chain();
        assert_eq!(rh.consensus, ConsensusKind::SettlesToEthereum);
        assert_eq!(
            rh.genesis_validators_root,
            ethereum().genesis_validators_root
        );
        assert_eq!(rh.forks, ethereum().forks);
        assert_eq!(rh.finality_depth, arbitrum().finality_depth);
    }
}
