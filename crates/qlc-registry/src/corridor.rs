// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qlc_core::{ratchet, TierError, VerificationTier};

use crate::finality::FinalityConfig;
use crate::network::{NetworkId, UnknownNetworkId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corridor {
    pub id: NetworkId,
    pub name: &'static str,
    pub tier: VerificationTier,
    pub finality: FinalityConfig,
}

pub fn corridor(id: NetworkId) -> Corridor {
    match id {
        NetworkId::Bitcoin => Corridor { id, name: "Bitcoin", tier: VerificationTier::Spv, finality: FinalityConfig::probabilistic(6, 6) },
        NetworkId::BitcoinCash => Corridor { id, name: "Bitcoin Cash", tier: VerificationTier::Spv, finality: FinalityConfig::probabilistic(10, 10) },
        NetworkId::Ethereum => Corridor { id, name: "Ethereum", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::BnbChain => Corridor { id, name: "BNB Chain", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(15, 15) },
        NetworkId::Polygon => Corridor { id, name: "Polygon", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(128, 128) },
        NetworkId::Avalanche => Corridor { id, name: "Avalanche", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Arbitrum => Corridor { id, name: "Arbitrum", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Optimism => Corridor { id, name: "Optimism", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Base => Corridor { id, name: "Base", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Fantom => Corridor { id, name: "Fantom", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Gnosis => Corridor { id, name: "Gnosis", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Linea => Corridor { id, name: "Linea", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Scroll => Corridor { id, name: "Scroll", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::ZkSyncEra => Corridor { id, name: "zkSync Era", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Mantle => Corridor { id, name: "Mantle", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Celo => Corridor { id, name: "Celo", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::CosmosHub => Corridor { id, name: "Cosmos Hub", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Osmosis => Corridor { id, name: "Osmosis", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Celestia => Corridor { id, name: "Celestia", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Injective => Corridor { id, name: "Injective", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Sei => Corridor { id, name: "Sei", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Kava => Corridor { id, name: "Kava", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(1) },
        NetworkId::Solana => Corridor { id, name: "Solana", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(32) },
        NetworkId::Tron => Corridor { id, name: "TRON", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(19) },
        NetworkId::XrpLedger => Corridor { id, name: "XRP Ledger", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Cardano => Corridor { id, name: "Cardano", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(15, 15) },
        NetworkId::Near => Corridor { id, name: "Near", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(2) },
        NetworkId::Sui => Corridor { id, name: "Sui", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Aptos => Corridor { id, name: "Aptos", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Hedera => Corridor { id, name: "Hedera", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Algorand => Corridor { id, name: "Algorand", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Ton => Corridor { id, name: "Ton", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::Stellar => Corridor { id, name: "Stellar", tier: VerificationTier::Federated, finality: FinalityConfig::deterministic(1) },
        NetworkId::RobinhoodChain => Corridor { id, name: "Robinhood Chain", tier: VerificationTier::LightClient, finality: FinalityConfig::deterministic(64) },
        NetworkId::Monero => Corridor { id, name: "Monero", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(10, 10) },
        NetworkId::Litecoin => Corridor { id, name: "Litecoin", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(12, 12) },
        NetworkId::Dogecoin => Corridor { id, name: "Dogecoin", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(30, 30) },
        NetworkId::Zcash => Corridor { id, name: "Zcash", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(24, 24) },
        NetworkId::Cctp => Corridor { id, name: "Circle CCTP", tier: VerificationTier::Federated, finality: FinalityConfig::probabilistic(20, 20) },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    UnknownNetwork(u32),
    TierDowngrade {
        from: VerificationTier,
        to: VerificationTier,
    },
}

pub fn corridor_for_id(raw: u32) -> Result<Corridor, RegistryError> {
    let id = NetworkId::try_from(raw)
        .map_err(|UnknownNetworkId(bad)| RegistryError::UnknownNetwork(bad))?;
    Ok(corridor(id))
}

pub fn upgrade_tier(
    id: NetworkId,
    proposed: VerificationTier,
) -> Result<VerificationTier, RegistryError> {
    let current = corridor(id).tier;
    ratchet(current, proposed)
        .map_err(|TierError::Downgrade { from, to }| RegistryError::TierDowngrade { from, to })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{all_network_ids, NETWORK_COUNT};

    #[test]
    fn every_network_id_resolves_a_tier_and_a_finality_config() {
        for raw in 0..NETWORK_COUNT {
            let c = corridor_for_id(raw).unwrap_or_else(|_| panic!("id {} did not resolve", raw));
            assert!(
                c.finality.confirmation_depth > 0,
                "corridor {} has no finality depth",
                c.name
            );
        }
    }

    #[test]
    fn the_full_set_of_thirty_nine_corridors_is_present() {
        let corridors: Vec<Corridor> = all_network_ids().iter().map(|id| corridor(*id)).collect();
        assert_eq!(corridors.len(), NETWORK_COUNT as usize);
    }

    #[test]
    fn an_unknown_network_id_is_rejected() {
        assert_eq!(
            corridor_for_id(NETWORK_COUNT),
            Err(RegistryError::UnknownNetwork(NETWORK_COUNT))
        );
        assert_eq!(
            corridor_for_id(u32::MAX),
            Err(RegistryError::UnknownNetwork(u32::MAX))
        );
    }

    #[test]
    fn a_tier_upgrade_is_accepted() {
        assert_eq!(
            upgrade_tier(NetworkId::Bitcoin, VerificationTier::LightClient),
            Ok(VerificationTier::LightClient)
        );
    }

    #[test]
    fn a_tier_downgrade_is_rejected() {
        assert_eq!(
            upgrade_tier(NetworkId::Ethereum, VerificationTier::Federated),
            Err(RegistryError::TierDowngrade {
                from: VerificationTier::LightClient,
                to: VerificationTier::Federated,
            })
        );
    }

    #[test]
    fn spv_networks_carry_the_spv_tier() {
        assert_eq!(corridor(NetworkId::Bitcoin).tier, VerificationTier::Spv);
        assert_eq!(corridor(NetworkId::BitcoinCash).tier, VerificationTier::Spv);
    }

    #[test]
    fn federated_networks_carry_the_federated_tier() {
        for id in [
            NetworkId::BnbChain,
            NetworkId::Polygon,
            NetworkId::Avalanche,
            NetworkId::Solana,
            NetworkId::Tron,
            NetworkId::XrpLedger,
            NetworkId::Cardano,
            NetworkId::Near,
            NetworkId::Sui,
            NetworkId::Aptos,
            NetworkId::Hedera,
            NetworkId::Algorand,
            NetworkId::Ton,
            NetworkId::Stellar,
            NetworkId::Monero,
            NetworkId::Litecoin,
            NetworkId::Dogecoin,
            NetworkId::Zcash,
            NetworkId::Cctp,
        ] {
            assert_eq!(corridor(id).tier, VerificationTier::Federated);
        }
    }

    #[test]
    fn light_client_networks_carry_the_light_client_tier() {
        for id in [
            NetworkId::Ethereum,
            NetworkId::Arbitrum,
            NetworkId::Optimism,
            NetworkId::Base,
            NetworkId::Fantom,
            NetworkId::Gnosis,
            NetworkId::Linea,
            NetworkId::Scroll,
            NetworkId::ZkSyncEra,
            NetworkId::Mantle,
            NetworkId::Celo,
            NetworkId::CosmosHub,
            NetworkId::Osmosis,
            NetworkId::Celestia,
            NetworkId::Injective,
            NetworkId::Sei,
            NetworkId::Kava,
            NetworkId::RobinhoodChain,
        ] {
            assert_eq!(corridor(id).tier, VerificationTier::LightClient);
        }
    }

    #[test]
    fn a_chain_that_runs_its_own_consensus_cannot_be_verified_by_the_ethereum_settled_engine() {
        for id in [NetworkId::BnbChain, NetworkId::Polygon, NetworkId::Avalanche] {
            assert_ne!(corridor(id).tier, VerificationTier::LightClient);
            assert_eq!(corridor(id).tier, VerificationTier::Federated);
        }
    }
}
