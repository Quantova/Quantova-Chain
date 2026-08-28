#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


pub mod corridor;
pub mod finality;
pub mod network;

pub use corridor::{corridor, corridor_for_id, upgrade_tier, Corridor, RegistryError};
pub use finality::{FinalityConfig, FinalityKind};
pub use network::{all_network_ids, ChainFamily, NetworkId, UnknownNetworkId, NETWORK_COUNT};

pub const FOUNDER_CONFIRMATION_PENDING: &str =
    "the network enumeration, its tiers, and its finality parameters await founder confirmation against the old v2 Network enum";

pub const TARGET_ASSETS: usize = 70;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asset {
    pub origin_chain: u32,
    pub symbol: &'static str,
    pub tag: &'static str,
}

pub fn seed_assets() -> Vec<Asset> {
    vec![
        Asset { origin_chain: 0, symbol: "BTC", tag: "qBTC.btc" },
        Asset { origin_chain: 2, symbol: "ETH", tag: "qETH.eth" },
        Asset { origin_chain: 2, symbol: "USDT", tag: "qUSDT.eth" },
        Asset { origin_chain: 2, symbol: "USDC", tag: "qUSDC.eth" },
        Asset { origin_chain: 2, symbol: "LINK", tag: "qLINK.eth" },
        Asset { origin_chain: 2, symbol: "SHIB", tag: "qSHIB.eth" },
        Asset { origin_chain: 2, symbol: "UNI", tag: "qUNI.eth" },
        Asset { origin_chain: 3, symbol: "USDT", tag: "qUSDT.bsc" },
        Asset { origin_chain: 3, symbol: "BNB", tag: "qBNB.bsc" },
        Asset { origin_chain: 3, symbol: "LINK", tag: "qLINK.bsc" },
        Asset { origin_chain: 3, symbol: "FDUSD", tag: "qFDUSD.bsc" },
        Asset { origin_chain: 3, symbol: "TUSD", tag: "qTUSD.bsc" },
        Asset { origin_chain: 22, symbol: "USDT", tag: "qUSDT.sol" },
        Asset { origin_chain: 22, symbol: "SOL", tag: "qSOL.sol" },
        Asset { origin_chain: 22, symbol: "USDC", tag: "qUSDC.sol" },
        Asset { origin_chain: 22, symbol: "RENDER", tag: "qRENDER.sol" },
        Asset { origin_chain: 22, symbol: "BONK", tag: "qBONK.sol" },
        Asset { origin_chain: 22, symbol: "WIF", tag: "qWIF.sol" },
        Asset { origin_chain: 23, symbol: "USDT", tag: "qUSDT.tron" },
        Asset { origin_chain: 23, symbol: "TRX", tag: "qTRX.tron" },
        Asset { origin_chain: 23, symbol: "TUSD", tag: "qTUSD.tron" },
        Asset { origin_chain: 23, symbol: "XAUT", tag: "qXAUT.tron" },
        Asset { origin_chain: 4, symbol: "USDT", tag: "qUSDT.poly" },
        Asset { origin_chain: 4, symbol: "USDC", tag: "qUSDC.poly" },
        Asset { origin_chain: 4, symbol: "LINK", tag: "qLINK.poly" },
        Asset { origin_chain: 4, symbol: "UNI", tag: "qUNI.poly" },
        Asset { origin_chain: 4, symbol: "AAVE", tag: "qAAVE.poly" },
        Asset { origin_chain: 4, symbol: "POL", tag: "qPOL.poly" },
        Asset { origin_chain: 6, symbol: "ETH", tag: "qETH.arb" },
        Asset { origin_chain: 6, symbol: "USDT", tag: "qUSDT.arb" },
        Asset { origin_chain: 6, symbol: "USDC", tag: "qUSDC.arb" },
        Asset { origin_chain: 6, symbol: "LINK", tag: "qLINK.arb" },
        Asset { origin_chain: 6, symbol: "UNI", tag: "qUNI.arb" },
        Asset { origin_chain: 6, symbol: "AAVE", tag: "qAAVE.arb" },
        Asset { origin_chain: 8, symbol: "ETH", tag: "qETH.base" },
        Asset { origin_chain: 8, symbol: "USDC", tag: "qUSDC.base" },
        Asset { origin_chain: 8, symbol: "LINK", tag: "qLINK.base" },
        Asset { origin_chain: 8, symbol: "AERO", tag: "qAERO.base" },
        Asset { origin_chain: 8, symbol: "VIRTUAL", tag: "qVIRTUAL.base" },
        Asset { origin_chain: 8, symbol: "wstETH", tag: "qwstETH.base" },
        Asset { origin_chain: 16, symbol: "ATOM", tag: "qATOM.atom" },
        Asset { origin_chain: 34, symbol: "XMR", tag: "qXMR.xmr" },
        Asset { origin_chain: 35, symbol: "LTC", tag: "qLTC.ltc" },
        Asset { origin_chain: 36, symbol: "DOGE", tag: "qDOGE.doge" },
        Asset { origin_chain: 37, symbol: "ZEC", tag: "qZEC.zec" },
        Asset { origin_chain: 38, symbol: "USDC", tag: "qUSDC.cctp" },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_founder_confirmation_flag_is_set() {
        assert!(!FOUNDER_CONFIRMATION_PENDING.is_empty());
    }

    #[test]
    fn assets_are_origin_tagged_and_unique() {
        let assets = seed_assets();
        let tags: BTreeSet<&str> = assets.iter().map(|a| a.tag).collect();
        assert_eq!(tags.len(), assets.len());
    }

    #[test]
    fn same_symbol_on_two_chains_is_two_distinct_assets() {
        let assets = seed_assets();
        let usdt: Vec<&Asset> = assets.iter().filter(|a| a.symbol == "USDT").collect();
        assert!(usdt.len() >= 5);
        let tags: BTreeSet<&str> = usdt.iter().map(|a| a.tag).collect();
        assert_eq!(tags.len(), usdt.len());
    }

    #[test]
    fn every_asset_origin_resolves_a_corridor() {
        for a in seed_assets() {
            assert!(
                corridor_for_id(a.origin_chain).is_ok(),
                "asset {} has no corridor",
                a.tag
            );
        }
    }

    #[test]
    fn seed_assets_stay_within_the_target_envelope() {
        assert!(seed_assets().len() <= TARGET_ASSETS);
    }
}
