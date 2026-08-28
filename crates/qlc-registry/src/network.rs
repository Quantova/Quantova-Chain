// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NetworkId {
    Bitcoin = 0,
    BitcoinCash = 1,
    Ethereum = 2,
    BnbChain = 3,
    Polygon = 4,
    Avalanche = 5,
    Arbitrum = 6,
    Optimism = 7,
    Base = 8,
    Fantom = 9,
    Gnosis = 10,
    Linea = 11,
    Scroll = 12,
    ZkSyncEra = 13,
    Mantle = 14,
    Celo = 15,
    CosmosHub = 16,
    Osmosis = 17,
    Celestia = 18,
    Injective = 19,
    Sei = 20,
    Kava = 21,
    Solana = 22,
    Tron = 23,
    XrpLedger = 24,
    Cardano = 25,
    Near = 26,
    Sui = 27,
    Aptos = 28,
    Hedera = 29,
    Algorand = 30,
    Ton = 31,
    Stellar = 32,
    RobinhoodChain = 33,
    Monero = 34,
    Litecoin = 35,
    Dogecoin = 36,
    Zcash = 37,
    Cctp = 38,
}

pub const NETWORK_COUNT: u32 = 39;

/// The consensus/proof family a network belongs to. The airlock requires a proof of a given kind to be
/// presented under a corridor of the matching family, so an EVM light-client proof cannot cross under a
/// Cosmos corridor that merely shares the same verification tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFamily {
    Bitcoin,
    Evm,
    Cosmos,
    Other,
}

impl NetworkId {
    pub fn family(self) -> ChainFamily {
        use NetworkId::*;
        match self {
            Bitcoin | BitcoinCash | Litecoin | Dogecoin | Zcash | Monero => ChainFamily::Bitcoin,
            Ethereum | BnbChain | Polygon | Avalanche | Arbitrum | Optimism | Base | Fantom
            | Gnosis | Linea | Scroll | ZkSyncEra | Mantle | Celo | RobinhoodChain => ChainFamily::Evm,
            CosmosHub | Osmosis | Celestia | Injective | Sei | Kava => ChainFamily::Cosmos,
            Solana | Tron | XrpLedger | Cardano | Near | Sui | Aptos | Hedera | Algorand | Ton
            | Stellar | Cctp => ChainFamily::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownNetworkId(pub u32);

impl TryFrom<u32> for NetworkId {
    type Error = UnknownNetworkId;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        match raw {
            0 => Ok(NetworkId::Bitcoin),
            1 => Ok(NetworkId::BitcoinCash),
            2 => Ok(NetworkId::Ethereum),
            3 => Ok(NetworkId::BnbChain),
            4 => Ok(NetworkId::Polygon),
            5 => Ok(NetworkId::Avalanche),
            6 => Ok(NetworkId::Arbitrum),
            7 => Ok(NetworkId::Optimism),
            8 => Ok(NetworkId::Base),
            9 => Ok(NetworkId::Fantom),
            10 => Ok(NetworkId::Gnosis),
            11 => Ok(NetworkId::Linea),
            12 => Ok(NetworkId::Scroll),
            13 => Ok(NetworkId::ZkSyncEra),
            14 => Ok(NetworkId::Mantle),
            15 => Ok(NetworkId::Celo),
            16 => Ok(NetworkId::CosmosHub),
            17 => Ok(NetworkId::Osmosis),
            18 => Ok(NetworkId::Celestia),
            19 => Ok(NetworkId::Injective),
            20 => Ok(NetworkId::Sei),
            21 => Ok(NetworkId::Kava),
            22 => Ok(NetworkId::Solana),
            23 => Ok(NetworkId::Tron),
            24 => Ok(NetworkId::XrpLedger),
            25 => Ok(NetworkId::Cardano),
            26 => Ok(NetworkId::Near),
            27 => Ok(NetworkId::Sui),
            28 => Ok(NetworkId::Aptos),
            29 => Ok(NetworkId::Hedera),
            30 => Ok(NetworkId::Algorand),
            31 => Ok(NetworkId::Ton),
            32 => Ok(NetworkId::Stellar),
            33 => Ok(NetworkId::RobinhoodChain),
            34 => Ok(NetworkId::Monero),
            35 => Ok(NetworkId::Litecoin),
            36 => Ok(NetworkId::Dogecoin),
            37 => Ok(NetworkId::Zcash),
            38 => Ok(NetworkId::Cctp),
            other => Err(UnknownNetworkId(other)),
        }
    }
}

impl From<NetworkId> for u32 {
    fn from(id: NetworkId) -> u32 {
        id as u32
    }
}

pub fn all_network_ids() -> [NetworkId; NETWORK_COUNT as usize] {
    [
        NetworkId::Bitcoin,
        NetworkId::BitcoinCash,
        NetworkId::Ethereum,
        NetworkId::BnbChain,
        NetworkId::Polygon,
        NetworkId::Avalanche,
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
        NetworkId::RobinhoodChain,
        NetworkId::Monero,
        NetworkId::Litecoin,
        NetworkId::Dogecoin,
        NetworkId::Zcash,
        NetworkId::Cctp,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_id_from_zero_to_thirty_eight_decodes() {
        for raw in 0..NETWORK_COUNT {
            assert!(
                NetworkId::try_from(raw).is_ok(),
                "id {} did not decode",
                raw
            );
        }
    }

    #[test]
    fn the_full_id_range_is_contiguous_and_unique() {
        let ids: BTreeSet<u32> = all_network_ids().iter().map(|id| u32::from(*id)).collect();
        let expected: BTreeSet<u32> = (0..NETWORK_COUNT).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn an_id_past_the_range_is_rejected() {
        assert_eq!(
            NetworkId::try_from(NETWORK_COUNT),
            Err(UnknownNetworkId(NETWORK_COUNT))
        );
        assert_eq!(
            NetworkId::try_from(u32::MAX),
            Err(UnknownNetworkId(u32::MAX))
        );
    }
}
