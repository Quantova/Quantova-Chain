// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    BitcoinCash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkParams {
    pub network: Network,
    pub name: &'static str,
    pub magic: [u8; 4],
    pub pow_limit_bits: u32,
    pub target_timespan: u32,
    pub target_spacing: u32,
    pub confirmation_depth: u32,
    pub requires_pinned_checkpoint: bool,
}

impl NetworkParams {
    pub fn retarget_interval(&self) -> u32 {
        self.target_timespan / self.target_spacing
    }
}

pub const BITCOIN: NetworkParams = NetworkParams {
    network: Network::Bitcoin,
    name: "Bitcoin",
    magic: [0xf9, 0xbe, 0xb4, 0xd9],
    pow_limit_bits: 0x1d00ffff,
    target_timespan: 1_209_600,
    target_spacing: 600,
    confirmation_depth: 6,
    requires_pinned_checkpoint: true,
};

pub const BITCOIN_CASH: NetworkParams = NetworkParams {
    network: Network::BitcoinCash,
    name: "Bitcoin Cash",
    magic: [0xe3, 0xe1, 0xf3, 0xe8],
    pow_limit_bits: 0x1d00ffff,
    target_timespan: 1_209_600,
    target_spacing: 600,
    confirmation_depth: 15,
    requires_pinned_checkpoint: true,
};

pub fn network_params(network: Network) -> NetworkParams {
    match network {
        Network::Bitcoin => BITCOIN,
        Network::BitcoinCash => BITCOIN_CASH,
    }
}

pub const BITCOIN_CASH_DAA_NOTE: &str =
    "bitcoin cash here retargets on the same legacy two week interval bitcoin used before november 2020 and does not model the real per block asert difficulty algorithm the live network adopted after that upgrade";

pub const BITCOIN_CHECKPOINT_PENDING: &str =
    "a trustless bitcoin or bitcoin cash corridor anchors every deposit to a pinned recent mainnet block, its height, its block hash, and the cumulative proof of work at that height, so a caller cannot substitute a cheap low difficulty chain of its own, a founder must arm pinned_checkpoint with that real block before the corridor is trusted live and until then a mainnet deposit is refused as not armed rather than trusted";

pub const BITCOIN_CASH_CONFIRMATION_PENDING: &str =
    "the bitcoin cash confirmation depth of fifteen follows the wider industry practice of asking for more confirmations than bitcoin given its far smaller and more volatile hash rate, a founder must confirm the final number before a bitcoin cash corridor is trusted live";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_network_retargets_every_two_thousand_and_sixteen_blocks() {
        assert_eq!(BITCOIN.retarget_interval(), 2016);
        assert_eq!(BITCOIN_CASH.retarget_interval(), 2016);
    }

    #[test]
    fn both_networks_share_the_sha256d_proof_of_work_limit() {
        assert_eq!(BITCOIN.pow_limit_bits, BITCOIN_CASH.pow_limit_bits);
        assert_eq!(BITCOIN.target_timespan, BITCOIN_CASH.target_timespan);
        assert_eq!(BITCOIN.target_spacing, BITCOIN_CASH.target_spacing);
    }

    #[test]
    fn the_two_networks_are_distinct() {
        assert_ne!(BITCOIN.network, BITCOIN_CASH.network);
        assert_ne!(BITCOIN.magic, BITCOIN_CASH.magic);
        assert_ne!(BITCOIN.confirmation_depth, BITCOIN_CASH.confirmation_depth);
    }

    #[test]
    fn network_lookup_returns_the_matching_parameters() {
        assert_eq!(network_params(Network::Bitcoin), BITCOIN);
        assert_eq!(network_params(Network::BitcoinCash), BITCOIN_CASH);
    }

    #[test]
    fn bitcoin_cash_asks_for_more_confirmations_than_bitcoin() {
        assert_eq!(BITCOIN_CASH.confirmation_depth, 15);
        assert!(BITCOIN_CASH.confirmation_depth > BITCOIN.confirmation_depth);
    }

    #[test]
    fn the_bitcoin_cash_daa_note_is_recorded() {
        assert!(!BITCOIN_CASH_DAA_NOTE.is_empty());
    }

    #[test]
    fn the_bitcoin_cash_confirmation_depth_awaits_founder_confirmation() {
        assert!(!BITCOIN_CASH_CONFIRMATION_PENDING.is_empty());
    }
}
