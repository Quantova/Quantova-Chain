#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::{chain_id_from_name, sign_call, SignedTransfer, Submit, MAINNET_CHAIN_ID};
use qcore::{Client, Network};
use qtv_node::bridge_btc::BitcoinMintProof;
use qtv_node::bridge_cosmos::CosmosMintProof;
use qtv_node::bridge_eth::EthMintProof;
use qtv_node::ledger::{
    bridge_btc_mint_address, bridge_cosmos_mint_address, bridge_eth_mint_address,
};

pub use qcore::SEED_LEN;

pub const RELAY_METER: u64 = 1_210;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corridor {
    Bitcoin,
    Ethereum,
    Cosmos,
}

impl Corridor {
    pub fn mint_address(self) -> String {
        match self {
            Corridor::Bitcoin => bridge_btc_mint_address(),
            Corridor::Ethereum => bridge_eth_mint_address(),
            Corridor::Cosmos => bridge_cosmos_mint_address(),
        }
    }
}

pub fn bitcoin_proof_bytes(proof: &BitcoinMintProof) -> Vec<u8> {
    proof.encode()
}

pub fn ethereum_proof_bytes(proof: &EthMintProof) -> Vec<u8> {
    proof.encode()
}

pub fn cosmos_proof_bytes(proof: &CosmosMintProof) -> Vec<u8> {
    proof.encode()
}

#[allow(clippy::too_many_arguments)]
pub fn build_submission(
    corridor: Corridor,
    proof_bytes: Vec<u8>,
    seed: &[u8; SEED_LEN],
    index: u64,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
) -> Result<SignedTransfer, String> {
    sign_call(
        seed,
        index,
        &corridor.mint_address(),
        proof_bytes,
        nonce,
        meter_limit,
        fee,
        chain_id,
        valid_until,
    )
}

pub struct Relay {
    client: Client,
    seed: [u8; SEED_LEN],
    index: u64,
    meter_limit: u64,
    max_fee: u128,
}

impl Relay {
    pub fn new(
        base_url: impl Into<String>,
        chain: impl Into<String>,
        acknowledge_mainnet: bool,
        seed: [u8; SEED_LEN],
        index: u64,
        meter_limit: u64,
        max_fee: u128,
    ) -> Result<Relay, String> {
        let base = base_url.into();
        let chain = chain.into();
        if chain.is_empty() {
            return Err("the relay needs the chain name it signs for".to_string());
        }
        let is_mainnet = chain_id_from_name(&chain) == MAINNET_CHAIN_ID;
        if is_mainnet && !acknowledge_mainnet {
            return Err(format!(
                "refusing to relay for the mainnet chain {chain} without acknowledging mainnet"
            ));
        }
        let mut network = Network::for_url(base.clone());
        network.chain_id = Some(chain);
        network.is_mainnet = is_mainnet;
        Ok(Relay {
            client: Client::with_network(base, network, acknowledge_mainnet),
            seed,
            index,
            meter_limit,
            max_fee,
        })
    }

    pub fn submit(
        &self,
        corridor: Corridor,
        proof_bytes: Vec<u8>,
    ) -> Result<(SignedTransfer, Submit), String> {
        self.client.call(
            &self.seed,
            self.index,
            &corridor.mint_address(),
            proof_bytes,
            self.meter_limit,
            self.max_fee,
        )
    }

    pub fn submit_bitcoin(
        &self,
        proof: &BitcoinMintProof,
    ) -> Result<(SignedTransfer, Submit), String> {
        self.submit(Corridor::Bitcoin, proof.encode())
    }

    pub fn submit_ethereum(
        &self,
        proof: &EthMintProof,
    ) -> Result<(SignedTransfer, Submit), String> {
        self.submit(Corridor::Ethereum, proof.encode())
    }

    pub fn submit_cosmos(
        &self,
        proof: &CosmosMintProof,
    ) -> Result<(SignedTransfer, Submit), String> {
        self.submit(Corridor::Cosmos, proof.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_devnet::wire::wrapper_from_bytes;

    fn seed() -> [u8; SEED_LEN] {
        [0x2a; SEED_LEN]
    }

    fn submission_targets(corridor: Corridor) {
        let signed = build_submission(
            corridor,
            vec![0x01, 0x02, 0x03, 0x04],
            &seed(),
            0,
            7,
            RELAY_METER,
            500,
            42,
            900,
        )
        .expect("a corridor submission signs");
        let wrapper = wrapper_from_bytes(&signed.tx_bytes)
            .expect("the relay submission decodes on the gateway wire");
        assert_eq!(
            wrapper.body().call().target(),
            corridor.mint_address(),
            "the submission targets the corridor mint address"
        );
        assert_eq!(
            wrapper.body().call().args(),
            &[0x01, 0x02, 0x03, 0x04],
            "the submission carries the raw proof bytes untouched"
        );
        assert_eq!(wrapper.body().nonce(), 7);
        assert_eq!(wrapper.body().chain_id(), 42);
        assert_eq!(wrapper.body().valid_until_height(), 900);
    }

    #[test]
    fn a_bitcoin_submission_is_a_well_formed_bridge_mint() {
        submission_targets(Corridor::Bitcoin);
    }

    #[test]
    fn an_ethereum_submission_is_a_well_formed_bridge_mint() {
        submission_targets(Corridor::Ethereum);
    }

    #[test]
    fn a_cosmos_submission_is_a_well_formed_bridge_mint() {
        submission_targets(Corridor::Cosmos);
    }

    #[test]
    fn a_relay_needs_a_chain_and_an_acknowledged_mainnet() {
        assert!(Relay::new("http://127.0.0.1:1", "", false, seed(), 0, RELAY_METER, 1).is_err());
        assert!(Relay::new(
            "http://127.0.0.1:1",
            qcore::MAINNET_CHAIN_NAME,
            false,
            seed(),
            0,
            RELAY_METER,
            1
        )
        .is_err());
        assert!(Relay::new(
            "http://127.0.0.1:1",
            qcore::MAINNET_CHAIN_NAME,
            true,
            seed(),
            0,
            RELAY_METER,
            1
        )
        .is_ok());
        assert!(Relay::new(
            "http://127.0.0.1:1",
            "Q-test-net-3",
            false,
            seed(),
            0,
            RELAY_METER,
            1
        )
        .is_ok());
    }

    #[test]
    fn the_three_corridors_target_three_distinct_mint_addresses() {
        let btc = Corridor::Bitcoin.mint_address();
        let eth = Corridor::Ethereum.mint_address();
        let cosmos = Corridor::Cosmos.mint_address();
        assert_ne!(btc, eth);
        assert_ne!(btc, cosmos);
        assert_ne!(eth, cosmos);
    }
}
