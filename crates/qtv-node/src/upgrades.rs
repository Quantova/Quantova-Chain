// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upgrades {
    pub gas_metered_from_height: u64,
    pub bound_draw_from_epoch: u64,
    pub hardened_from_height: u64,
}

pub const FROM_GENESIS: Upgrades = Upgrades {
    gas_metered_from_height: 0,
    bound_draw_from_epoch: 0,
    hardened_from_height: 0,
};

pub const TESTNET: Upgrades = Upgrades {
    gas_metered_from_height: 0,
    bound_draw_from_epoch: 0,
    hardened_from_height: 0,
};

pub const PROTOCOL_VERSION: u32 = 2;

fn table_bytes(table: &Upgrades, out: &mut Vec<u8>) {
    out.extend_from_slice(&table.gas_metered_from_height.to_le_bytes());
    out.extend_from_slice(&table.bound_draw_from_epoch.to_le_bytes());
    out.extend_from_slice(&table.hardened_from_height.to_le_bytes());
}

pub fn protocol_digest() -> [u8; 32] {
    let mut input = b"qtv/protocol".to_vec();
    input.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    table_bytes(&FROM_GENESIS, &mut input);
    table_bytes(&TESTNET, &mut input);
    qtv_crypto::sha3::sha3_256(&input)
}

pub fn for_chain(chain_id: u64) -> Upgrades {
    if chain_id == qtv_tx::TESTNET_CHAIN_ID {
        TESTNET
    } else {
        FROM_GENESIS
    }
}

impl Upgrades {
    pub fn gas_metered(&self, height: u64) -> bool {
        height >= self.gas_metered_from_height
    }

    pub fn bound_draw(&self, epoch: u64) -> bool {
        epoch >= self.bound_draw_from_epoch
    }

    pub fn hardened(&self, height: u64) -> bool {
        height >= self.hardened_from_height
    }

    pub fn full_committee(&self, epoch: u64, heights_per_epoch: u64) -> bool {
        epoch.saturating_mul(heights_per_epoch) >= self.hardened_from_height
    }
}
