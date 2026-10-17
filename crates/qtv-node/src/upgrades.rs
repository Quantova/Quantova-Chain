// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upgrades {
    pub gas_metered_from_height: u64,
    pub bound_draw_from_epoch: u64,
    pub hardened_from_height: u64,
    pub deploy_fee_cap_from_height: u64,
}

pub const FROM_GENESIS: Upgrades = Upgrades {
    gas_metered_from_height: 0,
    bound_draw_from_epoch: 0,
    hardened_from_height: 0,
    deploy_fee_cap_from_height: u64::MAX,
};

pub const TESTNET: Upgrades = Upgrades {
    gas_metered_from_height: 472_850,
    bound_draw_from_epoch: 11,
    hardened_from_height: 5_242_880,
    deploy_fee_cap_from_height: u64::MAX,
};

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

    pub fn deploy_fee_capped(&self, height: u64) -> bool {
        height >= self.deploy_fee_cap_from_height
    }

    pub fn full_committee(&self, epoch: u64, heights_per_epoch: u64) -> bool {
        epoch.saturating_mul(heights_per_epoch) >= self.hardened_from_height
    }
}
