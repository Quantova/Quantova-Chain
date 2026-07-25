// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use crate::clock::{Time, SLOT_MS};

const DELIVER_MS: Time = 5;

const VIEW_TIMEOUT_MS: Time = 3 * SLOT_MS;

const REORDER_SPREAD_MS: Time = 2 * SLOT_MS;

#[derive(Clone, Copy, Debug)]
pub struct Network {
    latency: Time,
    spread: Time,
    view_timeout: Time,
}

impl Network {
    pub fn synchronous() -> Self {
        Network {
            latency: DELIVER_MS,
            spread: 0,
            view_timeout: VIEW_TIMEOUT_MS,
        }
    }

    pub fn reordering() -> Self {
        Network {
            latency: DELIVER_MS,
            spread: REORDER_SPREAD_MS,
            view_timeout: VIEW_TIMEOUT_MS,
        }
    }

    pub fn with_view_timeout(mut self, view_timeout: Time) -> Self {
        self.view_timeout = view_timeout;
        self
    }

    pub fn delay(&self, seq: u64) -> Time {
        if self.spread == 0 {
            return self.latency;
        }
        self.latency + scramble(seq) % (self.spread + 1)
    }

    pub fn view_timeout(&self) -> Time {
        self.view_timeout
    }
}

impl Default for Network {
    fn default() -> Self {
        Network::synchronous()
    }
}

fn scramble(seq: u64) -> Time {
    seq.wrapping_mul(11400714819323198485).rotate_left(29)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_synchronous_schedule_is_one_latency_for_every_record() {
        let net = Network::synchronous();
        assert_eq!(net.delay(0), DELIVER_MS);
        assert_eq!(net.delay(1), DELIVER_MS);
        assert_eq!(net.delay(1000), DELIVER_MS);
    }

    #[test]
    fn a_reordering_schedule_stays_within_the_window_and_varies() {
        let net = Network::reordering();
        let mut distinct = std::collections::BTreeSet::new();
        for seq in 0..64 {
            let d = net.delay(seq);
            assert!((DELIVER_MS..=DELIVER_MS + REORDER_SPREAD_MS).contains(&d));
            distinct.insert(d);
        }
        assert!(distinct.len() > 1);
        assert!(DELIVER_MS + REORDER_SPREAD_MS < net.view_timeout());
    }

    #[test]
    fn the_schedule_is_a_pure_function_of_the_counter() {
        let net = Network::reordering();
        for seq in 0..32 {
            assert_eq!(net.delay(seq), net.delay(seq));
        }
    }
}
