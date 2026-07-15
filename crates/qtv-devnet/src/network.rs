//! The delivery schedule the round loop stamps sealed records with, and the view
//! timeout a node waits before it rotates the leader.
//!
//! The schedule is a pure function of a per record counter, so a run replays to
//! the identical chain and any reordering is deterministic rather than a race. A
//! synchronous schedule delivers every record after one fixed latency. A
//! reordering schedule spreads the delays across a window, so records from
//! different peers arrive at a receiver in a scrambled order while the records on
//! one directed edge still arrive in send order, the way one ordered stream
//! behaves under a network that interleaves several of them.

use crate::clock::{Time, SLOT_MS};

/// The base latency of one hop, in logical milliseconds.
const DELIVER_MS: Time = 5;

/// The default view timeout, three slots. A round of propose, attest, and collect
/// completes in a few hops, well inside this bound, so the happy path never times
/// out; a silent leader offers no proposal, so the bound elapses and the view
/// rotates.
const VIEW_TIMEOUT_MS: Time = 3 * SLOT_MS;

/// The reordering window, two slots. A record is delayed by up to this much on top
/// of the base latency, kept below the view timeout so a reordered proposal still
/// lands before the view would rotate.
const REORDER_SPREAD_MS: Time = 2 * SLOT_MS;

/// A delivery schedule: the base latency of a hop, the reordering window, and the
/// view timeout.
#[derive(Clone, Copy, Debug)]
pub struct Network {
    latency: Time,
    spread: Time,
    view_timeout: Time,
}

impl Network {
    /// A synchronous schedule: every record after one fixed latency, no spread,
    /// so records arrive in a single global order.
    pub fn synchronous() -> Self {
        Network {
            latency: DELIVER_MS,
            spread: 0,
            view_timeout: VIEW_TIMEOUT_MS,
        }
    }

    /// A schedule that spreads record delays across a window, so records from
    /// different peers arrive at a receiver in a scrambled order. Each directed
    /// edge still delivers in send order.
    pub fn reordering() -> Self {
        Network {
            latency: DELIVER_MS,
            spread: REORDER_SPREAD_MS,
            view_timeout: VIEW_TIMEOUT_MS,
        }
    }

    /// Override the view timeout, used to force or forbid a view change in a test.
    pub fn with_view_timeout(mut self, view_timeout: Time) -> Self {
        self.view_timeout = view_timeout;
        self
    }

    /// The delay to deliver the record with the given send counter. Deterministic
    /// in the counter, so the whole schedule replays identically.
    pub fn delay(&self, seq: u64) -> Time {
        if self.spread == 0 {
            return self.latency;
        }
        self.latency + scramble(seq) % (self.spread + 1)
    }

    /// The time a node waits at a height and view before it times out.
    pub fn view_timeout(&self) -> Time {
        self.view_timeout
    }
}

impl Default for Network {
    fn default() -> Self {
        Network::synchronous()
    }
}

/// A deterministic scramble of a counter, spreading consecutive counters across
/// the window so consecutive records do not keep their send order across edges.
fn scramble(seq: u64) -> Time {
    seq.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(29)
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
        // The delays actually spread, so records reorder across edges.
        assert!(distinct.len() > 1);
        // A reordered record still lands before the view would rotate.
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
