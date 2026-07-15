//! The logical clock and the event queue the asynchronous round loop turns over.
//!
//! A node acts when a message arrives or a timer fires, not when a central driver
//! steps every node together. Both are events on one logical clock. The clock
//! advances only when the loop pops an event, never against a wall clock, so a
//! given schedule of events replays to the identical chain. Ties at one logical
//! time break by the order the events were scheduled, so the pop order is a fixed
//! total order and there are no threads and no real time in the loop.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Logical time in milliseconds. One slot is `SLOT_MS` of this time.
pub type Time = u64;

/// The logical duration of a slot, the consensus slot reused as logical time. A
/// leader proposes within its slot and a view times out after a bound measured in
/// slots.
pub const SLOT_MS: Time = qtv_bft::params::SLOT_MS;

/// An event the round loop acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A view timeout fired for a node at a height and view. If the node is still
    /// at that height and view without a valid proposal, it advances the view.
    Timeout { node: usize, height: u64, view: u64 },
    /// One sealed record is ready to open at `to` from `from`. The loop opens
    /// exactly one record on that directed edge, in send order.
    Deliver { from: usize, to: usize },
}

/// An event stamped with the logical time it fires and the sequence number it was
/// scheduled under. The sequence number breaks ties at equal times, so the pop
/// order of the queue is a fixed total order for a given schedule.
struct Scheduled {
    time: Time,
    seq: u64,
    event: Event,
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.seq == other.seq
    }
}

impl Eq for Scheduled {}

impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time.cmp(&other.time).then(self.seq.cmp(&other.seq))
    }
}

impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A logical clock over a queue of scheduled events. The clock owns the present
/// time, a monotonic sequence counter, and a min ordered queue keyed by time then
/// sequence.
#[derive(Default)]
pub struct Clock {
    now: Time,
    seq: u64,
    queue: BinaryHeap<Reverse<Scheduled>>,
}

impl Clock {
    /// A clock at time zero with no events scheduled.
    pub fn new() -> Self {
        Clock::default()
    }

    /// The present logical time, the time of the last event popped.
    pub fn now(&self) -> Time {
        self.now
    }

    /// Schedule an event to fire at `at`, never before the present. Ties break by
    /// the order events are scheduled, keeping the pop order deterministic.
    pub fn schedule(&mut self, at: Time, event: Event) {
        let time = at.max(self.now);
        let seq = self.seq;
        self.seq += 1;
        self.queue.push(Reverse(Scheduled { time, seq, event }));
    }

    /// Pop the next event, advancing the present to its time. None when the queue
    /// is empty, which is quiescence: no timer and no record is left to act on.
    pub fn next_event(&mut self) -> Option<Event> {
        let Reverse(scheduled) = self.queue.pop()?;
        self.now = scheduled.time;
        Some(scheduled.event)
    }

    /// Whether no event is left to fire.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_pop_in_time_then_schedule_order() {
        let mut clock = Clock::new();
        clock.schedule(30, Event::Deliver { from: 0, to: 1 });
        clock.schedule(10, Event::Deliver { from: 1, to: 2 });
        clock.schedule(10, Event::Deliver { from: 2, to: 0 });
        assert_eq!(clock.next_event(), Some(Event::Deliver { from: 1, to: 2 }));
        assert_eq!(clock.now(), 10);
        assert_eq!(clock.next_event(), Some(Event::Deliver { from: 2, to: 0 }));
        assert_eq!(clock.now(), 10);
        assert_eq!(clock.next_event(), Some(Event::Deliver { from: 0, to: 1 }));
        assert_eq!(clock.now(), 30);
        assert!(clock.is_idle());
        assert_eq!(clock.next_event(), None);
    }

    #[test]
    fn a_schedule_never_fires_before_the_present() {
        let mut clock = Clock::new();
        clock.schedule(
            50,
            Event::Timeout {
                node: 0,
                height: 1,
                view: 0,
            },
        );
        clock.next_event();
        assert_eq!(clock.now(), 50);
        // Scheduled in the past, so it fires at the present, not before it.
        clock.schedule(
            20,
            Event::Timeout {
                node: 1,
                height: 1,
                view: 0,
            },
        );
        clock.next_event();
        assert_eq!(clock.now(), 50);
    }
}
