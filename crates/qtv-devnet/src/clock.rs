
use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

pub type Time = u64;

pub const SLOT_MS: Time = qtv_bft::params::SLOT_MS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Timeout { node: usize, height: u64, view: u64 },
    Deliver { from: usize, to: usize },
}

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

#[derive(Default)]
pub struct Clock {
    now: Time,
    seq: u64,
    queue: BinaryHeap<Reverse<Scheduled>>,
}

impl Clock {
    pub fn new() -> Self {
        Clock::default()
    }

    pub fn now(&self) -> Time {
        self.now
    }

    pub fn schedule(&mut self, at: Time, event: Event) {
        let time = at.max(self.now);
        let seq = self.seq;
        self.seq += 1;
        self.queue.push(Reverse(Scheduled { time, seq, event }));
    }

    pub fn peek_time(&self) -> Option<Time> {
        self.queue.peek().map(|Reverse(scheduled)| scheduled.time)
    }

    pub fn next_event(&mut self) -> Option<Event> {
        let Reverse(scheduled) = self.queue.pop()?;
        self.now = scheduled.time;
        Some(scheduled.event)
    }

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
