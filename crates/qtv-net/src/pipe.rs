// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};

struct Buffer {
    data: VecDeque<u8>,
    closed: bool,
}

type Shared = Arc<(Mutex<Buffer>, Condvar)>;

fn shared() -> Shared {
    Arc::new((
        Mutex::new(Buffer {
            data: VecDeque::new(),
            closed: false,
        }),
        Condvar::new(),
    ))
}

pub struct DuplexStream {
    inbound: Shared,
    outbound: Shared,
}

pub fn duplex() -> (DuplexStream, DuplexStream) {
    let one = shared();
    let two = shared();
    let left = DuplexStream {
        inbound: one.clone(),
        outbound: two.clone(),
    };
    let right = DuplexStream {
        inbound: two,
        outbound: one,
    };
    (left, right)
}

impl Read for DuplexStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let (lock, signal) = &*self.inbound;
        let mut buffer = lock.lock().unwrap();
        loop {
            if !buffer.data.is_empty() {
                let count = out.len().min(buffer.data.len());
                for (slot, byte) in out[..count].iter_mut().zip(buffer.data.drain(..count)) {
                    *slot = byte;
                }
                return Ok(count);
            }
            if buffer.closed {
                return Ok(0);
            }
            buffer = signal.wait(buffer).unwrap();
        }
    }
}

impl Write for DuplexStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let (lock, signal) = &*self.outbound;
        let mut buffer = lock.lock().unwrap();
        buffer.data.extend(data.iter().copied());
        signal.notify_all();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        let (lock, signal) = &*self.outbound;
        let mut buffer = lock.lock().unwrap();
        buffer.closed = true;
        signal.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn duplex_carries_bytes_both_ways() {
        let (mut left, mut right) = duplex();
        let worker = thread::spawn(move || {
            let mut seen = [0u8; 5];
            right.read_exact(&mut seen).unwrap();
            right.write_all(b"world").unwrap();
            seen
        });
        left.write_all(b"hello").unwrap();
        let seen = worker.join().unwrap();
        assert_eq!(&seen, b"hello");
        let mut back = [0u8; 5];
        left.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"world");
    }

    #[test]
    fn closing_one_end_signals_end_of_stream() {
        let (left, mut right) = duplex();
        drop(left);
        let mut sink = [0u8; 4];
        assert_eq!(right.read(&mut sink).unwrap(), 0);
    }
}
