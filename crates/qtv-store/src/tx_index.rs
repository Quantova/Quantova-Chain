// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// A transaction id and the height that finalized it, as stored.
const RECORD: usize = 40;
/// Merge the tail into the sorted run once it passes this many records, so a lookup
/// never scans a long tail.
const TAIL_MERGE_AT: usize = 4096;

fn record_bytes(id: &[u8; 32], height: u64) -> [u8; RECORD] {
    let mut out = [0u8; RECORD];
    out[..32].copy_from_slice(id);
    out[32..].copy_from_slice(&height.to_be_bytes());
    out
}

fn split_record(buf: &[u8; RECORD]) -> ([u8; 32], u64) {
    let mut id = [0u8; 32];
    id.copy_from_slice(&buf[..32]);
    let height = u64::from_be_bytes(buf[32..].try_into().expect("eight bytes"));
    (id, height)
}

/// Which height finalized a transaction, answered from disk.
///
/// The index used to be a `HashMap<String, Height>` held entirely in memory and rebuilt
/// on every start by decoding every block from genesis. That cost hundreds of megabytes
/// on a busy chain and made a restart proportional to the whole history. Records live in
/// a sorted run that is binary searched by seeking, plus a short unsorted tail that is
/// merged in once it grows, so memory is constant and a start reads nothing.
#[derive(Debug)]
pub struct TxIndex {
    sorted_path: PathBuf,
    tail_path: PathBuf,
    sorted: File,
    tail: File,
    sorted_len: usize,
    tail_len: usize,
}

impl TxIndex {
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let sorted_path = dir.join("txindex.sorted");
        let tail_path = dir.join("txindex.tail");
        let sorted = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&sorted_path)?;
        let tail = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&tail_path)?;
        // A torn write leaves a partial record; ignore the remainder rather than
        // reading half an id as a whole one.
        let sorted_len = sorted.metadata()?.len() as usize / RECORD;
        let tail_len = tail.metadata()?.len() as usize / RECORD;
        Ok(TxIndex {
            sorted_path,
            tail_path,
            sorted,
            tail,
            sorted_len,
            tail_len,
        })
    }

    pub fn insert(&mut self, id: &[u8; 32], height: u64) -> io::Result<()> {
        self.tail.write_all(&record_bytes(id, height))?;
        self.tail_len += 1;
        if self.tail_len >= TAIL_MERGE_AT {
            self.merge()?;
        }
        Ok(())
    }

    pub fn get(&self, id: &[u8; 32]) -> io::Result<Option<u64>> {
        // The tail is newest, so it wins over an older sorted entry for the same id.
        if let Some(height) = self.scan_tail(id)? {
            return Ok(Some(height));
        }
        self.search_sorted(id)
    }

    fn scan_tail(&self, id: &[u8; 32]) -> io::Result<Option<u64>> {
        let mut found = None;
        let mut file = &self.tail;
        let mut buf = [0u8; RECORD];
        for i in 0..self.tail_len {
            file.seek(SeekFrom::Start((i * RECORD) as u64))?;
            if file.read_exact(&mut buf).is_err() {
                break;
            }
            let (got, height) = split_record(&buf);
            if got == *id {
                found = Some(height);
            }
        }
        Ok(found)
    }

    fn search_sorted(&self, id: &[u8; 32]) -> io::Result<Option<u64>> {
        let mut lo = 0usize;
        let mut hi = self.sorted_len;
        let mut file = &self.sorted;
        let mut buf = [0u8; RECORD];
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            file.seek(SeekFrom::Start((mid * RECORD) as u64))?;
            file.read_exact(&mut buf)?;
            let (got, height) = split_record(&buf);
            match got.cmp(id) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Ok(Some(height)),
            }
        }
        Ok(None)
    }

    /// Fold the tail into the sorted run. The only point memory is proportional to the
    /// index, and it is bounded by how often this runs rather than by the chain.
    pub fn merge(&mut self) -> io::Result<()> {
        if self.tail_len == 0 {
            return Ok(());
        }
        let mut all: Vec<([u8; 32], u64)> = Vec::with_capacity(self.sorted_len + self.tail_len);
        let mut buf = [0u8; RECORD];

        self.sorted.seek(SeekFrom::Start(0))?;
        for _ in 0..self.sorted_len {
            self.sorted.read_exact(&mut buf)?;
            all.push(split_record(&buf));
        }
        let mut tail_read = File::open(&self.tail_path)?;
        for _ in 0..self.tail_len {
            if tail_read.read_exact(&mut buf).is_err() {
                break;
            }
            all.push(split_record(&buf));
        }

        // Later wins, so sort by id and keep the last of each run.
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all.dedup_by(|a, b| {
            if a.0 == b.0 {
                b.1 = a.1;
                true
            } else {
                false
            }
        });

        let tmp = self.sorted_path.with_extension("rebuilding");
        {
            let mut out = File::create(&tmp)?;
            for (id, height) in &all {
                out.write_all(&record_bytes(id, *height))?;
            }
            out.sync_all()?;
        }
        std::fs::rename(&tmp, &self.sorted_path)?;

        self.sorted = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.sorted_path)?;
        self.sorted_len = all.len();

        self.tail = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.tail_path)?;
        self.tail = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.tail_path)?;
        self.tail_len = 0;
        Ok(())
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.tail.flush()?;
        self.tail.sync_all()
    }

    pub fn len(&self) -> usize {
        self.sorted_len + self.tail_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a[31] = n.wrapping_mul(7);
        a
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qtv-txindex-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_transaction_height_survives_a_restart_without_rereading_the_chain() {
        let d = dir("restart");
        {
            let mut ix = TxIndex::open(&d).expect("opens");
            for n in 0..50u8 {
                ix.insert(&id(n), 1000 + n as u64).expect("insert");
            }
            ix.sync().expect("sync");
        }
        let ix = TxIndex::open(&d).expect("reopens");
        for n in 0..50u8 {
            assert_eq!(ix.get(&id(n)).expect("read"), Some(1000 + n as u64));
        }
        assert_eq!(ix.get(&id(200)).expect("read"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_merge_keeps_every_answer_and_empties_the_tail() {
        let d = dir("merge");
        let mut ix = TxIndex::open(&d).expect("opens");
        for n in 0..200u8 {
            ix.insert(&id(n), 7000 + n as u64).expect("insert");
        }
        ix.merge().expect("merge");
        assert_eq!(ix.tail_len, 0, "the tail is folded in");
        assert_eq!(ix.sorted_len, 200);
        for n in 0..200u8 {
            assert_eq!(ix.get(&id(n)).expect("read"), Some(7000 + n as u64));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_later_height_wins_for_a_repeated_id() {
        let d = dir("dup");
        let mut ix = TxIndex::open(&d).expect("opens");
        ix.insert(&id(9), 10).expect("insert");
        assert_eq!(ix.get(&id(9)).expect("read"), Some(10));
        ix.insert(&id(9), 20).expect("insert");
        assert_eq!(ix.get(&id(9)).expect("read"), Some(20), "tail beats sorted");
        ix.merge().expect("merge");
        assert_eq!(
            ix.get(&id(9)).expect("read"),
            Some(20),
            "and survives a merge"
        );
        assert_eq!(ix.len(), 1, "the duplicate is folded, not doubled");
        let _ = std::fs::remove_dir_all(&d);
    }
}
