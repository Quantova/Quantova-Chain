// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const RECORD: usize = 40;
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

#[derive(Debug)]
pub struct TxIndex {
    dir: PathBuf,
    tail_path: PathBuf,
    runs: Vec<Run>,
    next_seq: u64,
    tail: File,
    sorted_len: usize,
    tail_len: usize,
    tail_mem: Vec<([u8; 32], u64)>,
}

#[derive(Debug)]
struct Run {
    path: PathBuf,
    file: File,
    len: usize,
}

const RUN_PREFIX: &str = "txindex.run.";
const RUN_FANOUT: usize = 4;

fn sync_dir(dir: &Path) -> io::Result<()> {
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    File::open(dir)?.sync_all()
}

fn open_run(path: PathBuf) -> io::Result<Run> {
    let file = OpenOptions::new().read(true).open(&path)?;
    let len = file.metadata()?.len() as usize / RECORD;
    Ok(Run { path, file, len })
}

fn next_record(reader: &mut std::io::BufReader<File>) -> Option<([u8; 32], u64)> {
    let mut buf = [0u8; RECORD];
    reader.read_exact(&mut buf).ok()?;
    Some(split_record(&buf))
}

impl TxIndex {
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let tail_path = dir.join("txindex.tail");
        let mut found: Vec<(u64, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.ends_with(".rebuilding") {
                std::fs::remove_file(&path)?;
                continue;
            }
            if let Some(seq) = name.strip_prefix(RUN_PREFIX) {
                if let Ok(seq) = seq.parse::<u64>() {
                    found.push((seq, path));
                }
            }
        }
        found.sort_by_key(|(seq, _)| *seq);
        let next_seq = found.last().map_or(0, |(seq, _)| seq + 1);
        let mut runs = Vec::with_capacity(found.len());
        for (_, path) in found {
            runs.push(open_run(path)?);
        }
        let sorted_len = runs.iter().map(|run| run.len).sum();
        let tail = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&tail_path)?;
        let tail_bytes = tail.metadata()?.len() as usize;
        let tail_len = tail_bytes / RECORD;
        if tail_bytes % RECORD != 0 {
            tail.set_len((tail_len * RECORD) as u64)?;
        }
        let mut tail_mem = Vec::with_capacity(tail_len);
        {
            let mut r = std::io::BufReader::new(File::open(&tail_path)?);
            for _ in 0..tail_len {
                match next_record(&mut r) {
                    Some(record) => tail_mem.push(record),
                    None => break,
                }
            }
        }
        Ok(TxIndex {
            dir,
            tail_path,
            runs,
            next_seq,
            tail,
            sorted_len,
            tail_len,
            tail_mem,
        })
    }

    pub fn insert(&mut self, id: &[u8; 32], height: u64) -> io::Result<()> {
        self.tail.write_all(&record_bytes(id, height))?;
        self.tail_len += 1;
        self.tail_mem.push((*id, height));
        if self.tail_len >= TAIL_MERGE_AT {
            self.merge()?;
        }
        Ok(())
    }

    pub fn get(&self, id: &[u8; 32]) -> io::Result<Option<u64>> {
        if let Some(height) = self.scan_tail(id)? {
            return Ok(Some(height));
        }
        for run in self.runs.iter().rev() {
            if let Some(height) = search_run(run, id)? {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    fn scan_tail(&self, id: &[u8; 32]) -> io::Result<Option<u64>> {
        Ok(self
            .tail_mem
            .iter()
            .rev()
            .find(|(got, _)| got == id)
            .map(|(_, height)| *height))
    }

    fn write_run<I>(&mut self, records: I) -> io::Result<Run>
    where
        I: Iterator<Item = ([u8; 32], u64)>,
    {
        let path = self.dir.join(format!("{RUN_PREFIX}{:020}", self.next_seq));
        self.next_seq += 1;
        let tmp = path.with_extension("rebuilding");
        {
            let mut out = std::io::BufWriter::new(File::create(&tmp)?);
            for (id, height) in records {
                out.write_all(&record_bytes(&id, height))?;
            }
            out.flush()?;
            out.into_inner()
                .map_err(|e| io::Error::other(e.to_string()))?
                .sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        sync_dir(&self.dir)?;
        open_run(path)
    }

    pub fn merge(&mut self) -> io::Result<()> {
        if self.tail_len == 0 {
            return Ok(());
        }
        let mut tail = std::mem::take(&mut self.tail_mem);
        tail.sort_by_key(|r| r.0);
        tail.dedup_by(|a, b| {
            if a.0 == b.0 {
                b.1 = a.1;
                true
            } else {
                false
            }
        });
        let run = self.write_run(tail.into_iter())?;
        self.sorted_len += run.len;
        self.runs.push(run);

        self.tail = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.tail_path)?;
        self.tail.sync_all()?;
        self.tail = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.tail_path)?;
        self.tail_len = 0;

        while self.runs.len() >= 2 {
            let newer = &self.runs[self.runs.len() - 1];
            let older = &self.runs[self.runs.len() - 2];
            if newer.len.saturating_mul(RUN_FANOUT) < older.len {
                break;
            }
            self.fold_newest()?;
        }
        Ok(())
    }

    fn fold_newest(&mut self) -> io::Result<()> {
        let newer = self.runs.pop().expect("two runs");
        let older = self.runs.pop().expect("two runs");
        let mut left = std::io::BufReader::new(File::open(&older.path)?);
        let mut right = std::io::BufReader::new(File::open(&newer.path)?);
        let mut l = next_record(&mut left);
        let mut r = next_record(&mut right);
        let merged = std::iter::from_fn(move || match (l, r) {
            (None, None) => None,
            (Some(a), Some(b)) if a.0 == b.0 => {
                l = next_record(&mut left);
                r = next_record(&mut right);
                Some(b)
            }
            (Some(a), Some(b)) if a.0 < b.0 => {
                l = next_record(&mut left);
                Some(a)
            }
            (Some(_), Some(b)) => {
                r = next_record(&mut right);
                Some(b)
            }
            (Some(a), None) => {
                l = next_record(&mut left);
                Some(a)
            }
            (None, Some(b)) => {
                r = next_record(&mut right);
                Some(b)
            }
        });
        let run = self.write_run(merged)?;
        std::fs::remove_file(&older.path)?;
        std::fs::remove_file(&newer.path)?;
        sync_dir(&self.dir)?;
        self.sorted_len = self.sorted_len - older.len - newer.len + run.len;
        self.runs.push(run);
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

    #[cfg(test)]
    fn run_count(&self) -> usize {
        self.runs.len()
    }
}

fn search_run(run: &Run, id: &[u8; 32]) -> io::Result<Option<u64>> {
    let mut lo = 0usize;
    let mut hi = run.len;
    let mut file = &run.file;
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
    fn a_merge_across_many_entries_keeps_every_answer_in_order() {
        let d = dir("stream");
        let mut ix = TxIndex::open(&d).expect("opens");
        for n in 0..255u8 {
            ix.insert(&id(n), 100 + n as u64).expect("insert");
        }
        ix.merge().expect("first merge");
        for n in 0..255u8 {
            if n % 3 == 0 {
                ix.insert(&id(n), 9000 + n as u64).expect("rewrite");
            }
        }
        ix.merge().expect("second merge");
        for n in 0..255u8 {
            let want = if n % 3 == 0 { 9000 } else { 100 } + n as u64;
            assert_eq!(
                ix.get(&id(n)).expect("read"),
                Some(want),
                "id {n} must read back the later height"
            );
        }
        assert_eq!(ix.len(), 255, "rewrites fold rather than duplicate");
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

    #[test]
    fn many_flushes_keep_a_logarithmic_run_count_and_every_answer() {
        let d = dir("leveled");
        let mut ix = TxIndex::open(&d).expect("opens");
        let key = |n: u32| {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&n.to_be_bytes());
            a[31] = (n % 251) as u8;
            a
        };
        let total = 40 * TAIL_MERGE_AT as u32;
        for n in 0..total {
            ix.insert(&key(n.wrapping_mul(2_654_435_761)), n as u64)
                .expect("insert");
        }
        assert!(ix.run_count() <= 8, "held {} runs", ix.run_count());
        ix.sync().expect("sync");
        drop(ix);
        let ix = TxIndex::open(&d).expect("reopens");
        for n in (0..total).step_by(97) {
            assert_eq!(
                ix.get(&key(n.wrapping_mul(2_654_435_761))).expect("read"),
                Some(n as u64)
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
