// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct SignGuard {
    path: PathBuf,
    mark: Option<(u64, u64, Option<[u8; 32]>)>,
}

impl SignGuard {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mark = match fs::read(&path) {
            Ok(bytes) => match decode_mark(&bytes) {
                Some(mark) => Some(mark),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the sign watermark file is present but unreadable; refusing to sign so a \
                         corrupt watermark cannot silently re-enable signing at an already signed height",
                    ));
                }
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        Ok(SignGuard { path, mark })
    }

    pub fn mark(&self) -> Option<(u64, u64)> {
        self.mark.map(|(height, view, _)| (height, view))
    }

    /// Signing the same value again at the same height is a resumption, not a second
    /// vote. Without that a restart before the block is persisted is fatal forever.
    pub fn permits(&self, height: u64, view: u64, value: &[u8; 32]) -> bool {
        match &self.mark {
            Some((mh, mv, mval)) => match (height, view).cmp(&(*mh, *mv)) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => mval.as_ref() == Some(value),
                std::cmp::Ordering::Less => false,
            },
            None => true,
        }
    }

    pub fn try_sign(&mut self, height: u64, view: u64, value: &[u8; 32]) -> io::Result<bool> {
        if !self.permits(height, view, value) {
            return Ok(false);
        }
        self.persist(height, view, value)?;
        self.mark = Some((height, view, Some(*value)));
        Ok(true)
    }

    fn persist(&self, height: u64, view: u64, value: &[u8; 32]) -> io::Result<()> {
        let mut bytes = [0u8; 52];
        bytes[0..8].copy_from_slice(&height.to_le_bytes());
        bytes[8..16].copy_from_slice(&view.to_le_bytes());
        bytes[16..48].copy_from_slice(value);
        let checksum = crc32(&bytes[0..48]);
        bytes[48..52].copy_from_slice(&checksum.to_le_bytes());
        let temp = self.path.with_extension("tmp");
        let mut file = fs::File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            let _ = fs::File::open(dir).and_then(|d| d.sync_all());
        }
        Ok(())
    }
}

fn decode_mark(bytes: &[u8]) -> Option<(u64, u64, Option<[u8; 32]>)> {
    match bytes.len() {
        52 => {
            let stored = u32::from_le_bytes(bytes[48..52].try_into().ok()?);
            if crc32(&bytes[0..48]) != stored {
                return None;
            }
            let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
            let view = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
            let value: [u8; 32] = bytes[16..48].try_into().ok()?;
            Some((height, view, Some(value)))
        }
        20 => {
            let stored = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
            if crc32(&bytes[0..16]) != stored {
                return None;
            }
            let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
            let view = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
            Some((height, view, None))
        }
        16 => {
            let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
            let view = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
            Some((height, view, None))
        }
        _ => None,
    }
}

#[derive(Debug)]
pub struct PrevoteGuard {
    path: PathBuf,
    mark: Option<(u64, u64, [u8; 32])>,
}

impl PrevoteGuard {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mark = match fs::read(&path) {
            Ok(bytes) => match decode_prevote(&bytes) {
                Some(mark) => Some(mark),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the prevote watermark file is present but unreadable; refusing to \
                         prevote so a corrupt watermark cannot re-enable a conflicting prevote",
                    ));
                }
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        Ok(PrevoteGuard { path, mark })
    }

    pub fn permits(&self, height: u64, view: u64, value: &[u8; 32]) -> bool {
        match &self.mark {
            Some((mh, mv, mval)) => {
                let here = (height, view);
                let there = (*mh, *mv);
                match here.cmp(&there) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => value == mval,
                    std::cmp::Ordering::Less => false,
                }
            }
            None => true,
        }
    }

    pub fn try_prevote(&mut self, height: u64, view: u64, value: &[u8; 32]) -> io::Result<bool> {
        if !self.permits(height, view, value) {
            return Ok(false);
        }
        if self
            .mark
            .as_ref()
            .map(|(mh, mv, _)| (height, view) >= (*mh, *mv))
            .unwrap_or(true)
        {
            self.persist(height, view, value)?;
            self.mark = Some((height, view, *value));
        }
        Ok(true)
    }

    fn persist(&self, height: u64, view: u64, value: &[u8; 32]) -> io::Result<()> {
        let mut bytes = [0u8; 52];
        bytes[0..8].copy_from_slice(&height.to_le_bytes());
        bytes[8..16].copy_from_slice(&view.to_le_bytes());
        bytes[16..48].copy_from_slice(value);
        let checksum = crc32(&bytes[0..48]);
        bytes[48..52].copy_from_slice(&checksum.to_le_bytes());
        let temp = self.path.with_extension("tmp");
        let mut file = fs::File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            let _ = fs::File::open(dir).and_then(|d| d.sync_all());
        }
        Ok(())
    }
}

fn decode_prevote(bytes: &[u8]) -> Option<(u64, u64, [u8; 32])> {
    if bytes.len() != 52 {
        return None;
    }
    let stored = u32::from_le_bytes(bytes[48..52].try_into().ok()?);
    if crc32(&bytes[0..48]) != stored {
        return None;
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let view = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let mut value = [0u8; 32];
    value.copy_from_slice(&bytes[16..48]);
    Some((height, view, value))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "qtv-watermark-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        path
    }

    fn cleanup(path: &Path) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(path.with_extension("tmp")).ok();
    }

    #[test]
    fn a_restart_refuses_a_conflicting_prevote_but_allows_the_same_one() {
        let path = temp_path("prevote-restart");
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        {
            let mut guard = PrevoteGuard::open(&path).unwrap();
            assert!(
                guard.try_prevote(7, 2, &a).unwrap(),
                "first prevote is allowed"
            );
        }
        {
            let mut guard = PrevoteGuard::open(&path).unwrap();
            assert!(
                !guard.try_prevote(7, 2, &b).unwrap(),
                "a different value at the same height and view is refused after restart"
            );
            assert!(
                guard.try_prevote(7, 2, &a).unwrap(),
                "re-broadcasting the identical prevote is still allowed"
            );
            assert!(
                !guard.try_prevote(7, 1, &a).unwrap(),
                "an older view is refused after restart"
            );
            assert!(
                guard.try_prevote(7, 3, &b).unwrap(),
                "a newer view is allowed and advances the mark"
            );
            assert!(
                !guard.try_prevote(7, 3, &a).unwrap(),
                "once advanced, a conflicting value at the new view is refused too"
            );
        }
        cleanup(&path);
    }

    #[test]
    fn an_absent_watermark_permits_the_first_signature() {
        let path = temp_path("absent");
        let guard = SignGuard::open(&path).unwrap();
        assert_eq!(guard.mark(), None);
        assert!(guard.permits(1, 0, &[1u8; 32]));
        cleanup(&path);
    }

    #[test]
    // A node that signs, restarts before the block persists, and reproduces the same
    // block must resume. Refusing that is what bricked a validator for good.
    fn a_restart_resumes_the_same_value_but_refuses_a_different_one() {
        let path = temp_path("sign-resume");
        let value = [7u8; 32];
        let other = [9u8; 32];
        {
            let mut guard = SignGuard::open(&path).expect("open");
            assert!(guard.try_sign(4, 0, &value).expect("first sign"));
        }
        {
            let mut guard = SignGuard::open(&path).expect("reopen");
            assert!(
                guard.try_sign(4, 0, &value).expect("resume"),
                "a restart at the same height and the same block refused to resume"
            );
            assert!(
                !guard.try_sign(4, 0, &other).expect("conflict"),
                "a different block at a signed height was permitted"
            );
        }
        cleanup(&path);
    }

    // Precommitting a different value at a HIGHER view is ordinary consensus, not a
    // double sign. Refusing it killed a validator that restarted during a stalled height.
    #[test]
    fn a_higher_view_may_precommit_a_different_value() {
        let path = temp_path("higher-view");
        let a = [7u8; 32];
        let b = [8u8; 32];
        {
            let mut guard = SignGuard::open(&path).expect("open");
            assert!(guard.try_sign(9, 2, &a).expect("first sign"));
        }
        {
            let mut guard = SignGuard::open(&path).expect("reopen");
            assert!(
                guard.try_sign(9, 7, &b).expect("higher view"),
                "a different value at a higher view is a legitimate precommit"
            );
            assert!(
                !guard.try_sign(9, 7, &a).expect("same view conflict"),
                "a second value at the same view is still refused"
            );
        }
        cleanup(&path);
    }

    #[test]
    fn a_restart_refuses_a_height_and_view_it_already_signed() {
        let path = temp_path("restart");
        {
            let mut guard = SignGuard::open(&path).unwrap();
            assert!(guard.try_sign(5, 2, &[1u8; 32]).unwrap());
        }
        let mut guard = SignGuard::open(&path).unwrap();
        assert_eq!(guard.mark(), Some((5, 2)));
        assert!(
            !guard.try_sign(5, 2, &[2u8; 32]).unwrap(),
            "a different block at the exact height and view it signed"
        );
        assert!(
            !guard.try_sign(5, 1, &[1u8; 32]).unwrap(),
            "a lower view at the same height"
        );
        assert!(!guard.try_sign(4, 9, &[1u8; 32]).unwrap(), "a lower height");
        assert!(
            guard.try_sign(5, 3, &[1u8; 32]).unwrap(),
            "a higher view advances the watermark"
        );
        assert!(
            guard.try_sign(6, 0, &[1u8; 32]).unwrap(),
            "a higher height advances the watermark"
        );
        assert_eq!(guard.mark(), Some((6, 0)));
        cleanup(&path);
    }

    #[test]
    fn a_present_but_truncated_watermark_refuses_to_open() {
        let path = temp_path("truncated");
        std::fs::write(&path, [0u8; 9]).unwrap();
        let err = SignGuard::open(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "a corrupt watermark fails closed"
        );
        cleanup(&path);
    }

    #[test]
    fn a_watermark_with_a_bad_checksum_refuses_to_open() {
        let path = temp_path("badcrc");
        let mut bytes = [0u8; 20];
        bytes[0..8].copy_from_slice(&5u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&2u64.to_le_bytes());
        let checksum = crc32(&bytes[0..16]);
        bytes[16..20].copy_from_slice(&checksum.to_le_bytes());
        bytes[0] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let err = SignGuard::open(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "a bit-flip that lowers the mark is detected"
        );
        cleanup(&path);
    }

    #[test]
    fn a_legacy_sixteen_byte_watermark_is_accepted_and_upgraded() {
        let path = temp_path("legacy");
        let mut legacy = [0u8; 16];
        legacy[0..8].copy_from_slice(&7u64.to_le_bytes());
        legacy[8..16].copy_from_slice(&3u64.to_le_bytes());
        std::fs::write(&path, legacy).unwrap();

        let mut guard = SignGuard::open(&path).unwrap();
        assert_eq!(guard.mark(), Some((7, 3)), "a legacy mark loads");
        assert!(
            !guard.try_sign(7, 3, &[1u8; 32]).unwrap(),
            "and still refuses what it already signed"
        );
        assert!(guard.try_sign(8, 0, &[1u8; 32]).unwrap());

        let reopened = SignGuard::open(&path).unwrap();
        assert_eq!(
            reopened.mark(),
            Some((8, 0)),
            "the upgraded checksummed mark round trips"
        );
        assert_eq!(
            std::fs::read(&path).unwrap().len(),
            52,
            "the file upgraded to the value bound format"
        );
        cleanup(&path);
    }

    #[test]
    fn the_watermark_advances_monotonically_within_one_run() {
        let path = temp_path("mono");
        let mut guard = SignGuard::open(&path).unwrap();
        assert!(guard.try_sign(1, 0, &[1u8; 32]).unwrap());
        assert!(guard.try_sign(2, 0, &[1u8; 32]).unwrap());
        assert!(!guard.try_sign(2, 0, &[2u8; 32]).unwrap());
        assert!(!guard.try_sign(1, 5, &[1u8; 32]).unwrap());
        assert!(guard.try_sign(2, 1, &[1u8; 32]).unwrap());
        cleanup(&path);
    }
}
