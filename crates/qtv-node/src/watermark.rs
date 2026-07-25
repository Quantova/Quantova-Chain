// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct SignGuard {
    path: PathBuf,
    mark: Option<(u64, u64)>,
}

impl SignGuard {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mark = match fs::read(&path) {
            Ok(bytes) => decode_mark(&bytes),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        Ok(SignGuard { path, mark })
    }

    pub fn mark(&self) -> Option<(u64, u64)> {
        self.mark
    }

    pub fn permits(&self, height: u64, view: u64) -> bool {
        match self.mark {
            Some(mark) => (height, view) > mark,
            None => true,
        }
    }

    pub fn try_sign(&mut self, height: u64, view: u64) -> io::Result<bool> {
        if !self.permits(height, view) {
            return Ok(false);
        }
        self.persist(height, view)?;
        self.mark = Some((height, view));
        Ok(true)
    }

    fn persist(&self, height: u64, view: u64) -> io::Result<()> {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&height.to_le_bytes());
        bytes[8..16].copy_from_slice(&view.to_le_bytes());
        let temp = self.path.with_extension("tmp");
        fs::write(&temp, bytes)?;
        fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

fn decode_mark(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() != 16 {
        return None;
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let view = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    Some((height, view))
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
    fn an_absent_watermark_permits_the_first_signature() {
        let path = temp_path("absent");
        let guard = SignGuard::open(&path).unwrap();
        assert_eq!(guard.mark(), None);
        assert!(guard.permits(1, 0));
        cleanup(&path);
    }

    #[test]
    fn a_restart_refuses_a_height_and_view_it_already_signed() {
        let path = temp_path("restart");
        {
            let mut guard = SignGuard::open(&path).unwrap();
            assert!(guard.try_sign(5, 2).unwrap());
        }
        let mut guard = SignGuard::open(&path).unwrap();
        assert_eq!(guard.mark(), Some((5, 2)));
        assert!(!guard.try_sign(5, 2).unwrap(), "the exact height and view it signed");
        assert!(!guard.try_sign(5, 1).unwrap(), "a lower view at the same height");
        assert!(!guard.try_sign(4, 9).unwrap(), "a lower height");
        assert!(guard.try_sign(5, 3).unwrap(), "a higher view advances the watermark");
        assert!(guard.try_sign(6, 0).unwrap(), "a higher height advances the watermark");
        assert_eq!(guard.mark(), Some((6, 0)));
        cleanup(&path);
    }

    #[test]
    fn the_watermark_advances_monotonically_within_one_run() {
        let path = temp_path("mono");
        let mut guard = SignGuard::open(&path).unwrap();
        assert!(guard.try_sign(1, 0).unwrap());
        assert!(guard.try_sign(2, 0).unwrap());
        assert!(!guard.try_sign(2, 0).unwrap());
        assert!(!guard.try_sign(1, 5).unwrap());
        assert!(guard.try_sign(2, 1).unwrap());
        cleanup(&path);
    }
}
