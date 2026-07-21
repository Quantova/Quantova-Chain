
use std::collections::BTreeMap;

use qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES;
use qtv_net::{Identity, PeerId};

pub const KEY_BYTES: usize = PUBLIC_KEY_BYTES;

#[derive(Clone, PartialEq, Eq)]
pub struct PeerEntry {
    key: [u8; KEY_BYTES],
    address: String,
}

impl PeerEntry {
    pub fn new(key: [u8; KEY_BYTES], address: impl Into<String>) -> Self {
        PeerEntry {
            key,
            address: address.into(),
        }
    }

    pub fn from_identity(identity: &Identity, address: impl Into<String>) -> Self {
        PeerEntry::new(*identity.public(), address)
    }

    pub fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public(&self.key)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        *self.peer_id().fingerprint()
    }
}

#[derive(Clone, Default)]
pub struct PeerTable {
    entries: BTreeMap<[u8; 32], PeerEntry>,
}

impl PeerTable {
    pub fn new() -> Self {
        PeerTable::default()
    }

    pub fn insert(&mut self, entry: PeerEntry) -> bool {
        let fingerprint = entry.fingerprint();
        if self.entries.contains_key(&fingerprint) {
            return false;
        }
        self.entries.insert(fingerprint, entry);
        true
    }

    pub fn merge(&mut self, other: &PeerTable) -> usize {
        let mut learned = 0;
        for entry in other.entries.values() {
            if self.insert(entry.clone()) {
                learned += 1;
            }
        }
        learned
    }

    pub fn contains(&self, fingerprint: &[u8; 32]) -> bool {
        self.entries.contains_key(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &PeerEntry> {
        self.entries.values()
    }

    pub fn fingerprints(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    #[test]
    fn an_entry_names_the_identity_it_authenticates_against() {
        let id = identity(1);
        let entry = PeerEntry::from_identity(&id, "mem://1");
        assert_eq!(entry.peer_id(), id.peer_id());
        assert_eq!(entry.fingerprint(), *id.peer_id().fingerprint());
        assert_eq!(entry.address(), "mem://1");
    }

    #[test]
    fn insert_reports_only_newly_learned_peers() {
        let mut table = PeerTable::new();
        let entry = PeerEntry::from_identity(&identity(1), "mem://1");
        assert!(table.insert(entry.clone()));
        assert!(!table.insert(entry));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn merge_folds_in_what_a_neighbor_reported() {
        let mut a = PeerTable::new();
        a.insert(PeerEntry::from_identity(&identity(1), "mem://1"));
        a.insert(PeerEntry::from_identity(&identity(2), "mem://2"));

        let mut b = PeerTable::new();
        b.insert(PeerEntry::from_identity(&identity(2), "mem://2"));
        b.insert(PeerEntry::from_identity(&identity(3), "mem://3"));

        assert_eq!(b.merge(&a), 1);
        assert_eq!(b.len(), 3);
        assert_eq!(b.merge(&a), 0);
    }

    #[test]
    fn the_ordering_is_a_function_of_the_set_not_the_insertion_order() {
        let mut a = PeerTable::new();
        for seed in [3u8, 1, 2] {
            a.insert(PeerEntry::from_identity(&identity(seed), "mem://x"));
        }
        let mut b = PeerTable::new();
        for seed in [2u8, 3, 1] {
            b.insert(PeerEntry::from_identity(&identity(seed), "mem://x"));
        }
        assert_eq!(a.fingerprints(), b.fingerprints());
    }
}
