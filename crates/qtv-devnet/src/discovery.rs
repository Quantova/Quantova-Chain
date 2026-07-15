//! Peer discovery: how a node learns the rest of the network from a small set of
//! bootstrap peers.
//!
//! A node starts knowing only itself and its bootstrap peers. It exchanges its
//! known peer set with them over a qtv-net channel and merges what it receives,
//! and after a few rounds of exchange over a connected bootstrap graph every node
//! knows every peer. The operator wires only the bootstrap edges, not every pair.
//!
//! A peer entry carries the network identity and the address, nothing else. The
//! network identity is the ML-DSA public key, whose SHA3-256 fingerprint keys the
//! table and orders it, so two nodes that learned the same peers hold byte
//! identical tables. A learned entry is only a claim until a channel to it
//! completes the pinned qtv-net handshake: the handshake authenticates the peer
//! against the very public key in the entry, so a peer that cannot prove the
//! identity is refused and never trusted.

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES;
use qtv_net::{Identity, PeerId};

/// The length of a network identity public key, an ML-DSA public key.
pub const KEY_BYTES: usize = PUBLIC_KEY_BYTES;

/// A discovered peer: its network identity public key and the address a node
/// dials to reach it. The identity is authenticated by the pinned handshake when
/// a channel to the peer is established, so the address alone grants no trust.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerEntry {
    key: [u8; KEY_BYTES],
    address: String,
}

impl PeerEntry {
    /// A peer entry from a raw public key and an address.
    pub fn new(key: [u8; KEY_BYTES], address: impl Into<String>) -> Self {
        PeerEntry {
            key,
            address: address.into(),
        }
    }

    /// A peer entry naming a known identity at an address.
    pub fn from_identity(identity: &Identity, address: impl Into<String>) -> Self {
        PeerEntry::new(*identity.public(), address)
    }

    /// The network identity public key.
    pub fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }

    /// The address a node dials to reach this peer.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The peer identity a channel to this peer is pinned to.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public(&self.key)
    }

    /// The SHA3-256 fingerprint of the identity, the key that orders the table.
    pub fn fingerprint(&self) -> [u8; 32] {
        *self.peer_id().fingerprint()
    }
}

/// A node's view of the network: the peers it has discovered, keyed and ordered by
/// identity fingerprint so the ordering is a deterministic function of the set.
#[derive(Clone, Default)]
pub struct PeerTable {
    entries: BTreeMap<[u8; 32], PeerEntry>,
}

impl PeerTable {
    /// An empty table.
    pub fn new() -> Self {
        PeerTable::default()
    }

    /// Insert an entry, returning whether the peer was newly learned. A peer
    /// already in the table is left as it is, so re-learning it is a no-op.
    pub fn insert(&mut self, entry: PeerEntry) -> bool {
        let fingerprint = entry.fingerprint();
        if self.entries.contains_key(&fingerprint) {
            return false;
        }
        self.entries.insert(fingerprint, entry);
        true
    }

    /// Merge another view into this one, returning how many peers were newly
    /// learned. This is the exchange step of discovery: a node folds in the peers
    /// a neighbor reported and counts what it did not already know.
    pub fn merge(&mut self, other: &PeerTable) -> usize {
        let mut learned = 0;
        for entry in other.entries.values() {
            if self.insert(entry.clone()) {
                learned += 1;
            }
        }
        learned
    }

    /// Whether the table holds a peer with this fingerprint.
    pub fn contains(&self, fingerprint: &[u8; 32]) -> bool {
        self.entries.contains_key(fingerprint)
    }

    /// The number of peers known.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The known peers in fingerprint order.
    pub fn entries(&self) -> impl Iterator<Item = &PeerEntry> {
        self.entries.values()
    }

    /// The known fingerprints in order, the ring the overlay is drawn over.
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

        // b learns only peer 1 from a; peer 2 was already known.
        assert_eq!(b.merge(&a), 1);
        assert_eq!(b.len(), 3);
        // A second merge learns nothing new, so discovery reaches a fixpoint.
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
