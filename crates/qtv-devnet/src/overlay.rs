//! The bounded gossip overlay: which neighbors a node relays to, and the record of
//! messages it has already seen.
//!
//! A node keeps a bounded set of neighbors rather than a link to every node. The
//! neighbors are drawn as a ring lattice over the peers ordered by identity
//! fingerprint: a node at ring position `p` links to the nearest positions on
//! either side, up to a fanout. Every node links to its ring successor, so the
//! union of all neighbor sets always contains a Hamiltonian ring and the overlay
//! is connected whatever the fanout. A connected overlay of bounded degree has a
//! bounded diameter, so a message from any node reaches every node in a bounded
//! number of hops.
//!
//! A node relays a gossip message to its neighbors, but only the first time it
//! sees it. The seen record, keyed by the message's content id, is what makes the
//! relay terminate: a message that arrives a second time by another path is not
//! relayed again, so it is never double counted and a relay loop cannot form.

use std::collections::BTreeSet;

/// The ring positions a node at `pos` links to, in a ring of `n` positions, up to
/// `fanout` neighbors. Neighbors are taken nearest first, alternating the
/// successor and predecessor side, so a fanout of one is the directed ring, a
/// fanout of two is the undirected ring, and a larger fanout adds the next nearest
/// chords. The successor is always included when the fanout is at least one, which
/// is what keeps the union connected.
pub fn ring_neighbors(pos: usize, n: usize, fanout: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if n <= 1 {
        return out;
    }
    let cap = fanout.min(n - 1);
    let mut step = 1usize;
    while out.len() < cap {
        let successor = (pos + step) % n;
        if successor != pos && !out.contains(&successor) {
            out.push(successor);
            if out.len() == cap {
                break;
            }
        }
        let predecessor = (pos + n - step) % n;
        if predecessor != pos && !out.contains(&predecessor) {
            out.push(predecessor);
            if out.len() == cap {
                break;
            }
        }
        step += 1;
    }
    out
}

/// The undirected neighbor sets of a ring lattice over `n` positions at the given
/// fanout. An edge is present when either endpoint selects the other, so the graph
/// is symmetric and a channel serves both directions. The degree is bounded by
/// twice the fanout, well below the `n - 1` of a full mesh.
pub fn ring_lattice(n: usize, fanout: usize) -> Vec<Vec<usize>> {
    let mut sets: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for pos in 0..n {
        for other in ring_neighbors(pos, n, fanout) {
            sets[pos].insert(other);
            sets[other].insert(pos);
        }
    }
    sets.into_iter().map(|s| s.into_iter().collect()).collect()
}

/// A node's record of the gossip messages it has already seen, so each is relayed
/// at most once and a relay cannot loop.
#[derive(Clone, Default)]
pub struct Seen {
    ids: BTreeSet<[u8; 32]>,
}

impl Seen {
    /// An empty record.
    pub fn new() -> Self {
        Seen::default()
    }

    /// Mark a message id seen, returning whether it was new. A false return is a
    /// duplicate: the node has already relayed and acted on this message, so it
    /// must neither relay nor count it again.
    pub fn mark(&mut self, id: [u8; 32]) -> bool {
        self.ids.insert(id)
    }

    /// Whether a message id has already been seen.
    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.ids.contains(id)
    }

    /// The number of distinct messages seen.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether nothing has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether an undirected adjacency is connected, by a walk from node zero.
    fn is_connected(adjacency: &[Vec<usize>]) -> bool {
        let n = adjacency.len();
        if n == 0 {
            return true;
        }
        let mut reached = vec![false; n];
        let mut stack = vec![0usize];
        reached[0] = true;
        let mut count = 1;
        while let Some(node) = stack.pop() {
            for &next in &adjacency[node] {
                if !reached[next] {
                    reached[next] = true;
                    count += 1;
                    stack.push(next);
                }
            }
        }
        count == n
    }

    #[test]
    fn neighbors_are_bounded_by_the_fanout() {
        for n in 2..12 {
            for fanout in 1..6 {
                let neighbors = ring_neighbors(3 % n, n, fanout);
                assert!(neighbors.len() <= fanout.min(n - 1));
                assert!(!neighbors.contains(&(3 % n)));
            }
        }
    }

    #[test]
    fn the_ring_lattice_is_connected_at_every_fanout() {
        for n in 1..16 {
            for fanout in 1..5 {
                let lattice = ring_lattice(n, fanout);
                assert!(
                    is_connected(&lattice),
                    "n {n} fanout {fanout} was not connected"
                );
            }
        }
    }

    #[test]
    fn a_small_fanout_stays_well_below_a_full_mesh() {
        let n = 12;
        let lattice = ring_lattice(n, 2);
        let degree = lattice.iter().map(Vec::len).max().unwrap();
        // A full mesh would be n - 1 neighbors each; the ring stays at the fanout.
        assert!(degree <= 4, "degree {degree} was not bounded");
        assert!(degree < n - 1);
    }

    #[test]
    fn the_lattice_is_symmetric() {
        let lattice = ring_lattice(9, 3);
        for (node, neighbors) in lattice.iter().enumerate() {
            for &other in neighbors {
                assert!(
                    lattice[other].contains(&node),
                    "edge {node}-{other} was not symmetric"
                );
            }
        }
    }

    #[test]
    fn the_seen_record_reports_a_duplicate_once() {
        let mut seen = Seen::new();
        let id = [7u8; 32];
        assert!(seen.mark(id));
        assert!(!seen.mark(id));
        assert!(seen.contains(&id));
        assert_eq!(seen.len(), 1);
    }
}
