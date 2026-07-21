
use std::collections::BTreeSet;

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

#[derive(Clone, Default)]
pub struct Seen {
    ids: BTreeSet<[u8; 32]>,
}

impl Seen {
    pub fn new() -> Self {
        Seen::default()
    }

    pub fn mark(&mut self, id: [u8; 32]) -> bool {
        self.ids.insert(id)
    }

    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.ids.contains(id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
