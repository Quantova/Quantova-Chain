//! A measurement of the state root update cost.
//!
//! It times a full recompute over the whole trie at several sizes, then times an
//! incremental update for a range of changed account counts at a small state and
//! at a large state. The full recompute scales with the total number of accounts,
//! while the incremental update scales with the number of changed accounts and the
//! tree depth and does not move with the total state. From the two it projects the
//! per block cost at one million accounts.
//!
//! Run it in release so the hashes are optimized:
//!
//!   cargo run --release --example scaling -p qtv-state

use std::time::{Duration, Instant};

use qtv_state::{Key, Trie, DEPTH, KEY_LEN};

/// A small deterministic generator, splitmix64, so the states and the change sets
/// are varied but the run is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(11400714819323198485);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
        z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
        z ^ (z >> 31)
    }

    fn key(&mut self) -> Key {
        let mut key = [0u8; KEY_LEN];
        for chunk in key.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        key
    }
}

/// An account sized value, thirty two bytes, the shape a nonce, a balance, a
/// scheme byte and a short key take once encoded.
fn value(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for _ in 0..4 {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out
}

/// A trie loaded with `count` random accounts, along with its keys, before the
/// first root is taken.
fn build(count: usize, rng: &mut Rng) -> (Trie, Vec<Key>) {
    let mut trie = Trie::new();
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let key = rng.key();
        trie.insert(key, value(rng));
        keys.push(key);
    }
    (trie, keys)
}

fn micros_per(total: Duration, n: usize) -> f64 {
    total.as_secs_f64() * 1e6 / n as f64
}

fn main() {
    println!("depth {} levels, sha3 256\n", DEPTH);

    // A full recompute over the whole trie at three sizes. The per account cost is
    // flat, which is the linear in total state behaviour that breaks at scale.
    println!("full recompute over the whole state");
    let mut full_us_per_account = 0.0;
    for &count in &[2_000usize, 20_000, 200_000] {
        let mut rng = Rng(4369 ^ count as u64);
        let (trie, _keys) = build(count, &mut rng);
        let start = Instant::now();
        let _ = trie.root();
        let elapsed = start.elapsed();
        let per = micros_per(elapsed, count);
        full_us_per_account = per;
        println!(
            "  N = {count:>7}   {:>10.3} ms total   {per:>8.3} us/account",
            elapsed.as_secs_f64() * 1e3
        );
    }

    // An incremental update at a small state and a large state, over a range of
    // changed account counts. Each figure is the average over several blocks. The
    // per changed account cost is the same at both state sizes, so the block cost
    // follows the changed count and the depth, not the total state.
    println!("\nincremental root update, average over 24 blocks");
    println!("  N        B        block          per changed account");
    let changed_counts = [1usize, 8, 64, 256, 1024];
    let mut incremental_block_at_large_b64 = Duration::ZERO;
    for &count in &[2_000usize, 200_000] {
        let mut rng = Rng(8738 ^ count as u64);
        let (mut trie, keys) = build(count, &mut rng);
        let _ = trie.root(); // commit the whole state once, up front
        for &batch in &changed_counts {
            if batch > keys.len() {
                continue;
            }
            let blocks = 24;
            let mut total = Duration::ZERO;
            for _ in 0..blocks {
                for _ in 0..batch {
                    let key = keys[(rng.next() as usize) % keys.len()];
                    trie.insert(key, value(&mut rng));
                }
                let start = Instant::now();
                let _ = trie.root();
                total += start.elapsed();
            }
            let per_block = total / blocks;
            if count == 200_000 && batch == 64 {
                incremental_block_at_large_b64 = per_block;
            }
            println!(
                "  {count:>7}  {batch:>5}   {:>9.3} ms   {:>8.2} us/account",
                per_block.as_secs_f64() * 1e3,
                micros_per(per_block, batch)
            );
        }
    }

    // The projection to one million accounts. The full recompute grows with the
    // state, the incremental block does not.
    let projected_full_ms = full_us_per_account * 1_000_000.0 / 1e3;
    println!("\nprojected at one million accounts");
    println!(
        "  full recompute per block   {:>10.1} ms   ({:.1} s)",
        projected_full_ms,
        projected_full_ms / 1e3
    );
    println!(
        "  incremental block, 64 changed accounts   {:>7.3} ms   (flat in total state)",
        incremental_block_at_large_b64.as_secs_f64() * 1e3
    );
    let speedup = projected_full_ms / (incremental_block_at_large_b64.as_secs_f64() * 1e3);
    println!("  speedup at one million accounts   {speedup:>8.0}x");
}
