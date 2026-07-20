//! Signature verification throughput. This is the piece that decides whether the block path is
//! verify bound or state bound. It builds signed transfers, then verifies them across the cores and
//! reports the verifies a second, sequential and parallel. Set beside the pure virtual machine figure
//! and the full block figure, it says which half of the path to parallelise to reach the target: if
//! parallel verify sits far above the target then verify is not the ceiling and the state trie is, if
//! it sits at or below the target then verification itself needs aggregation or a faster scheme.
//!
//! Run it in release:
//!   cargo run --release --example verify_bench -p qtv-node
//! Arguments: signature count (default 100000), threads (default all cores).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use qtv_account::{derive, Account as KeyAccount};
use qtv_idfmt::render_address;
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_tx::{sign, verify, Body, Wrapper};

const SEED: [u8; 32] = [42u8; 32];
const TARGET_TPS: f64 = 25_000.0;

fn parallel_build<T, F>(n: usize, threads: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    let next = AtomicUsize::new(0);
    let mut collected: Vec<(usize, T)> = Vec::with_capacity(n);
    thread::scope(|scope| {
        let handles: Vec<_> = (0..threads.max(1))
            .map(|_| {
                scope.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= n {
                            break;
                        }
                        local.push((i, f(i)));
                    }
                    local
                })
            })
            .collect();
        for handle in handles {
            collected.extend(handle.join().expect("a build worker panicked"));
        }
    });
    collected.sort_by_key(|(i, _)| *i);
    collected.into_iter().map(|(_, v)| v).collect()
}

fn tagged_address(domain: u8, tag: u64) -> String {
    let mut payload = [0u8; 32];
    payload[0] = domain;
    payload[1..9].copy_from_slice(&tag.to_le_bytes());
    render_address(&payload).expect("a thirty two byte payload renders as an address")
}

fn median(mut s: Vec<f64>) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    s[s.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let cores = thread::available_parallelism().map(|p| p.get()).unwrap_or(1);
    let threads: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(cores);

    let fee = FeeParams::devnet();
    let fee_amount = u128::from(fee.transfer_fee());

    let senders: Vec<KeyAccount> = parallel_build(count, threads, |i| derive(&SEED, i as u64));
    // Signed transfers paired with the signer public key the verifier checks against.
    let signed: Vec<(Wrapper, Vec<u8>)> = parallel_build(count, threads, |i| {
        let recipient = tagged_address(1, i as u64);
        let call = transfer_call(&recipient, 100);
        let body = Body::new(senders[i].address(), 0, TRANSFER_METER, fee_amount, call);
        (sign(&senders[i], &body), senders[i].public_key().to_vec())
    });

    // Sequential verify, the per core figure.
    let seq: Vec<f64> = (0..3)
        .map(|_| {
            let start = Instant::now();
            let mut ok = 0usize;
            for (w, pk) in &signed {
                if verify(w, pk) {
                    ok += 1;
                }
            }
            assert_eq!(ok, signed.len(), "every signature verifies");
            count as f64 / start.elapsed().as_secs_f64()
        })
        .collect();

    // Parallel verify across the cores.
    let par: Vec<f64> = (0..5)
        .map(|_| {
            let next = AtomicUsize::new(0);
            let start = Instant::now();
            let ok = thread::scope(|scope| {
                let handles: Vec<_> = (0..threads.max(1))
                    .map(|_| {
                        scope.spawn(|| {
                            let mut ok = 0usize;
                            loop {
                                let i = next.fetch_add(1, Ordering::Relaxed);
                                if i >= signed.len() {
                                    break;
                                }
                                if verify(&signed[i].0, &signed[i].1) {
                                    ok += 1;
                                }
                            }
                            ok
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().expect("verify worker panicked")).sum::<usize>()
            });
            assert_eq!(ok, signed.len(), "every signature verifies");
            count as f64 / start.elapsed().as_secs_f64()
        })
        .collect();

    let vseq = median(seq);
    let vpar = median(par);
    println!("Signature verification throughput, {count} signatures, {threads} of {cores} cores");
    println!("  sequential, one core : {vseq:>10.0} verify/s");
    println!("  parallel, {threads} cores  : {vpar:>10.0} verify/s   speedup {:.1}x", vpar / vseq);
    if vpar >= TARGET_TPS {
        println!(
            "  parallel verify {vpar:.0} is ABOVE the {TARGET_TPS:.0} target, so verification is not the ceiling, the serial state trie is what caps the block path"
        );
    } else {
        println!(
            "  parallel verify {vpar:.0} is at or below the {TARGET_TPS:.0} target, so verification itself is a ceiling and needs aggregation or a faster scheme"
        );
    }
}
