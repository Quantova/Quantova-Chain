//! Sustained execution throughput. This answers one question, the maximum transactions a second the
//! node can hold constantly, not for a single burst. It builds one workload of independent transfers,
//! then executes it in a tight loop for a set duration, recording the throughput of every round. It
//! reports running figures as it goes and a final summary, the floor being the number the node holds
//! essentially all the time, which is the honest maximum a validator can rely on.
//!
//! Each round is a full block execute, module lattice signature verify, virtual machine transfer, and
//! account write back, the exact path the node runs. The clone of the base ledger sits outside the
//! timed region so the figure is execution alone. The parallel executor is checked against the
//! sequential state root once before any number is trusted.
//!
//! Run it in release on a validator class machine:
//!   cargo run --release --example sustained_tps -p qtv-node
//! Arguments: transactions per round (default 100000), duration seconds (default 3600), threads
//! (default all cores).

use std::hint::black_box;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use qtv_account::{derive, Account as KeyAccount};
use qtv_idfmt::render_address;
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{Account, Ledger};
use qtv_node::node::execute_ordered;
use qtv_node::parallel::execute_parallel;
use qtv_tx::{sign, Body, Wrapper};

const SEED: [u8; 32] = [42u8; 32];
const SENDER_BALANCE: u64 = 1_000_000_000;
/// The throughput target the chain is built to clear.
const TARGET_TPS: f64 = 25_000.0;

/// Build `n` values across `threads` cores, returned in index order.
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

/// An address minted straight from a tagged payload, a recipient that exists to pay.
fn tagged_address(domain: u8, tag: u64) -> String {
    let mut payload = [0u8; 32];
    payload[0] = domain;
    payload[1..9].copy_from_slice(&tag.to_le_bytes());
    render_address(&payload).expect("a thirty two byte payload renders as an address")
}

/// A block of independent transfers, each from a funded sender to a fresh recipient, so no two
/// transactions share an account and the executor runs at full width.
fn build_block(senders: &[KeyAccount], fee: &FeeParams, threads: usize) -> Vec<Wrapper> {
    let fee_amount = u128::from(fee.transfer_fee());
    parallel_build(senders.len(), threads, |i| {
        let recipient = tagged_address(1, i as u64);
        let call = transfer_call(&recipient, 100);
        let body = Body::new(senders[i].address(), 0, TRANSFER_METER, fee_amount, call);
        sign(&senders[i], &body)
    })
}

/// The min, fifth percentile, median, and max of a set of throughput samples.
fn stats(samples: &[f64]) -> (f64, f64, f64, f64) {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a timing"));
    let min = s[0];
    let max = s[s.len() - 1];
    let median = s[s.len() / 2];
    let p5 = s[((s.len() as f64) * 0.05) as usize];
    (min, p5, median, max)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let duration_secs: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(3600);
    let cores = thread::available_parallelism().map(|p| p.get()).unwrap_or(1);
    let threads: usize = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(cores);

    let fee = FeeParams::devnet();

    // Build the workload once, across the cores so setup does not dominate.
    let senders: Vec<KeyAccount> = parallel_build(count, threads, |i| derive(&SEED, i as u64));
    let mut base = Ledger::new();
    for sender in &senders {
        base.set_account(
            &sender.address(),
            &Account::funded(SENDER_BALANCE, sender.scheme(), sender.public_key().to_vec()),
        );
    }
    let _ = base.state_root();
    let block = build_block(&senders, &fee, threads);

    // Trust the number only after the parallel executor is proven to match the sequential root.
    {
        let mut a = base.clone();
        let _ = execute_ordered(&mut a, &block, &fee, 0);
        let mut b = base.clone();
        let _ = execute_parallel(&mut b, &block, &fee, threads, 0);
        assert_eq!(
            a.state_root(),
            b.state_root(),
            "the parallel executor must match the sequential state root before any number is trusted"
        );
    }

    println!(
        "Sustained execution throughput, {count} independent transfers a round, {threads} of {cores} cores, holding for {duration_secs}s"
    );
    println!("each round is a full block execute, module lattice verify plus virtual machine transfer plus write back");
    println!("samples every 30s, the p5 floor is the number held constantly");
    let _ = std::io::stdout().flush();

    let start = Instant::now();
    let end = start + Duration::from_secs(duration_secs);
    let mut samples: Vec<f64> = Vec::new();
    let mut last_report = start;
    let mut rounds: u64 = 0;

    while Instant::now() < end {
        let mut ledger = base.clone();
        let t = Instant::now();
        let included = execute_parallel(&mut ledger, &block, &fee, threads, 0);
        let dt = t.elapsed().as_secs_f64();
        black_box(&included);
        rounds += 1;
        samples.push(count as f64 / dt);

        if last_report.elapsed().as_secs() >= 30 {
            let (mn, p5, md, mx) = stats(&samples);
            println!(
                "[{:>6.0}s] rounds {:>6}  now {:>9.0}  min {:>9.0}  p5 {:>9.0}  median {:>9.0}  max {:>9.0} tx/s",
                start.elapsed().as_secs_f64(),
                rounds,
                samples.last().copied().unwrap_or(0.0),
                mn,
                p5,
                md,
                mx
            );
            let _ = std::io::stdout().flush();
            last_report = Instant::now();
        }
    }

    let (mn, p5, md, mx) = stats(&samples);
    let held = p5;
    let verdict = if held >= TARGET_TPS { "HOLDS ABOVE" } else { "BELOW" };
    println!();
    println!(
        "SUSTAINED over {duration_secs}s, {rounds} rounds: min {mn:.0}  p5 {p5:.0}  median {md:.0}  max {mx:.0} tx/s"
    );
    println!(
        "the maximum held constantly (p5 floor) is {held:.0} tx/s, {verdict} the {TARGET_TPS:.0} target"
    );
    let _ = std::io::stdout().flush();
}
