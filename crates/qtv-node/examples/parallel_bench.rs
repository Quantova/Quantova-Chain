// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Execution throughput of the parallel executor against the sequential path.
//!
//! This measures the lever it exists to move: transactions executed per second
//! of wall clock. It runs a block of native transfers through the sequential
//! executor and through the parallel executor at the host core count, over an
//! independent workload where no two transactions share an account and over a
//! mixed workload where a share of transactions pay a small set of hot accounts
//! and so conflict. It prints the sequential and the parallel throughput and the
//! speedup for each, and it checks the two executors land on the identical state
//! root before it trusts a number, so the gain is measured against a run proven
//! bit identical to the sequential order.
//!
//! Two things are measured and reported apart. The full block execution is the
//! path the node runs: validate each transaction, which verifies its module
//! lattice signature, execute the transfer through the virtual machine, and write
//! the two accounts back. The virtual machine component is the transfer execution
//! alone, the roughly ten microseconds a transaction the reference benchmark
//! names, isolated so its own scaling across the cores is visible. The state root
//! is folded in once after execution, a serial step outside the parallel region,
//! and its cost is printed on its own rather than hidden inside a throughput.
//!
//! Run it in release for a real number:
//!   cargo run --release --example parallel_bench -p qtv-node
//! Optional arguments: transaction count, conflict percent, thread count.

use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use qtv_account::{derive, Account as KeyAccount};
use qtv_idfmt::render_address;
use qtv_node::execution::{execute_transfer, transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{Account, Ledger};
use qtv_node::node::execute_ordered;
use qtv_node::parallel::{execute_parallel, plan_layers};
use qtv_tx::{sign, Body, Wrapper};

const SEED: [u8; 32] = [42u8; 32];
/// The number of hot accounts a conflicting transfer pays into. A small set
/// keeps the conflicts real without collapsing the block to one long chain.
const HOT_ACCOUNTS: u64 = 256;
/// The starting balance of a sender, ample for a run of single transfers.
const SENDER_BALANCE: u64 = 1_000_000_000;
/// The throughput target the chain is built to clear, twenty five thousand transactions a second.
const TARGET_TPS: f64 = 25_000.0;

/// A small deterministic mixer so a workload is varied yet identical run to run.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(11400714819323198485);
    z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
    z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
    z ^ (z >> 31)
}

/// An address minted straight from a tagged payload, so a recipient exists to
/// pay without the cost of deriving a key it never signs with.
fn tagged_address(domain: u8, tag: u64) -> String {
    let mut payload = [0u8; 32];
    payload[0] = domain;
    payload[1..9].copy_from_slice(&tag.to_le_bytes());
    render_address(&payload).expect("a thirty two byte payload renders as an address")
}

/// Build `n` values across `threads` cores, returned in index order. Each worker
/// pulls the next index from a shared counter and returns its own results, which
/// merge and sort, so the build is parallel without any unsafe code.
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
    collected.into_iter().map(|(_, value)| value).collect()
}

/// The block for a workload: one transfer per sender at nonce zero. A conflict
/// percent of zero pays every transfer to a private recipient nobody else
/// touches, so the block is independent; a positive percent sends that share to
/// a hot account, a write write conflict several transfers share.
fn build_block(
    senders: &[KeyAccount],
    conflict_percent: u64,
    fee: &FeeParams,
    threads: usize,
) -> Vec<Wrapper> {
    let fee_amount = u128::from(fee.transfer_fee());
    parallel_build(senders.len(), threads, |i| {
        let roll = mix(i as u64) % 100;
        let recipient = if roll < conflict_percent {
            tagged_address(192, mix(i as u64 ^ 23130) % HOT_ACCOUNTS)
        } else {
            tagged_address(1, i as u64)
        };
        let call = transfer_call(&recipient, 100);
        let body = Body::new(senders[i].address(), 0, TRANSFER_METER, fee_amount, call);
        sign(&senders[i], &body)
    })
}

/// The median of a set of samples, the throughput figure reported so a single
/// noisy run does not set the number.
fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a timing"));
    samples[samples.len() / 2]
}

/// Time the sequential and the parallel full block execution and return their
/// throughput in transactions a second. The clone of the base ledger and the
/// state root fold sit outside the timed region, so the figure is execution
/// alone. The two runs are checked to land on the identical root first.
fn measure_full(base: &Ledger, block: &[Wrapper], fee: &FeeParams, threads: usize) -> (f64, f64) {
    let n = block.len() as f64;

    let mut sequential_root = None;
    let sequential: Vec<f64> = (0..5)
        .map(|_| {
            let mut ledger = base.clone();
            let start = Instant::now();
            let included = execute_ordered(&mut ledger, block, fee, 0);
            let elapsed = start.elapsed().as_secs_f64();
            black_box(&included);
            sequential_root = Some(ledger.state_root());
            n / elapsed
        })
        .collect();

    let mut parallel_root = None;
    let parallel: Vec<f64> = (0..5)
        .map(|_| {
            let mut ledger = base.clone();
            let start = Instant::now();
            let included = execute_parallel(&mut ledger, block, fee, threads, 0);
            let elapsed = start.elapsed().as_secs_f64();
            black_box(&included);
            parallel_root = Some(ledger.state_root());
            n / elapsed
        })
        .collect();

    assert_eq!(
        sequential_root, parallel_root,
        "the parallel executor must land on the sequential state root"
    );
    (median(sequential), median(parallel))
}

/// Time the virtual machine transfer alone, sequentially and across the cores,
/// over the independent inputs of the block. This is the execution component the
/// ten microsecond figure names, with no signature verification in it, so its own
/// scaling is visible apart from the rest of the path.
fn measure_vm(inputs: &[(u64, u64, u64, u64)], threads: usize) -> (f64, f64) {
    let n = inputs.len() as f64;

    let sequential: Vec<f64> = (0..5)
        .map(|_| {
            let start = Instant::now();
            let mut acc = 0u64;
            for &(sender, recipient, amount, fee) in inputs {
                let out = execute_transfer(sender, recipient, amount, fee, TRANSFER_METER)
                    .expect("a funded transfer runs clean");
                acc = acc.wrapping_add(out.sender_balance);
            }
            black_box(acc);
            n / start.elapsed().as_secs_f64()
        })
        .collect();

    let parallel: Vec<f64> = (0..5)
        .map(|_| {
            let next = AtomicUsize::new(0);
            let start = Instant::now();
            let mut total = 0u64;
            thread::scope(|scope| {
                let handles: Vec<_> = (0..threads.max(1))
                    .map(|_| {
                        scope.spawn(|| {
                            let mut acc = 0u64;
                            loop {
                                let i = next.fetch_add(1, Ordering::Relaxed);
                                if i >= inputs.len() {
                                    break;
                                }
                                let (sender, recipient, amount, fee) = inputs[i];
                                let out =
                                    execute_transfer(sender, recipient, amount, fee, TRANSFER_METER)
                                        .expect("a funded transfer runs clean");
                                acc = acc.wrapping_add(out.sender_balance);
                            }
                            acc
                        })
                    })
                    .collect();
                for handle in handles {
                    total = total.wrapping_add(handle.join().expect("a vm worker panicked"));
                }
            });
            black_box(total);
            n / start.elapsed().as_secs_f64()
        })
        .collect();

    (median(sequential), median(parallel))
}

fn row(label: &str, sequential: f64, parallel: f64) {
    println!(
        "  {label:<26} seq {:>10.0} tx/s   parallel {:>10.0} tx/s   speedup {:>5.2}x",
        sequential,
        parallel,
        parallel / sequential
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let conflict_percent: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(30);
    let cores = thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    let threads: usize = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(cores);

    let fee = FeeParams::devnet();

    // Build the senders and both workloads across the cores so setup does not
    // dominate the wall clock. Signing is the heavy part and it is pure, so it
    // parallelises cleanly.
    let senders: Vec<KeyAccount> = parallel_build(count, threads, |i| derive(&SEED, i as u64));
    let mut base = Ledger::new();
    for sender in &senders {
        base.set_account(
            &sender.address(),
            &Account::funded(
                SENDER_BALANCE,
                sender.scheme(),
                sender.public_key().to_vec(),
            ),
        );
    }
    // Warm the base root so a clone starts with the cache the node would hold.
    let _ = base.state_root();

    let independent = build_block(&senders, 0, &fee, threads);
    let mixed = build_block(&senders, conflict_percent, &fee, threads);

    // The virtual machine inputs for the independent block: each transfer debits a
    // funded sender and credits a fresh recipient.
    let fee_amount = fee.transfer_fee();
    let vm_inputs: Vec<(u64, u64, u64, u64)> = (0..count)
        .map(|_| (SENDER_BALANCE, 0u64, 100u64, fee_amount))
        .collect();

    let independent_layers = plan_layers(&independent).len();
    let mixed_layers = plan_layers(&mixed).len();

    println!("Quantova parallel execution throughput");
    println!(
        "reference host: {cores} physical cores, release build, {count} transactions, {threads} worker threads"
    );
    println!();

    println!(
        "full block execution (module lattice verify + virtual machine transfer + write back)"
    );
    let (seq, par_independent) = measure_full(&base, &independent, &fee, threads);
    row(
        &format!("independent ({independent_layers} layer)"),
        seq,
        par_independent,
    );
    let (seq, par) = measure_full(&base, &mixed, &fee, threads);
    row(
        &format!("mixed {conflict_percent}% conflict ({mixed_layers} layers)"),
        seq,
        par,
    );
    println!();

    // The enforced floor. A validator must execute across at least half its cores, so measure the
    // independent workload there too. That floor is the guaranteed throughput, the number a validator
    // can never fall below however it configures itself, not the best case at full cores.
    let floor_threads = (cores / 2).max(1);
    let (_, par_floor) = measure_full(&base, &independent, &fee, floor_threads);
    println!(
        "  {:<26} {:>10.0} tx/s   ({floor_threads} threads, the enforced minimum)",
        "independent at 50% cores", par_floor
    );
    println!();

    // The verdict against the target, so a rack run answers the question without arithmetic. The floor
    // line is the one that matters, it is the throughput the network is guaranteed at any validator.
    let verdict = |label: &str, tps: f64| {
        let met = if tps >= TARGET_TPS { "MEETS" } else { "BELOW" };
        println!("  {met} {TARGET_TPS:.0} tx/s target at {label}: {tps:.0} tx/s");
    };
    println!("against the {TARGET_TPS:.0} tx/s target");
    verdict(&format!("{threads} threads"), par_independent);
    verdict(&format!("the 50% core floor ({floor_threads} threads)"), par_floor);
    println!();

    println!("virtual machine execution component (transfer only, the ~10 us/tx figure)");
    let (seq, par) = measure_vm(&vm_inputs, threads);
    row("independent", seq, par);
    println!();

    // The serial cost of folding the post state into a root, printed on its own so
    // it is never mistaken for part of the parallel execution figure.
    let mut ledger = base.clone();
    let _ = execute_ordered(&mut ledger, &independent, &fee, 0);
    let mut samples = Vec::new();
    for _ in 0..5 {
        let mut probe = base.clone();
        let _ = execute_ordered(&mut probe, &independent, &fee, 0);
        let start = Instant::now();
        black_box(probe.state_root());
        samples.push(start.elapsed().as_secs_f64());
    }
    println!(
        "state root fold over {count} changed accounts: {:.3} ms (serial, outside the execution figure)",
        median(samples) * 1e3
    );
}
