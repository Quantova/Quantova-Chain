// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_account::{derive, Account as KeyAccount};
use qtv_node::execution::transfer_call;
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{Account, Ledger};
use qtv_node::node::execute_ordered;
use qtv_node::parallel::execute_parallel;
use qtv_tx::{sign, Body, Call, Wrapper};

const SEED: [u8; 32] = [77u8; 32];
static DEPLOYS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn rnd(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn tx(from: &KeyAccount, to: &str, amount: u64, nonce: u64, fee: u128) -> Wrapper {
    let body = Body::new(
        from.address(),
        nonce,
        qtv_node::execution::TRANSFER_METER,
        fee,
        transfer_call(to, amount),
    );
    sign(from, &body)
}

fn raw(from: &KeyAccount, to: &str, args: Vec<u8>, nonce: u64, fee: u128, meter: u64) -> Wrapper {
    let body = Body::new(
        from.address(),
        nonce,
        meter,
        fee,
        Call::new(to.to_string(), args),
    );
    sign(from, &body)
}

fn container() -> Vec<u8> {
    let code = qtv_vm::asm::assemble("LDI r1, 0\nMLOAD r0, r1\nLDI r2, 1\nSSTORE r2, r0\nHALT")
        .expect("the probe program assembles");
    let entry = qtv_vm::container::Entry {
        selector: qtv_vm::container::selector("bump()"),
        offset: 0,
        access: qtv_vm::container::StateAccess {
            reads: vec![1],
            writes: vec![1],
            keyed_reads: Vec::new(),
            keyed_writes: Vec::new(),
        },
    };
    qtv_vm::container::Container::new(code, Vec::new(), vec![entry]).canonical_bytes()
}

#[test]
fn ordered_and_parallel_agree_on_random_blocks() {
    let fee_params = FeeParams::devnet();
    let base_fee = u128::from(fee_params.transfer_fee());
    let keys: Vec<KeyAccount> = (0..12).map(|i| derive(&SEED, i)).collect();
    let systems = [
        qtv_node::ledger::stake_system_address(),
        qtv_node::ledger::stake_exit_address(),
        qtv_node::ledger::stake_withdraw_address(),
        qtv_node::ledger::stake_claim_address(),
        qtv_node::ledger::gov_system_address(),
        qtv_node::ledger::bridge_freeze_address(),
        qtv_node::ledger::bridge_unfreeze_address(),
        qtv_node::ledger::grants_address(),
    ];
    let fresh: Vec<String> = (100..108u64).map(|i| derive(&SEED, i).address()).collect();

    let mut state = 0x243f_6a88_85a3_08d3u64;
    for round in 0..300u32 {
        let mut base = Ledger::new();
        base.seed_supply(1_000_000_000);
        for (i, key) in keys.iter().enumerate() {
            let balance = match rnd(&mut state) % 5 {
                0 => 0,
                1 => u64::from(fee_params.transfer_fee()),
                2 => 1_000,
                3 => 50_000,
                _ => 5_000_000_000,
            };
            let _ = i;
            base.set_account(
                &key.address(),
                &Account::funded(balance, key.scheme(), key.public_key().to_vec()),
            );
        }
        if rnd(&mut state) % 4 == 0 {
            base.set_round_proposer(
                &keys[(rnd(&mut state) % keys.len() as u64) as usize].address(),
            );
        }

        let count = 1 + rnd(&mut state) % 24;
        let mut block: Vec<Wrapper> = Vec::new();
        let mut nonces = vec![0u64; keys.len()];
        let mut deployed: Vec<String> = Vec::new();
        for _ in 0..count {
            let s = (rnd(&mut state) % keys.len() as u64) as usize;
            let from = &keys[s];
            let to = match rnd(&mut state) % 8 {
                0 => fresh[(rnd(&mut state) % fresh.len() as u64) as usize].clone(),
                1 => systems[(rnd(&mut state) % systems.len() as u64) as usize].clone(),
                2 => from.address(),
                _ => keys[(rnd(&mut state) % keys.len() as u64) as usize].address(),
            };
            let amount = match rnd(&mut state) % 6 {
                0 => 0,
                1 => 1,
                2 => 1_000,
                3 => 4_999_999,
                4 => u64::MAX,
                _ => rnd(&mut state) % 100_000,
            };
            let nonce = match rnd(&mut state) % 8 {
                0 => nonces[s].saturating_sub(1),
                1 => nonces[s] + 1,
                _ => {
                    let n = nonces[s];
                    nonces[s] += 1;
                    n
                }
            };
            let fee = match rnd(&mut state) % 6 {
                0 => 0,
                1 => base_fee,
                2 => base_fee * 3,
                _ => base_fee,
            };
            let wrapper = match rnd(&mut state) % 6 {
                0 => {
                    if let Some(address) =
                        qtv_node::ledger::contract_address(&from.address(), nonce)
                    {
                        deployed.push(address);
                    }
                    raw(
                        from,
                        &qtv_node::ledger::vm_deploy_address(),
                        container(),
                        nonce,
                        5_000_000,
                        12_000_000,
                    )
                }
                1 if !deployed.is_empty() => {
                    let target =
                        deployed[(rnd(&mut state) % deployed.len() as u64) as usize].clone();
                    let mut args = qtv_vm::container::selector("bump()").to_vec();
                    args.extend_from_slice(&[7u8; 240]);
                    raw(from, &target, args, nonce, 5_000_000, 12_000_000)
                }
                2 => {
                    let mut junk = vec![0u8; (rnd(&mut state) % 40) as usize];
                    for b in junk.iter_mut() {
                        *b = (rnd(&mut state) & 0xff) as u8;
                    }
                    raw(
                        from,
                        &to,
                        junk,
                        nonce,
                        fee,
                        qtv_node::execution::TRANSFER_METER,
                    )
                }
                _ => tx(from, &to, amount, nonce, fee),
            };
            if rnd(&mut state) % 10 == 0 {
                block.push(wrapper.clone());
            }
            block.push(wrapper);
        }

        let mut sequential = base.clone();
        let ordered = execute_ordered(&mut sequential, &block, &fee_params, 0);
        for w in &ordered {
            if w.body().call().target() == qtv_node::ledger::vm_deploy_address() {
                DEPLOYS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else if w.body().meter_limit() > qtv_node::execution::TRANSFER_METER {
                CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        for threads in [1usize, 2, 4, 8] {
            let mut parallel = base.clone();
            let par = execute_parallel(&mut parallel, &block, &fee_params, threads, 0);
            assert_eq!(
                sequential.q_root(),
                parallel.q_root(),
                "round {round} threads {threads} state root differs"
            );
            let a: Vec<String> = ordered.iter().map(Wrapper::id).collect();
            let b: Vec<String> = par.iter().map(Wrapper::id).collect();
            assert_eq!(a, b, "round {round} threads {threads} included set differs");
        }
    }
    assert!(
        DEPLOYS.load(std::sync::atomic::Ordering::Relaxed) > 20,
        "the sweep must reach the deploy path"
    );
    assert!(
        CALLS.load(std::sync::atomic::Ordering::Relaxed) > 5,
        "the sweep must reach the contract call path"
    );
}
