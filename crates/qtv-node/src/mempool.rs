
use std::thread;

use qtv_tx::Wrapper;

use crate::execution::{transfer_amount, TRANSFER_METER};
use crate::fee::FeeParams;
use crate::ledger::{Account, Ledger};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    UnknownSender,
    UnsupportedScheme,
    BadSignature,
    BadNonce { expected: u64, got: u64 },
    BadCall,
    SelfTransfer,
    MeterLimitTooLow,
    FeeTooLow,
    InsufficientFunds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    Fresh,
    Known,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
}

pub fn validate(
    wrapper: &Wrapper,
    ledger: &Ledger,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    let sender = ledger.account(wrapper.body().sender());
    plan_from_account(wrapper, &sender, fee_params)
}

pub fn validate_verified(
    wrapper: &Wrapper,
    ledger: &Ledger,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> Result<TransferPlan, Reject> {
    let sender = ledger.account(wrapper.body().sender());
    plan_verified(wrapper, &sender, fee_params, signature_ok)
}

pub fn plan_from_account(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    if !account.has_key() {
        return Err(Reject::UnknownSender);
    }
    if !qtv_tx::scheme_supported(wrapper.scheme()) {
        return Err(Reject::UnsupportedScheme);
    }
    if !qtv_tx::verify(wrapper, &account.public_key) {
        return Err(Reject::BadSignature);
    }
    plan_from_account_checks(wrapper, account, fee_params)
}

pub fn plan_verified(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
    signature_ok: bool,
) -> Result<TransferPlan, Reject> {
    if !qtv_tx::scheme_supported(wrapper.scheme()) {
        return Err(Reject::UnsupportedScheme);
    }
    if !signature_ok {
        return Err(Reject::BadSignature);
    }
    plan_from_account_checks(wrapper, account, fee_params)
}

fn plan_from_account_checks(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    let body = wrapper.body();
    let sender = body.sender().to_string();

    if body.nonce() != account.nonce {
        return Err(Reject::BadNonce {
            expected: account.nonce,
            got: body.nonce(),
        });
    }

    let amount = transfer_amount(body.call()).ok_or(Reject::BadCall)?;
    let recipient = body.call().target().to_string();
    if qtv_idfmt::parse_address(&recipient).is_err() {
        return Err(Reject::BadCall);
    }
    if recipient == sender {
        return Err(Reject::SelfTransfer);
    }
    if body.meter_limit() < TRANSFER_METER {
        return Err(Reject::MeterLimitTooLow);
    }

    let floor = fee_params.transfer_fee();
    if body.fee() < u128::from(floor) {
        return Err(Reject::FeeTooLow);
    }
    let ceiling = fee_params.ceiling_fee();
    let charged = u64::try_from(body.fee().min(u128::from(ceiling))).unwrap_or(ceiling);
    let debit = amount.checked_add(charged).ok_or(Reject::InsufficientFunds)?;
    if account.balance < debit {
        return Err(Reject::InsufficientFunds);
    }

    Ok(TransferPlan {
        sender,
        recipient,
        amount,
        fee: charged,
    })
}

const PARALLEL_VERIFY_THRESHOLD: usize = 4;

fn verify_signatures(ledger: &Ledger, batch: &[Wrapper], verify_cores: usize) -> Vec<bool> {
    let keys: Vec<Vec<u8>> = batch
        .iter()
        .map(|wrapper| ledger.account(wrapper.body().sender()).public_key)
        .collect();

    let mut verdicts = vec![false; batch.len()];
    let cores = verify_cores.min(batch.len());

    if cores <= 1 || batch.len() < PARALLEL_VERIFY_THRESHOLD {
        for (verdict, (wrapper, key)) in verdicts.iter_mut().zip(batch.iter().zip(&keys)) {
            *verdict = qtv_tx::verify(wrapper, key);
        }
        return verdicts;
    }

    let chunk = batch.len().div_ceil(cores);
    thread::scope(|scope| {
        for ((verdict_chunk, wrapper_chunk), key_chunk) in verdicts
            .chunks_mut(chunk)
            .zip(batch.chunks(chunk))
            .zip(keys.chunks(chunk))
        {
            scope.spawn(move || {
                for (verdict, (wrapper, key)) in verdict_chunk
                    .iter_mut()
                    .zip(wrapper_chunk.iter().zip(key_chunk))
                {
                    *verdict = qtv_tx::verify(wrapper, key);
                }
            });
        }
    });

    verdicts
}

const CONTRACTS_ENABLED: bool = true;

#[derive(Debug, Clone, Default)]
pub struct Mempool {
    pending: Vec<Wrapper>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            pending: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.pending.iter().any(|w| w.id() == id)
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn admit(
        &mut self,
        wrapper: Wrapper,
        ledger: &Ledger,
        fee_params: &FeeParams,
    ) -> Result<Admitted, Reject> {
        if crate::node::is_vm_op(ledger, &wrapper) {
            if !CONTRACTS_ENABLED {
                return Err(Reject::BadCall);
            }
            let account = ledger.account(wrapper.body().sender());
            let signature_ok = qtv_tx::verify(&wrapper, &account.public_key);
            if !crate::node::vm_admissible(&wrapper, &account, fee_params, signature_ok) {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_key_register(&wrapper) {
            let account = ledger.account(wrapper.body().sender());
            if crate::node::key_register_admissible(&wrapper, &account, fee_params).is_none() {
                return Err(Reject::BadCall);
            }
        } else if wrapper.body().call().target() == crate::ledger::gov_system_address() {
            let account = ledger.account(wrapper.body().sender());
            let signature_ok = qtv_tx::verify(&wrapper, &account.public_key);
            if crate::node::governance_admissible(&wrapper, &account, fee_params, signature_ok)
                .is_none()
            {
                return Err(Reject::BadCall);
            }
        } else {
            validate(&wrapper, ledger, fee_params)?;
        }
        let id = wrapper.id();
        if self.pending.iter().any(|w| w.id() == id) {
            return Ok(Admitted::Known);
        }
        self.pending.push(wrapper);
        Ok(Admitted::Fresh)
    }

    pub fn admit_batch(
        &mut self,
        batch: Vec<Wrapper>,
        ledger: &Ledger,
        fee_params: &FeeParams,
    ) -> Vec<Wrapper> {
        let cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        self.admit_batch_across(batch, ledger, fee_params, cores)
    }

    fn admit_batch_across(
        &mut self,
        batch: Vec<Wrapper>,
        ledger: &Ledger,
        fee_params: &FeeParams,
        verify_cores: usize,
    ) -> Vec<Wrapper> {
        let verified = verify_signatures(ledger, &batch, verify_cores);
        let mut admitted = Vec::new();
        for (index, wrapper) in batch.into_iter().enumerate() {
            let admissible = if crate::node::is_vm_op(ledger, &wrapper) {
                if !CONTRACTS_ENABLED {
                    false
                } else {
                    let account = ledger.account(wrapper.body().sender());
                    crate::node::vm_admissible(&wrapper, &account, fee_params, verified[index])
                }
            } else if crate::node::is_key_register(&wrapper) {
                let account = ledger.account(wrapper.body().sender());
                crate::node::key_register_admissible(&wrapper, &account, fee_params).is_some()
            } else if wrapper.body().call().target() == crate::ledger::gov_system_address() {
                let account = ledger.account(wrapper.body().sender());
                crate::node::governance_admissible(&wrapper, &account, fee_params, verified[index])
                    .is_some()
            } else {
                validate_verified(&wrapper, ledger, fee_params, verified[index]).is_ok()
            };
            if !admissible {
                continue;
            }
            let id = wrapper.id();
            if self.pending.iter().any(|w| w.id() == id) {
                continue;
            }
            self.pending.push(wrapper.clone());
            admitted.push(wrapper);
        }
        admitted
    }

    pub fn candidates(&self) -> Vec<Wrapper> {
        let mut ordered = self.pending.clone();
        ordered.sort_by(|a, b| {
            b.body()
                .fee()
                .cmp(&a.body().fee())
                .then_with(|| a.body().sender().cmp(b.body().sender()))
                .then_with(|| a.body().nonce().cmp(&b.body().nonce()))
        });
        ordered
    }

    pub fn remove_included(&mut self, ids: &[String]) {
        self.pending.retain(|w| !ids.contains(&w.id()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::transfer_call;
    use crate::ledger::Account;
    use qtv_account::{derive, Account as KeyAccount};
    use qtv_tx::{sign, Body};

    fn keypair(index: u64) -> KeyAccount {
        derive(&[9u8; 32], index)
    }

    fn fund(ledger: &mut Ledger, account: &KeyAccount, balance: u64) {
        ledger.set_account(
            &account.address(),
            &Account::funded(balance, account.scheme(), account.public_key().to_vec()),
        );
    }

    fn signed_transfer(from: &KeyAccount, to: &str, amount: u64, nonce: u64, fee: u128) -> Wrapper {
        let call = transfer_call(to, amount);
        let body = Body::new(from.address(), nonce, TRANSFER_METER, fee, call);
        sign(from, &body)
    }

    #[test]
    fn a_valid_transfer_is_admitted() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert!(pool.admit(tx, &ledger, &params).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let mut tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut sig = tx.signature().to_vec();
        sig[0] ^= 1;
        tx = Wrapper::new(tx.body().clone(), tx.scheme(), sig);
        let mut pool = Mempool::new();
        assert_eq!(pool.admit(tx, &ledger, &params), Err(Reject::BadSignature));
        assert!(pool.is_empty());
    }

    #[test]
    fn an_unaffordable_transfer_is_refused() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 100);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::InsufficientFunds)
        );
    }

    #[test]
    fn pay_what_you_bid_charges_the_bid_clamped_to_the_ceiling() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let account =
            Account::funded(1_000_000, alice.scheme(), alice.public_key().to_vec());
        let floor = params.transfer_fee();
        let ceiling = params.ceiling_fee();
        assert!(ceiling > floor);

        let at_floor = signed_transfer(&alice, &bob.address(), 100, 0, u128::from(floor));
        assert_eq!(
            plan_from_account(&at_floor, &account, &params).unwrap().fee,
            floor
        );

        let mid = floor + (ceiling - floor) / 2;
        let at_mid = signed_transfer(&alice, &bob.address(), 100, 0, u128::from(mid));
        assert_eq!(plan_from_account(&at_mid, &account, &params).unwrap().fee, mid);

        let over =
            signed_transfer(&alice, &bob.address(), 100, 0, u128::from(ceiling) * 100);
        assert_eq!(
            plan_from_account(&over, &account, &params).unwrap().fee,
            ceiling
        );

        let under = signed_transfer(&alice, &bob.address(), 100, 0, u128::from(floor) - 1);
        assert_eq!(
            plan_from_account(&under, &account, &params),
            Err(Reject::FeeTooLow)
        );
    }

    #[test]
    fn a_wrong_nonce_is_refused() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            3,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::BadNonce {
                expected: 0,
                got: 3
            })
        );
    }

    #[test]
    fn an_unsupported_scheme_is_refused_as_such_not_as_a_bad_signature() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let good = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let tx = Wrapper::new(good.body().clone(), 99, good.signature().to_vec());
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::UnsupportedScheme)
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn a_resubmission_is_known_and_idempotent() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        let tx = signed_transfer(
            &alice,
            &bob.address(),
            500,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(pool.admit(tx.clone(), &ledger, &params), Ok(Admitted::Fresh));
        assert_eq!(pool.admit(tx, &ledger, &params), Ok(Admitted::Known));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn candidates_order_by_fee_then_sender_and_nonce() {
        let params = FeeParams::devnet();
        let base = u128::from(params.transfer_fee());
        let alice = keypair(0);
        let bob = keypair(1);
        let carol = keypair(2);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);
        fund(&mut ledger, &bob, 10_000);
        let low = signed_transfer(&alice, &carol.address(), 100, 0, base);
        let high = signed_transfer(&bob, &carol.address(), 100, 0, base + 5);
        let mut pool = Mempool::new();
        pool.admit(low.clone(), &ledger, &params).unwrap();
        pool.admit(high.clone(), &ledger, &params).unwrap();
        let ordered = pool.candidates();
        assert_eq!(ordered[0].id(), high.id());
        assert_eq!(ordered[1].id(), low.id());
    }

    fn ids(txs: &[Wrapper]) -> Vec<String> {
        txs.iter().map(Wrapper::id).collect()
    }

    fn mixed_batch(params: &FeeParams) -> (Ledger, Vec<Wrapper>) {
        let count = 64u64;
        let keys: Vec<KeyAccount> = (0..count).map(keypair).collect();
        let mut ledger = Ledger::new();
        for (i, key) in keys.iter().enumerate().take(60) {
            let balance = if i == 42 { 1 } else { 5_000_000 };
            fund(&mut ledger, key, balance);
        }
        let fee = u128::from(params.transfer_fee());

        let mut batch = Vec::new();
        for i in 0..40u64 {
            let sender = i as usize;
            let recipient = 40 + (i % 20) as usize;
            batch.push(signed_transfer(
                &keys[sender],
                &keys[recipient].address(),
                1_000,
                0,
                fee,
            ));
        }
        let good = signed_transfer(&keys[40], &keys[41].address(), 500, 0, fee);
        let mut sig = good.signature().to_vec();
        sig[0] ^= 1;
        batch.push(Wrapper::new(good.body().clone(), good.scheme(), sig));
        batch.push(signed_transfer(&keys[41], &keys[42].address(), 500, 5, fee));
        batch.push(signed_transfer(&keys[42], &keys[43].address(), 1_000_000, 0, fee));
        batch.push(signed_transfer(&keys[43], &keys[43].address(), 100, 0, fee));
        batch.push(signed_transfer(&keys[60], &keys[44].address(), 100, 0, fee));

        (ledger, batch)
    }

    #[test]
    fn admit_batch_matches_per_transaction_admit_across_core_counts() {
        let params = FeeParams::devnet();
        let (ledger, batch) = mixed_batch(&params);

        let mut reference = Mempool::new();
        for tx in &batch {
            let _ = reference.admit(tx.clone(), &ledger, &params);
        }
        let reference_ids = ids(&reference.candidates());
        assert!(
            !reference.is_empty() && reference.len() < batch.len(),
            "the batch must both admit and refuse transactions"
        );

        for cores in [1usize, 2, 4, 8, 24] {
            let mut pool = Mempool::new();
            pool.admit_batch_across(batch.clone(), &ledger, &params, cores);
            assert_eq!(
                ids(&pool.candidates()),
                reference_ids,
                "the batch admitted set differs from per transaction admit at {cores} cores"
            );
            assert_eq!(
                pool.len(),
                reference.len(),
                "the batch admitted count differs at {cores} cores"
            );
        }

        let mut public = Mempool::new();
        let admitted = public.admit_batch(batch.clone(), &ledger, &params);
        assert_eq!(ids(&public.candidates()), reference_ids);
        assert_eq!(ids(&admitted), ids(&reference.pending));
    }
}
