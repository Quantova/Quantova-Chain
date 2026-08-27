// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::collections::HashSet;
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
    WrongChain,
    PoolFull,
    SenderQueueFull,
    RateLimited,
}

pub fn chain_ok(wrapper: &Wrapper, fee_params: &FeeParams) -> bool {
    wrapper.body().chain_id() == fee_params.chain_id
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
    let plan = plan_from_account_checks(wrapper, account, fee_params)?;
    if !qtv_tx::verify(wrapper, &account.public_key) {
        return Err(Reject::BadSignature);
    }
    Ok(plan)
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

fn canonical_address(address: &str) -> bool {
    match qtv_idfmt::parse_address(address) {
        Ok(payload) if payload.len() == qtv_idfmt::DIGEST_LEN => {
            qtv_idfmt::render_address(&payload).ok().as_deref() == Some(address)
        }
        _ => false,
    }
}

fn plan_from_account_checks(
    wrapper: &Wrapper,
    account: &Account,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    let body = wrapper.body();
    let sender = body.sender().to_string();

    if !chain_ok(wrapper, fee_params) {
        return Err(Reject::WrongChain);
    }

    if body.nonce() != account.nonce {
        return Err(Reject::BadNonce {
            expected: account.nonce,
            got: body.nonce(),
        });
    }

    if !canonical_address(&sender) {
        return Err(Reject::UnknownSender);
    }
    let amount = transfer_amount(body.call()).ok_or(Reject::BadCall)?;
    let recipient = body.call().target().to_string();
    if !canonical_address(&recipient) {
        return Err(Reject::BadCall);
    }
    if recipient == sender {
        return Err(Reject::SelfTransfer);
    }
    if crate::ledger::state_key(&sender) == crate::ledger::state_key(&recipient) {
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

fn sender_prevalidated(wrapper: &Wrapper, account: &Account, fee_params: &FeeParams) -> bool {
    let body = wrapper.body();
    if body.nonce() != account.nonce {
        return false;
    }
    if body.fee() < u128::from(fee_params.transfer_fee()) {
        return false;
    }
    let charged = u64::try_from(body.fee().min(u128::from(fee_params.ceiling_fee())))
        .unwrap_or_else(|_| fee_params.ceiling_fee());
    account.balance >= charged
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

pub const DEFAULT_MEMPOOL_CAP: usize = 65_536;

pub const DEFAULT_PER_SENDER_CAP: usize = 1_024;

pub const DEFAULT_PRIORITY_RESERVE: usize = 512;

pub fn is_priority(wrapper: &Wrapper) -> bool {
    wrapper.body().call().target() == crate::ledger::gov_system_address()
}

pub const DEFAULT_FEELESS_ADMITS_PER_WINDOW: usize = 128;

pub const DEFAULT_FEELESS_ATTEMPTS_PER_WINDOW: usize = 512;

fn is_feeless(wrapper: &Wrapper) -> bool {
    crate::node::is_bridge_mint(wrapper)
        || crate::node::is_bridge_settle(wrapper)
        || crate::node::is_evidence(wrapper)
        || crate::node::is_bridge_guardian(wrapper)
}

fn candidate_order(a: &Wrapper, b: &Wrapper, ceiling: u128) -> std::cmp::Ordering {
    b.body()
        .fee()
        .min(ceiling)
        .cmp(&a.body().fee().min(ceiling))
        .then_with(|| a.body().sender().cmp(b.body().sender()))
        .then_with(|| a.body().nonce().cmp(&b.body().nonce()))
}

#[derive(Debug, Clone)]
pub struct Mempool {
    pending: Vec<Wrapper>,
    // Ids currently in pending, kept in sync, so the duplicate check is O(1) not an O(n) rehash.
    ids: HashSet<String>,
    cap: usize,
    per_sender: usize,
    reserve: usize,
    feeless_cap: usize,
    feeless_admits: usize,
    feeless_attempts_cap: usize,
    evidence_attempts: usize,
    mint_attempts: usize,
    settle_attempts: usize,
    guardian_attempts: usize,
    // The capped fee actually charged bounds inclusion and eviction ranking, so a bid above the
    // ceiling buys no priority it never pays for. Refreshed from the fee params on every admit.
    ceiling: u128,
}

impl Default for Mempool {
    fn default() -> Self {
        Mempool::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Mempool::with_limits(
            DEFAULT_MEMPOOL_CAP,
            DEFAULT_PER_SENDER_CAP,
            DEFAULT_PRIORITY_RESERVE,
        )
    }

    pub fn with_limits(cap: usize, per_sender: usize, reserve: usize) -> Self {
        Mempool {
            pending: Vec::new(),
            ids: HashSet::new(),
            cap: cap.max(1),
            per_sender: per_sender.max(1),
            reserve: reserve.min(cap.saturating_sub(1)),
            feeless_cap: DEFAULT_FEELESS_ADMITS_PER_WINDOW,
            feeless_admits: 0,
            feeless_attempts_cap: DEFAULT_FEELESS_ATTEMPTS_PER_WINDOW,
            evidence_attempts: 0,
            mint_attempts: 0,
            settle_attempts: 0,
            guardian_attempts: 0,
            ceiling: u128::MAX,
        }
    }

    // Remove the pending entry at `index`, keeping the id set in sync. Used by the
    // eviction paths, which are the only places a pending entry leaves by index.
    fn remove_at(&mut self, index: usize) -> Wrapper {
        let wrapper = self.pending.remove(index);
        self.ids.remove(&wrapper.id());
        wrapper
    }

    fn effective_fee(&self, wrapper: &Wrapper) -> u128 {
        wrapper.body().fee().min(self.ceiling)
    }

    fn lowest_fee_normal(&self) -> Option<(usize, u128)> {
        self.pending
            .iter()
            .enumerate()
            .filter(|(_, w)| !is_priority(w))
            .min_by(|a, b| self.effective_fee(a.1).cmp(&self.effective_fee(b.1)))
            .map(|(index, w)| (index, self.effective_fee(w)))
    }

    fn lowest_fee_priority(&self) -> Option<(usize, u128)> {
        self.pending
            .iter()
            .enumerate()
            .filter(|(_, w)| is_priority(w))
            .min_by(|a, b| self.effective_fee(a.1).cmp(&self.effective_fee(b.1)))
            .map(|(index, w)| (index, self.effective_fee(w)))
    }

    fn duplicate_mint(&self, incoming: &Wrapper) -> bool {
        let source_key = match crate::node::bridge_mint_source_key(incoming) {
            Some(source_key) => source_key,
            None => return false,
        };
        self.pending.iter().any(|w| {
            crate::node::is_bridge_mint(w)
                && crate::node::bridge_mint_source_key(w) == Some(source_key)
        })
    }

    fn duplicate_settle(&self, incoming: &Wrapper) -> bool {
        let burn_ref = match crate::node::bridge_settle_burn_ref(incoming) {
            Some(burn_ref) => burn_ref,
            None => return false,
        };
        self.pending.iter().any(|w| {
            crate::node::is_bridge_settle(w)
                && crate::node::bridge_settle_burn_ref(w) == Some(burn_ref)
        })
    }

    fn has_pending_from_sender_nonce(&self, sender: &str, nonce: u64) -> bool {
        self.pending
            .iter()
            .any(|w| w.body().sender() == sender && w.body().nonce() == nonce)
    }

    fn has_capacity(&self, incoming: &Wrapper) -> bool {
        let sender = incoming.body().sender();
        let sender_count = self
            .pending
            .iter()
            .filter(|w| w.body().sender() == sender)
            .count();
        if sender_count >= self.per_sender {
            return false;
        }
        if is_priority(incoming) {
            return true;
        }
        let normal = self.pending.iter().filter(|w| !is_priority(w)).count();
        normal < self.cap.saturating_sub(self.reserve) && self.pending.len() < self.cap
    }

    fn charge_feeless(&mut self) -> bool {
        if self.feeless_admits >= self.feeless_cap {
            return false;
        }
        self.feeless_admits += 1;
        true
    }

    // Whether the feeless window has room, without spending it, to reject before the admissibility check.
    fn feeless_has_room(&self) -> bool {
        self.feeless_admits < self.feeless_cap
    }

    fn charge_feeless_attempt_for(&mut self, wrapper: &Wrapper) -> bool {
        let cap = self.feeless_attempts_cap;
        let counter = if crate::node::is_evidence(wrapper) {
            &mut self.evidence_attempts
        } else if crate::node::is_bridge_mint(wrapper) {
            &mut self.mint_attempts
        } else if crate::node::is_bridge_settle(wrapper) {
            &mut self.settle_attempts
        } else {
            &mut self.guardian_attempts
        };
        if *counter >= cap {
            return false;
        }
        *counter += 1;
        true
    }

    fn make_room(&mut self, incoming: &Wrapper) -> Result<(), Reject> {
        let sender = incoming.body().sender();
        let sender_count = self
            .pending
            .iter()
            .filter(|w| w.body().sender() == sender)
            .count();
        if sender_count >= self.per_sender {
            return Err(Reject::SenderQueueFull);
        }
        if is_priority(incoming) {
            if self.pending.len() < self.cap {
                return Ok(());
            }
            if let Some((index, _)) = self.lowest_fee_normal() {
                self.remove_at(index);
                return Ok(());
            }
            match self.lowest_fee_priority() {
                Some((index, fee)) if fee < self.effective_fee(incoming) => {
                    self.remove_at(index);
                    Ok(())
                }
                _ => Err(Reject::PoolFull),
            }
        } else {
            let normal = self.pending.iter().filter(|w| !is_priority(w)).count();
            if normal < self.cap.saturating_sub(self.reserve) && self.pending.len() < self.cap {
                return Ok(());
            }
            match self.lowest_fee_normal() {
                Some((index, fee)) if fee < self.effective_fee(incoming) => {
                    self.remove_at(index);
                    Ok(())
                }
                _ => Err(Reject::PoolFull),
            }
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
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
        if !chain_ok(&wrapper, fee_params) {
            return Err(Reject::WrongChain);
        }
        self.ceiling = u128::from(fee_params.ceiling_fee());
        let id = wrapper.id();
        if self.ids.contains(&id) {
            return Ok(Admitted::Known);
        }
        if !canonical_address(wrapper.body().sender()) {
            return Err(Reject::UnknownSender);
        }
        if crate::node::is_bridge_mint(&wrapper) {
            if self.duplicate_mint(&wrapper) {
                return Ok(Admitted::Known);
            }
            let fresh = crate::node::bridge_mint_source_key(&wrapper)
                .is_some_and(|(source_chain, source_ref)| !ledger.bridge_reference_seen(source_chain, &source_ref));
            if !fresh {
                return Err(Reject::BadCall);
            }
        }
        if crate::node::is_bridge_settle(&wrapper) {
            if self.duplicate_settle(&wrapper) {
                return Ok(Admitted::Known);
            }
            let fresh = crate::node::bridge_settle_burn_ref(&wrapper)
                .is_some_and(|burn_ref| !ledger.bridge_exit_settled(&burn_ref));
            if !fresh {
                return Err(Reject::BadCall);
            }
        }
        // Gate a feeless call before the admissibility check; the window is charged only once it proves admissible.
        if is_feeless(&wrapper) {
            if !self.has_capacity(&wrapper) {
                return Err(Reject::PoolFull);
            }
            if !self.feeless_has_room() {
                return Err(Reject::RateLimited);
            }
            if !self.charge_feeless_attempt_for(&wrapper) {
                return Err(Reject::RateLimited);
            }
        }
        if crate::node::is_vm_op(ledger, &wrapper) {
            if !CONTRACTS_ENABLED {
                return Err(Reject::BadCall);
            }
            if self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce()) {
                return Err(Reject::SenderQueueFull);
            }
            let account = ledger.account(wrapper.body().sender());
            if !sender_prevalidated(&wrapper, &account, fee_params) {
                return Err(Reject::BadCall);
            }
            let signature_ok = qtv_tx::verify(&wrapper, &account.public_key);
            if !crate::node::vm_admissible(&wrapper, &account, fee_params, signature_ok) {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_key_register(&wrapper) {
            if self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce()) {
                return Err(Reject::SenderQueueFull);
            }
            let account = ledger.account(wrapper.body().sender());
            if crate::node::key_register_admissible(&wrapper, &account, fee_params).is_none() {
                return Err(Reject::BadCall);
            }
        } else if wrapper.body().call().target() == crate::ledger::gov_system_address() {
            if self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce()) {
                return Err(Reject::SenderQueueFull);
            }
            let account = ledger.account(wrapper.body().sender());
            if !sender_prevalidated(&wrapper, &account, fee_params) {
                return Err(Reject::BadCall);
            }
            let signature_ok = qtv_tx::verify(&wrapper, &account.public_key);
            if crate::node::governance_admissible(&wrapper, &account, fee_params, signature_ok)
                .is_none()
            {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_evidence(&wrapper) {
            if !crate::node::evidence_admissible(fee_params.chain_id, &wrapper, ledger) {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_bridge_guardian(&wrapper) {
            if !crate::node::guardian_admissible(ledger, &wrapper, fee_params.chain_id) {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_bridge_mint(&wrapper) {
            if !crate::node::bridge_mint_admissible(ledger, &wrapper, fee_params.chain_id) {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_bridge_settle(&wrapper) {
            if !crate::node::bridge_settle_admissible(ledger, &wrapper, fee_params.chain_id) {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_bridge_exit(&wrapper) {
            if self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce()) {
                return Err(Reject::SenderQueueFull);
            }
            let account = ledger.account(wrapper.body().sender());
            if !sender_prevalidated(&wrapper, &account, fee_params) {
                return Err(Reject::BadCall);
            }
            let signature_ok = qtv_tx::verify(&wrapper, &account.public_key);
            if crate::node::bridge_exit_admissible(ledger, &wrapper, &account, fee_params, signature_ok)
                .is_none()
            {
                return Err(Reject::BadCall);
            }
        } else if crate::node::is_registration(&wrapper) {
            return Err(Reject::BadCall);
        } else {
            if self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce()) {
                return Err(Reject::SenderQueueFull);
            }
            validate(&wrapper, ledger, fee_params)?;
        }
        // Charge the feeless window only now the call is admissible, so a malformed call cannot spend it.
        if is_feeless(&wrapper) && !self.charge_feeless() {
            return Err(Reject::RateLimited);
        }
        self.make_room(&wrapper)?;
        self.pending.push(wrapper);
        self.ids.insert(id);
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
        self.ceiling = u128::from(fee_params.ceiling_fee());
        let mut admitted = Vec::new();
        for (index, wrapper) in batch.into_iter().enumerate() {
            if !chain_ok(&wrapper, fee_params) {
                continue;
            }
            let id = wrapper.id();
            if self.ids.contains(&id) {
                continue;
            }
            if !canonical_address(wrapper.body().sender()) {
                continue;
            }
            if crate::node::is_bridge_mint(&wrapper) {
                if self.duplicate_mint(&wrapper) {
                    continue;
                }
                let fresh = crate::node::bridge_mint_source_key(&wrapper)
                    .is_some_and(|(source_chain, source_ref)| !ledger.bridge_reference_seen(source_chain, &source_ref));
                if !fresh {
                    continue;
                }
            }
            if crate::node::is_bridge_settle(&wrapper) {
                if self.duplicate_settle(&wrapper) {
                    continue;
                }
                let fresh = crate::node::bridge_settle_burn_ref(&wrapper)
                    .is_some_and(|burn_ref| !ledger.bridge_exit_settled(&burn_ref));
                if !fresh {
                    continue;
                }
            }
            // Gate a feeless call before the admissibility check; charged only after it proves admissible.
            if is_feeless(&wrapper)
                && (!self.has_capacity(&wrapper)
                    || !self.feeless_has_room()
                    || !self.charge_feeless_attempt_for(&wrapper))
            {
                continue;
            }
            let admissible = if crate::node::is_vm_op(ledger, &wrapper) {
                if !CONTRACTS_ENABLED {
                    false
                } else if self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce()) {
                    false
                } else {
                    let account = ledger.account(wrapper.body().sender());
                    crate::node::vm_admissible(&wrapper, &account, fee_params, verified[index])
                }
            } else if crate::node::is_key_register(&wrapper) {
                !self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce())
                    && {
                        let account = ledger.account(wrapper.body().sender());
                        crate::node::key_register_admissible(&wrapper, &account, fee_params).is_some()
                    }
            } else if wrapper.body().call().target() == crate::ledger::gov_system_address() {
                !self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce())
                    && {
                        let account = ledger.account(wrapper.body().sender());
                        crate::node::governance_admissible(&wrapper, &account, fee_params, verified[index])
                            .is_some()
                    }
            } else if crate::node::is_evidence(&wrapper) {
                crate::node::evidence_admissible(fee_params.chain_id, &wrapper, ledger)
            } else if crate::node::is_bridge_guardian(&wrapper) {
                crate::node::guardian_admissible(ledger, &wrapper, fee_params.chain_id)
            } else if crate::node::is_bridge_mint(&wrapper) {
                crate::node::bridge_mint_admissible(ledger, &wrapper, fee_params.chain_id)
            } else if crate::node::is_bridge_settle(&wrapper) {
                crate::node::bridge_settle_admissible(ledger, &wrapper, fee_params.chain_id)
            } else if crate::node::is_bridge_exit(&wrapper) {
                !self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce())
                    && {
                        let account = ledger.account(wrapper.body().sender());
                        crate::node::bridge_exit_admissible(
                            ledger,
                            &wrapper,
                            &account,
                            fee_params,
                            verified[index],
                        )
                        .is_some()
                    }
            } else if crate::node::is_registration(&wrapper) {
                false
            } else {
                !self.has_pending_from_sender_nonce(wrapper.body().sender(), wrapper.body().nonce())
                    && validate_verified(&wrapper, ledger, fee_params, verified[index]).is_ok()
            };
            if !admissible {
                continue;
            }
            if is_feeless(&wrapper) && !self.charge_feeless() {
                continue;
            }
            if self.make_room(&wrapper).is_err() {
                continue;
            }
            self.pending.push(wrapper.clone());
            self.ids.insert(id);
            admitted.push(wrapper);
        }
        admitted
    }

    pub fn candidates(&self) -> Vec<Wrapper> {
        let mut ordered = self.pending.clone();
        ordered.sort_by(|a, b| candidate_order(a, b, self.ceiling));
        ordered
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn find_pending(&self, id: &str) -> Option<Wrapper> {
        if !self.ids.contains(id) {
            return None;
        }
        self.pending.iter().find(|w| w.id() == id).cloned()
    }

    pub fn top_candidates(&self, limit: usize) -> Vec<Wrapper> {
        if self.pending.len() <= limit {
            return self.candidates();
        }
        let mut refs: Vec<&Wrapper> = self.pending.iter().collect();
        refs.select_nth_unstable_by(limit, |a, b| candidate_order(a, b, self.ceiling));
        refs.truncate(limit);
        refs.sort_by(|a, b| candidate_order(a, b, self.ceiling));
        refs.into_iter().cloned().collect()
    }

    pub fn remove_included(&mut self, ids: &[String]) {
        let included: HashSet<&str> = ids.iter().map(String::as_str).collect();
        self.pending.retain(|w| !included.contains(w.id().as_str()));
        for id in ids {
            self.ids.remove(id);
        }
        self.feeless_admits = 0;
        self.evidence_attempts = 0;
        self.mint_attempts = 0;
        self.settle_attempts = 0;
        self.guardian_attempts = 0;
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
    fn a_bid_above_the_ceiling_buys_no_eviction_power() {
        let params = FeeParams::devnet();
        let ceiling = u128::from(params.ceiling_fee());
        let mut ledger = Ledger::new();
        // A single normal slot, so admitting a second normal transaction forces an eviction test.
        let mut pool = Mempool::with_limits(1, 100, 0);

        let alice = keypair(1);
        fund(&mut ledger, &alice, 1_000_000_000);
        let at_ceiling = signed_transfer(&alice, &keypair(9).address(), 100, 0, ceiling);
        assert!(matches!(
            pool.admit(at_ceiling, &ledger, &params),
            Ok(Admitted::Fresh)
        ));

        // Bob bids far above the ceiling. His charge is capped at the ceiling, so his effective fee
        // ties Alice's and he must not be able to evict her at the same real cost.
        let bob = keypair(2);
        fund(&mut ledger, &bob, 1_000_000_000);
        let above_ceiling = signed_transfer(&bob, &keypair(9).address(), 100, 0, u128::MAX);
        assert_eq!(
            pool.admit(above_ceiling, &ledger, &params),
            Err(Reject::PoolFull),
            "a fee above the ceiling wins no priority it never pays for"
        );
        assert_eq!(pool.pending_len(), 1, "the ceiling fee transaction stays");
    }

    #[test]
    fn a_self_transfer_is_refused_so_the_two_copy_write_cannot_mint() {
        let params = FeeParams::devnet();
        let mut ledger = Ledger::new();
        let alice = keypair(1);
        fund(&mut ledger, &alice, 1_000_000_000);
        let start = ledger.account(&alice.address()).balance;
        let tx = signed_transfer(&alice, &alice.address(), 100, 0, u128::from(params.transfer_fee()));
        assert_eq!(
            validate(&tx, &ledger, &params),
            Err(Reject::SelfTransfer),
            "a sender paying itself is the one write that would mint, so it must be refused"
        );
        assert_eq!(ledger.account(&alice.address()).balance, start);
    }

    #[test]
    fn remove_included_keeps_the_id_set_in_sync() {
        let params = FeeParams::devnet();
        let alice = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 1_000_000_000);
        let tx = signed_transfer(
            &alice,
            &keypair(2).address(),
            100,
            0,
            u128::from(params.transfer_fee()),
        );
        let id = tx.id();
        let mut pool = Mempool::new();

        assert_eq!(pool.admit(tx.clone(), &ledger, &params), Ok(Admitted::Fresh));
        assert!(pool.contains(&id), "the admitted id is in the set");
        assert_eq!(
            pool.admit(tx.clone(), &ledger, &params),
            Ok(Admitted::Known),
            "a resubmission before inclusion is known through the set"
        );

        pool.remove_included(&[id.clone()]);
        assert_eq!(pool.len(), 0, "the included tx left the pool");
        assert!(!pool.contains(&id), "and left the id set, so the set did not drift");
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Ok(Admitted::Fresh),
            "the same tx admits fresh again, proving the set was cleaned"
        );
    }

    fn seeded_evidence(offender_secret: &[u8; 32]) -> (Ledger, Wrapper, String) {
        use qtv_attest::{Attester, Beacon, Block as AttBlock, Parent};

        let params = FeeParams::devnet();
        let offender = crate::keys::validator_address(offender_secret);
        let attester = Attester::from_secret(1, offender_secret, 2_000);
        let offender_pk = attester.attest_public_key().to_vec();

        let beacon = Beacon::genesis();
        let block_a = AttBlock::new(1, [1u8; 32], Parent::Genesis);
        let block_b = AttBlock::new(1, [2u8; 32], Parent::Genesis);
        let a = attester.attest(params.chain_id, 1, 1, 0, [0u8; 32], block_a, &beacon);
        let b = attester.attest(params.chain_id, 1, 1, 0, [0u8; 32], block_b, &beacon);
        let evidence = crate::evidence::Equivocation {
            offender: offender.clone(),
            height: 1,
            view_a: 0,
            view_b: 0,
            slot_a: 1,
            slot_b: 1,
            committee_a: [0u8; 32],
            committee_b: [0u8; 32],
            block_a: block_a.to_bytes(),
            sig_a: a.sig.to_vec(),
            block_b: block_b.to_bytes(),
            sig_b: b.sig.to_vec(),
        };

        let mut ledger = Ledger::new();
        ledger.seed_supply(1_000_000_000);
        ledger.seed_validator_bond(&offender, 2_000 * 1_000_000);
        ledger.set_validator_attest_key(&offender, &offender_pk);

        let call = qtv_tx::Call::new(crate::ledger::evidence_address(), evidence.encode());
        let body = Body::with_context(
            crate::ledger::evidence_address(),
            0,
            0,
            0,
            call,
            0,
            params.chain_id,
        );
        (ledger, Wrapper::new(body, qtv_tx::SCHEME_LATTICE, Vec::new()), offender)
    }

    #[test]
    fn a_no_fee_evidence_transaction_is_admitted_and_a_forged_one_is_refused() {
        let params = FeeParams::devnet();
        let (ledger, tx, _offender) = seeded_evidence(&[9u8; 32]);
        let mut pool = Mempool::new();
        assert_eq!(pool.admit(tx, &ledger, &params), Ok(Admitted::Fresh));
        assert_eq!(pool.len(), 1, "valid evidence rides with no fee and no signature");

        let (bare, forged, _) = seeded_evidence(&[11u8; 32]);
        let empty = Ledger::new();
        let _ = bare;
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(forged, &empty, &params),
            Err(Reject::BadCall),
            "evidence naming an offender with no attestation key in state is refused"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn a_user_registration_transaction_is_refused_from_the_mempool() {
        let params = FeeParams::devnet();
        let alice = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 1_000_000_000);
        let tx = signed_transfer(
            &alice,
            &crate::ledger::registration_address(),
            100,
            0,
            u128::from(params.transfer_fee()),
        );
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(tx.clone(), &ledger, &params),
            Err(Reject::BadCall),
            "a user registration tx is refused at admission"
        );
        assert!(pool.is_empty());

        let admitted = pool.admit_batch(vec![tx], &ledger, &params);
        assert!(admitted.is_empty(), "and batch admission drops it too");
        assert!(pool.is_empty());
    }

    #[test]
    fn an_inadmissible_feeless_call_does_not_spend_the_window() {
        let params = FeeParams::devnet();
        let mut pool = Mempool::new();

        // A forged evidence tx is feeless by target but inadmissible; it must not charge the window.
        let (_bare, forged, _) = seeded_evidence(&[11u8; 32]);
        let empty = Ledger::new();
        assert_eq!(pool.admit(forged, &empty, &params), Err(Reject::BadCall));
        assert_eq!(
            pool.feeless_admits, 0,
            "an inadmissible feeless call must not spend the feeless window"
        );

        // A genuinely admissible feeless call spends exactly one unit.
        let (ledger, valid, _) = seeded_evidence(&[9u8; 32]);
        assert_eq!(pool.admit(valid, &ledger, &params), Ok(Admitted::Fresh));
        assert_eq!(
            pool.feeless_admits, 1,
            "an admitted feeless call spends one unit of the window"
        );
    }

    fn mixed_case(address: &str) -> String {
        let mut out = address.to_string();
        if let Some(pos) = out.rfind(|c: char| c.is_ascii_uppercase()) {
            let lowered = out[pos..=pos].to_ascii_lowercase();
            out.replace_range(pos..=pos, &lowered);
        }
        out
    }

    #[test]
    fn non_canonical_addresses_are_refused_at_admission() {
        let params = FeeParams::devnet();
        let fee = u128::from(params.transfer_fee());
        let attacker = keypair(0);
        let victim = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &attacker, 10_000_000);
        let canonical = attacker.address();
        let alias = canonical.to_ascii_lowercase();
        let mut pool = Mempool::new();

        let tx = signed_transfer(&attacker, &alias, 1_000, 0, fee);
        assert!(
            matches!(
                pool.admit(tx, &ledger, &params),
                Err(Reject::BadCall) | Err(Reject::SelfTransfer)
            ),
            "a lowercase aliased recipient must be refused after its signature verifies"
        );

        let call = transfer_call(&victim.address(), 1_000);
        let tx = sign(&attacker, &Body::new(alias.clone(), 0, TRANSFER_METER, fee, call));
        assert_eq!(
            pool.admit(tx, &ledger, &params),
            Err(Reject::UnknownSender),
            "a non canonical sender is refused"
        );

        let forged = Wrapper::new(
            Body::new(
                canonical.clone(),
                0,
                TRANSFER_METER,
                fee,
                transfer_call(&mixed_case(&victim.address()), 1_000),
            ),
            attacker.scheme(),
            vec![0u8; 8],
        );
        assert!(
            pool.admit(forged, &ledger, &params).is_err(),
            "a hand crafted mixed case recipient is refused at admission"
        );

        let forged = Wrapper::new(
            Body::new(
                canonical.clone(),
                0,
                TRANSFER_METER,
                fee,
                transfer_call("Q1nope", 1_000),
            ),
            attacker.scheme(),
            vec![0u8; 8],
        );
        assert!(
            pool.admit(forged, &ledger, &params).is_err(),
            "a hand crafted unparseable recipient is refused at admission"
        );

        let tx = signed_transfer(&attacker, &victim.address(), 1_000, 0, fee);
        assert!(
            pool.admit(tx, &ledger, &params).is_ok(),
            "a canonical transfer still admits after the gate"
        );
        assert_eq!(pool.len(), 1, "only the canonical transfer entered the pool");
    }

    #[test]
    fn a_non_canonical_sender_is_refused_on_every_lane_not_only_transfers() {
        let params = FeeParams::devnet();
        let fee = u128::from(params.transfer_fee());
        let owner = keypair(5);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &owner, 10_000_000);
        let alias = owner.address().to_ascii_lowercase();
        assert_ne!(alias, owner.address(), "the alias is a distinct surface string");
        let mut pool = Mempool::new();

        let aliased = sign(
            &owner,
            &Body::new(
                alias,
                0,
                TRANSFER_METER,
                fee,
                qtv_tx::Call::new(crate::ledger::gov_system_address(), vec![5]),
            ),
        );
        assert_eq!(
            pool.admit(aliased, &ledger, &params),
            Err(Reject::UnknownSender),
            "a non canonical sender is refused before lane dispatch, not only on the transfer lane"
        );
        assert_eq!(pool.len(), 0, "the aliased special-op did not enter the pool");

        let canonical = sign(
            &owner,
            &Body::new(
                owner.address(),
                0,
                TRANSFER_METER,
                fee,
                qtv_tx::Call::new(crate::ledger::gov_system_address(), vec![5]),
            ),
        );
        assert_ne!(
            pool.admit(canonical, &ledger, &params),
            Err(Reject::UnknownSender),
            "a canonical sender passes the sender gate and reaches its lane"
        );
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

    fn gov_release(from: &KeyAccount, nonce: u64, fee: u128) -> Wrapper {
        let call = qtv_tx::Call::new(crate::ledger::gov_system_address(), vec![5]);
        let body = Body::new(from.address(), nonce, TRANSFER_METER, fee, call);
        sign(from, &body)
    }

    #[test]
    fn the_mempool_is_bounded_and_a_priority_tx_is_always_includable() {
        let params = FeeParams::devnet();
        let fee = u128::from(params.transfer_fee());
        let mut ledger = Ledger::new();
        let mut pool = Mempool::with_limits(4, 100, 2);

        let recipient = keypair(200);
        for i in 0..2u64 {
            let sender = keypair(100 + i);
            fund(&mut ledger, &sender, 10_000_000);
            let tx = signed_transfer(&sender, &recipient.address(), 100, 0, fee);
            assert!(pool.admit(tx, &ledger, &params).is_ok());
        }
        for i in 0..2u64 {
            let guardian = keypair(140 + i);
            fund(&mut ledger, &guardian, 10_000_000);
            assert!(pool.admit(gov_release(&guardian, 0, fee), &ledger, &params).is_ok());
        }
        assert_eq!(pool.len(), 4, "the pool is at its hard cap");

        let crowd = keypair(160);
        fund(&mut ledger, &crowd, 10_000_000);
        let crowd_tx = signed_transfer(&crowd, &recipient.address(), 100, 0, fee);
        assert_eq!(
            pool.admit(crowd_tx, &ledger, &params),
            Err(Reject::PoolFull),
            "a fee competing transfer cannot exceed the bound"
        );
        assert_eq!(pool.len(), 4, "the pool stays bounded");

        let sentinel = keypair(170);
        fund(&mut ledger, &sentinel, 10_000_000);
        assert!(
            pool.admit(gov_release(&sentinel, 0, fee), &ledger, &params).is_ok(),
            "a safety transaction is always includable through the reserved lane"
        );
        assert_eq!(pool.len(), 4, "admitting a safety transaction keeps the pool bounded");
        assert_eq!(
            pool.candidates().iter().filter(|w| is_priority(w)).count(),
            3,
            "the safety transaction displaced a fee competing transfer, not another safety one"
        );
    }

    #[test]
    fn a_per_sender_flood_is_bounded() {
        let params = FeeParams::devnet();
        let fee = u128::from(params.transfer_fee());
        let mut ledger = Ledger::new();
        let mut pool = Mempool::with_limits(64, 3, 2);
        let spammer = keypair(0);
        let recipient = keypair(1);
        fund(&mut ledger, &spammer, 10_000_000);
        let first = signed_transfer(&spammer, &recipient.address(), 100, 0, fee);
        assert!(pool.admit(first, &ledger, &params).is_ok());
        for amount in 1..8u64 {
            let flood = signed_transfer(&spammer, &recipient.address(), 100 + amount, 0, fee);
            assert_eq!(
                pool.admit(flood, &ledger, &params),
                Err(Reject::SenderQueueFull),
                "a sender cannot queue a second transfer at the same nonce"
            );
        }
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_transaction_for_another_chain_is_rejected() {
        let params = FeeParams::devnet();
        let alice = keypair(0);
        let bob = keypair(1);
        let mut ledger = Ledger::new();
        fund(&mut ledger, &alice, 10_000);

        let fee = u128::from(params.transfer_fee());
        let foreign = Body::with_context(
            alice.address(),
            0,
            TRANSFER_METER,
            fee,
            transfer_call(&bob.address(), 500),
            0,
            qtv_tx::TESTNET_CHAIN_ID,
        );
        let mut pool = Mempool::new();
        assert_eq!(
            pool.admit(sign(&alice, &foreign), &ledger, &params),
            Err(Reject::WrongChain)
        );
        assert!(pool.is_empty());

        let native = Body::with_context(
            alice.address(),
            0,
            TRANSFER_METER,
            fee,
            transfer_call(&bob.address(), 500),
            0,
            params.chain_id,
        );
        assert!(pool.admit(sign(&alice, &native), &ledger, &params).is_ok());
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

    #[test]
    fn top_candidates_matches_the_sorted_prefix_and_find_pending_locates_by_id() {
        let params = FeeParams::devnet();
        let base = u128::from(params.transfer_fee());
        let carol = keypair(99);
        let mut ledger = Ledger::new();
        let mut pool = Mempool::new();
        let mut submitted = Vec::new();
        for i in 0..12u64 {
            let sender = keypair(i);
            fund(&mut ledger, &sender, 10_000);
            let tx = signed_transfer(&sender, &carol.address(), 100, 0, base + u128::from(i));
            pool.admit(tx.clone(), &ledger, &params).unwrap();
            submitted.push(tx);
        }
        assert_eq!(pool.pending_len(), 12, "every admitted tx is pending");
        let full = ids(&pool.candidates());
        for k in [1usize, 5, 11, 12, 20] {
            assert_eq!(
                ids(&pool.top_candidates(k)),
                full[..k.min(full.len())].to_vec(),
                "top_candidates({k}) equals the sorted prefix of candidates()"
            );
        }
        let target = &submitted[7];
        assert_eq!(
            pool.find_pending(&target.id()).map(|w| w.id()),
            Some(target.id()),
            "find_pending returns the pending tx by id"
        );
        assert_eq!(
            pool.find_pending("QTX1notinthepool"),
            None,
            "find_pending returns None for an id that is not pending"
        );
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
