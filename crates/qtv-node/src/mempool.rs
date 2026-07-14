//! The mempool, following SPEC-mempool.md.
//!
//! A transaction is admitted only when it is valid: its signature verifies under
//! the sender public key held in state, its nonce matches the next expected value
//! of the sender, and the sender can pay the transfer amount, the protocol fee,
//! and the gas. An invalid transaction is refused at the edge and never held, so
//! a bad signature or an insufficient balance can never reach a block. The pool
//! orders candidates by fee for a simple market and, within a sender, by nonce,
//! so block building over the same admitted set is reproducible.

use qtv_tx::Wrapper;

use crate::execution::{transfer_amount, TRANSFER_GAS};
use crate::fee::FeeParams;
use crate::ledger::Ledger;

/// The reason a transaction was refused admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The sender has no account with a public key to verify against.
    UnknownSender,
    /// The signature does not verify under the sender public key.
    BadSignature,
    /// The nonce does not match the next expected value of the sender.
    BadNonce { expected: u64, got: u64 },
    /// The call is not a well formed native transfer.
    BadCall,
    /// The transfer names the sender as its own recipient.
    SelfTransfer,
    /// The gas limit does not cover a transfer.
    InsufficientGas,
    /// The offered fee is below the protocol fee.
    FeeTooLow,
    /// The sender cannot pay the amount and the fee.
    InsufficientFunds,
}

/// A validated native transfer ready to execute: the sender, the recipient, the
/// amount, and the protocol fee that will be charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
}

/// Validate a transaction against the current state and the fee parameters,
/// returning the transfer it will carry out or the reason it is refused. The
/// charged fee is the protocol fee taken from the parameters, not the raw figure
/// the sender declared, which must only reach that floor.
pub fn validate(
    wrapper: &Wrapper,
    ledger: &Ledger,
    fee_params: &FeeParams,
) -> Result<TransferPlan, Reject> {
    let body = wrapper.body();
    let sender = body.sender().to_string();

    let account = ledger.account(&sender);
    if !account.has_key() {
        return Err(Reject::UnknownSender);
    }
    if !qtv_tx::verify(wrapper, &account.public_key) {
        return Err(Reject::BadSignature);
    }
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
    if body.gas_limit() < TRANSFER_GAS {
        return Err(Reject::InsufficientGas);
    }

    let fee = fee_params.transfer_fee();
    if body.fee() < u128::from(fee) {
        return Err(Reject::FeeTooLow);
    }
    let debit = amount.checked_add(fee).ok_or(Reject::InsufficientFunds)?;
    if account.balance < debit {
        return Err(Reject::InsufficientFunds);
    }

    Ok(TransferPlan {
        sender,
        recipient,
        amount,
        fee,
    })
}

/// The mempool of admitted transactions.
#[derive(Debug, Clone, Default)]
pub struct Mempool {
    pending: Vec<Wrapper>,
}

impl Mempool {
    /// An empty mempool.
    pub fn new() -> Self {
        Mempool {
            pending: Vec::new(),
        }
    }

    /// The number of admitted transactions waiting to enter a block.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the pool holds no transactions.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Admit a transaction, validating it against the state and the fee
    /// parameters first. A refused transaction is never held. A resubmission of a
    /// transaction already held is dropped.
    pub fn admit(
        &mut self,
        wrapper: Wrapper,
        ledger: &Ledger,
        fee_params: &FeeParams,
    ) -> Result<(), Reject> {
        validate(&wrapper, ledger, fee_params)?;
        let id = wrapper.id();
        if !self.pending.iter().any(|w| w.id() == id) {
            self.pending.push(wrapper);
        }
        Ok(())
    }

    /// The admitted transactions in build order: by declared fee for a simple
    /// market, then by sender and by nonce so a sender keeps its order. The order
    /// is a pure function of the pool, so block building is reproducible.
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

    /// Drop the transactions that were included in a block, named by their ids.
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
        let body = Body::new(from.address(), nonce, TRANSFER_GAS, fee, call);
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
}
