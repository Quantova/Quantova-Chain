//! Chain state held in the qtv-state sparse Merkle trie, following SPEC-state.md
//! and SPEC-accounts.md.
//!
//! Every address maps to an account record that holds the nonce that orders the
//! transactions of the sender, the native balance in base units, and the sender
//! signature scheme and public key. The public key is kept in state so a
//! signature can be verified without a side channel. The trie is keyed by the
//! thirty two byte address hash, which is the canonical address payload, so no
//! separate hashing step is introduced. The state root is the trie root over the
//! whole account set and is fixed by that set, independent of insertion order.

use qtv_codec::{from_bytes, to_bytes, Decode, Decoder, Encode, Encoder, Error};
use qtv_state::{Key, Trie, HASH_LEN, KEY_LEN};

/// An account record: the nonce, the native balance, the signature scheme, and
/// the public key the sender signs under. An absent account reads as the default,
/// a fresh account with a zero balance and no key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
    pub scheme: u8,
    pub public_key: Vec<u8>,
}

impl Account {
    /// A funded account with a known signing key, the shape a genesis account and
    /// a sender both take.
    pub fn funded(balance: u64, scheme: u8, public_key: Vec<u8>) -> Self {
        Account {
            nonce: 0,
            balance,
            scheme,
            public_key,
        }
    }

    /// Whether the account carries a public key, the precondition for verifying a
    /// signature from it. A receive only account has none until it first signs.
    pub fn has_key(&self) -> bool {
        !self.public_key.is_empty()
    }
}

impl Encode for Account {
    fn encode(&self, encoder: &mut Encoder) {
        self.nonce.encode(encoder);
        self.balance.encode(encoder);
        self.scheme.encode(encoder);
        self.public_key.encode(encoder);
    }
}

impl Decode for Account {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Account {
            nonce: u64::decode(decoder)?,
            balance: u64::decode(decoder)?,
            scheme: u8::decode(decoder)?,
            public_key: Vec::<u8>::decode(decoder)?,
        })
    }
}

/// The trie key for an address, the canonical address payload rendered back to
/// its raw bytes. A canonical address carries the full thirty two byte hash, so
/// the payload fills the key. A shorter payload is left padded space, and an
/// address that does not parse maps to the zero key, which the caller rules out
/// by validating the address before it reaches state.
fn state_key(address: &str) -> Key {
    let mut key = [0u8; KEY_LEN];
    if let Ok(payload) = qtv_idfmt::parse_address(address) {
        let n = payload.len().min(KEY_LEN);
        key[..n].copy_from_slice(&payload[..n]);
    }
    key
}

/// The account state of the chain over the sparse Merkle trie.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    trie: Trie,
}

impl Ledger {
    /// An empty ledger with no accounts.
    pub fn new() -> Self {
        Ledger { trie: Trie::new() }
    }

    /// The account an address holds, or the default fresh account when the
    /// address is absent.
    pub fn account(&self, address: &str) -> Account {
        match self.trie.get(&state_key(address)) {
            Some(bytes) => from_bytes(bytes).expect("state holds a canonical account record"),
            None => Account::default(),
        }
    }

    /// Bind an address to an account record, replacing any prior record.
    pub fn set_account(&mut self, address: &str, account: &Account) {
        self.trie.insert(state_key(address), to_bytes(account));
    }

    /// The balance an address holds.
    pub fn balance(&self, address: &str) -> u64 {
        self.account(address).balance
    }

    /// The next expected nonce of an address.
    pub fn nonce(&self, address: &str) -> u64 {
        self.account(address).nonce
    }

    /// The state root over the whole account set, fixed by the set and not by the
    /// order the accounts were written in.
    pub fn state_root(&self) -> [u8; HASH_LEN] {
        self.trie.root()
    }

    /// The state root rendered under the state family for display.
    pub fn state_root_id(&self) -> String {
        qtv_idfmt::render_state(&self.state_root())
            .expect("a state root is the fixed digest length")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(index: u64) -> String {
        let account = qtv_account::derive(&[7u8; 32], index);
        account.address()
    }

    #[test]
    fn an_absent_account_reads_as_the_default() {
        let ledger = Ledger::new();
        assert_eq!(ledger.account(&address(0)), Account::default());
        assert_eq!(ledger.balance(&address(0)), 0);
    }

    #[test]
    fn an_account_round_trips_through_state() {
        let mut ledger = Ledger::new();
        let addr = address(1);
        let account = Account::funded(5_000, qtv_account::SCHEME_LATTICE, vec![1, 2, 3]);
        ledger.set_account(&addr, &account);
        assert_eq!(ledger.account(&addr), account);
        assert_eq!(ledger.balance(&addr), 5_000);
    }

    #[test]
    fn the_root_moves_with_a_balance_change() {
        let mut ledger = Ledger::new();
        let addr = address(2);
        ledger.set_account(&addr, &Account::funded(1, 0, Vec::new()));
        let before = ledger.state_root();
        ledger.set_account(&addr, &Account::funded(2, 0, Vec::new()));
        assert_ne!(before, ledger.state_root());
    }

    #[test]
    fn the_root_is_independent_of_write_order() {
        let a = address(3);
        let b = address(4);
        let mut one = Ledger::new();
        one.set_account(&a, &Account::funded(10, 0, Vec::new()));
        one.set_account(&b, &Account::funded(20, 0, Vec::new()));
        let mut two = Ledger::new();
        two.set_account(&b, &Account::funded(20, 0, Vec::new()));
        two.set_account(&a, &Account::funded(10, 0, Vec::new()));
        assert_eq!(one.state_root(), two.state_root());
    }
}
