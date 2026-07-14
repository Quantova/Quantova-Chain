//! The account model for the Quantova stack.
//!
//! Every key carries a scheme identifier byte ahead of the key. Scheme one is
//! the machine lattice signature and is the default, scheme two is the hash
//! based signature, and scheme three is the Falcon style signature behind the
//! fn-dsa feature. A thirty two byte master seed feeds a frozen pipeline. The
//! pipeline folds the master seed, the scheme identifier and an index through
//! shake256 to reach a thirty two byte account seed, and that seed drives key
//! production under the account scheme. The stored secret is that account seed
//! and never the expanded key.
//!
//! An address is the address family render of the sha3 256 hash of the scheme
//! identifier followed by the public key. The canonical tier keeps the full
//! thirty two byte hash and is the default. The compact tier keeps the leading
//! twenty four bytes. Neither tier falls below the twenty four byte floor. A
//! secret export is the secret family render of the account seed.

#![forbid(unsafe_code)]

use qtv_crypto::{ml_dsa, sha3, slh_dsa};

/// The scheme identifier for the machine lattice signature, ml_dsa. This is the
/// default scheme.
pub const SCHEME_LATTICE: u8 = 1;

/// The scheme identifier for the hash based signature, slh_dsa.
pub const SCHEME_HASH: u8 = 2;

/// The scheme identifier for the Falcon style signature, fn_dsa. It stays behind
/// the fn-dsa feature and is off in every default build until its standard is
/// final.
pub const SCHEME_FALCON: u8 = 3;

/// The length in bytes of a master seed.
pub const MASTER_SEED_LEN: usize = 32;
/// The length in bytes of an account seed, the stored secret.
pub const SEED_LEN: usize = 32;
/// The payload length in bytes of a canonical address, the default tier.
pub const CANONICAL_LEN: usize = 32;
/// The payload length in bytes of a compact address.
pub const COMPACT_LEN: usize = 24;

/// The width of an address payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The canonical thirty two byte payload, the default tier.
    Canonical,
    /// The compact twenty four byte payload.
    Compact,
}

impl Tier {
    /// The payload length in bytes this tier keeps from the address hash.
    pub fn payload_len(self) -> usize {
        match self {
            Tier::Canonical => CANONICAL_LEN,
            Tier::Compact => COMPACT_LEN,
        }
    }
}

/// Fold a master seed, a scheme identifier and an index into an account seed.
/// The input is the master seed followed by the scheme identifier followed by
/// the index in eight byte little endian order, and shake256 keeps the leading
/// thirty two bytes.
pub fn account_seed(master_seed: &[u8; MASTER_SEED_LEN], scheme: u8, index: u64) -> [u8; SEED_LEN] {
    let mut input = Vec::with_capacity(MASTER_SEED_LEN + 1 + 8);
    input.extend_from_slice(master_seed);
    input.push(scheme);
    input.extend_from_slice(&index.to_le_bytes());
    let mut seed = [0u8; SEED_LEN];
    sha3::shake256(&input, &mut seed);
    seed
}

/// The seed width slh_dsa consumes for each of its three seeds. The public key
/// holds PK.seed and PK.root, so half its width is one seed.
const HASH_SEED_LEN: usize = slh_dsa::PUBLIC_KEY_BYTES / 2;

/// Derive the hash based signature key pair from an account seed. shake256
/// expands the account seed into the three seeds slh_dsa keygen consumes, so a
/// signer can rebuild the same secret key the address commits to. The secret key
/// comes first, then the public key.
pub fn hash_keypair(
    seed: &[u8; SEED_LEN],
) -> (
    [u8; slh_dsa::SECRET_KEY_BYTES],
    [u8; slh_dsa::PUBLIC_KEY_BYTES],
) {
    let mut material = [0u8; 3 * HASH_SEED_LEN];
    sha3::shake256(seed, &mut material);
    let mut sk_seed = [0u8; HASH_SEED_LEN];
    let mut sk_prf = [0u8; HASH_SEED_LEN];
    let mut pk_seed = [0u8; HASH_SEED_LEN];
    sk_seed.copy_from_slice(&material[..HASH_SEED_LEN]);
    sk_prf.copy_from_slice(&material[HASH_SEED_LEN..2 * HASH_SEED_LEN]);
    pk_seed.copy_from_slice(&material[2 * HASH_SEED_LEN..]);
    slh_dsa::keygen(&sk_seed, &sk_prf, &pk_seed)
}

/// The sha3 256 hash of the scheme identifier followed by the public key. This
/// digest is the source of every address tier.
fn address_hash(scheme: u8, public_key: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + public_key.len());
    input.push(scheme);
    input.extend_from_slice(public_key);
    sha3::sha3_256(&input)
}

/// Render an address for a scheme identifier and a public key at a tier. The
/// payload is the leading bytes of the address hash for that tier, and it never
/// falls below the floor, so the format render always holds.
pub fn address_for_key(scheme: u8, public_key: &[u8], tier: Tier) -> String {
    let hash = address_hash(scheme, public_key);
    let payload = &hash[..tier.payload_len()];
    qtv_idfmt::render_address(payload).expect("an address tier payload reaches the key floor")
}

/// A derived account. The stored secret is the account seed and never the
/// expanded key, and the public key is retained for address and signature use.
#[derive(Debug, Clone)]
pub struct Account {
    scheme: u8,
    index: u64,
    seed: [u8; SEED_LEN],
    public_key: Vec<u8>,
}

impl Account {
    /// The scheme identifier this account was derived under.
    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    /// The index this account was derived under.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The account seed, the stored secret.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The public key bytes under the account scheme.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The address in the canonical tier, the default.
    pub fn address(&self) -> String {
        self.address_at(Tier::Canonical)
    }

    /// The address in the requested tier.
    pub fn address_at(&self, tier: Tier) -> String {
        address_for_key(self.scheme, &self.public_key, tier)
    }

    /// The secret export, the secret family render of the account seed.
    pub fn secret_export(&self) -> String {
        qtv_idfmt::render_secret(&self.seed).expect("an account seed reaches the key floor")
    }
}

/// Derive an account from a master seed and an index under the default machine
/// lattice scheme.
pub fn derive(master_seed: &[u8; MASTER_SEED_LEN], index: u64) -> Account {
    derive_with_scheme(master_seed, SCHEME_LATTICE, index)
}

/// Derive an account from a master seed and an index under a scheme identifier.
/// The account seed drives key production under the scheme, the expanded secret
/// key is dropped, and the account keeps the seed and the public key. Scheme one
/// runs ml_dsa keygen, scheme two runs slh_dsa keygen over shake256 expanded
/// seeds, and scheme three runs fn_dsa keygen behind the fn-dsa feature. An
/// unknown scheme identifier is rejected.
pub fn derive_with_scheme(master_seed: &[u8; MASTER_SEED_LEN], scheme: u8, index: u64) -> Account {
    let seed = account_seed(master_seed, scheme, index);
    let public_key = match scheme {
        SCHEME_LATTICE => {
            let (public_key, _expanded) = ml_dsa::keygen(&seed);
            public_key.to_vec()
        }
        SCHEME_HASH => {
            let (_secret, public_key) = hash_keypair(&seed);
            public_key.to_vec()
        }
        #[cfg(feature = "fn-dsa")]
        SCHEME_FALCON => {
            // The Falcon style scheme forwards to qtv_crypto::fn_dsa, which stays
            // unpublished until its standard is final. The gated path tracks the
            // module so it is ready when fn_dsa keygen lands.
            #[allow(unused_imports)]
            use qtv_crypto::fn_dsa;
            unimplemented!("fn_dsa key derivation is gated until the standard is final")
        }
        _ => panic!("derive was handed an unknown scheme identifier"),
    };
    Account {
        scheme,
        index,
        seed,
        public_key,
    }
}

/// A binding that records the move from an old address to a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    from: String,
    to: String,
}

impl Binding {
    /// The old address this binding moves away from.
    pub fn from(&self) -> &str {
        &self.from
    }

    /// The new address this binding moves to.
    pub fn to(&self) -> &str {
        &self.to
    }
}

/// The outcome of a rotation, the fresh account and the binding it records.
#[derive(Debug, Clone)]
pub struct Rotation {
    next: Account,
    binding: Binding,
}

impl Rotation {
    /// The fresh account derived under the new index.
    pub fn next(&self) -> &Account {
        &self.next
    }

    /// The binding from the old address to the new one.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
}

/// Rotate an account by deriving a fresh account under a new index and recording
/// the binding from the current canonical address to the fresh canonical
/// address.
pub fn rotate(master_seed: &[u8; MASTER_SEED_LEN], current: &Account, next_index: u64) -> Rotation {
    let next = derive(master_seed, next_index);
    let binding = Binding {
        from: current.address(),
        to: next.address(),
    };
    Rotation { next, binding }
}
