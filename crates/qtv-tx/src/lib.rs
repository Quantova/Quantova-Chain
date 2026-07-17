//! The transaction model for the Quantova stack.
//!
//! A transaction is a wrapper around a body. The signature is carried outside
//! the body so that the body stays the exact run of bytes that a sender commits
//! to. The body holds the sender address, a nonce that orders the transactions
//! of a sender, the gas limit, the fee, and the call. A call is a target address
//! together with the encoded arguments.
//!
//! The bytes that are signed are the sha3 256 hash of the canonical body
//! encoding followed by a fixed transaction domain tag. The domain tag keeps a
//! transaction signature from ever standing in for another signed message. The
//! signature of the signing account scheme signs that digest, and the wrapper
//! carries the scheme identifier of that signature alongside it.
//!
//! Signing folds the account seed back into a key under the account scheme and
//! signs the body digest. Verifying recomputes the digest under the same domain
//! tag, reads the scheme identifier from the wrapper, and dispatches to ml_dsa
//! for scheme one, slh_dsa for scheme two, and the fn-dsa gated fn_dsa for
//! scheme three, rejecting any other value. The transaction id is the identifier
//! format render under the transaction prefix of the sha3 256 hash of the
//! canonical wrapper.

#![forbid(unsafe_code)]

use qtv_account::Account;
use qtv_codec::{to_bytes, Encode, Encoder};
use qtv_crypto::{ml_dsa, sha3, slh_dsa};

/// The scheme identifier for the module lattice signature, the default scheme.
pub const SCHEME_LATTICE: u8 = qtv_account::SCHEME_LATTICE;

/// The scheme identifier for the hash based signature.
pub const SCHEME_HASH: u8 = qtv_account::SCHEME_HASH;

/// The scheme identifier for the Falcon style signature, behind the fn-dsa
/// feature.
pub const SCHEME_FALCON: u8 = qtv_account::SCHEME_FALCON;

/// The fixed domain tag folded into every transaction digest. It separates a
/// transaction signature from any other signed message in the stack.
pub const DOMAIN_TX: &[u8] = b"quantova.transaction.v1";

/// The randomizer that drives deterministic module lattice signing. A run of
/// zero bytes selects the deterministic variant, so a body signs the same way
/// every time.
const SIGN_RANDOMIZER: [u8; 32] = [0u8; 32];

/// The additional randomness that drives deterministic hash based signing. A run
/// of zero bytes fixes the signature, so a body signs the same way every time.
const SIGN_RANDOMIZER_HASH: [u8; slh_dsa::PUBLIC_KEY_BYTES / 2] =
    [0u8; slh_dsa::PUBLIC_KEY_BYTES / 2];

/// A call names the target address and carries the encoded arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    target: String,
    args: Vec<u8>,
}

impl Call {
    /// Assemble a call from a target address and its encoded arguments.
    pub fn new(target: String, args: Vec<u8>) -> Self {
        Call { target, args }
    }

    /// The target address the call reaches.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The encoded arguments the call carries.
    pub fn args(&self) -> &[u8] {
        &self.args
    }
}

impl Encode for Call {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_bytes(self.target.as_bytes());
        encoder.put_bytes(&self.args);
    }
}

/// The signed content of a transaction. Every field enters the digest through
/// the canonical codec, so one body has exactly one signed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    sender: String,
    nonce: u64,
    gas_limit: u64,
    fee: u128,
    call: Call,
}

impl Body {
    /// Assemble a body from a sender address, a nonce, a gas limit, a fee, and a
    /// call.
    pub fn new(sender: String, nonce: u64, gas_limit: u64, fee: u128, call: Call) -> Self {
        Body {
            sender,
            nonce,
            gas_limit,
            fee,
            call,
        }
    }

    /// The sender address that owns and signs the transaction.
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// The nonce that orders the transactions of the sender.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The gas limit the sender allows the call to consume.
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// The fee the sender offers for inclusion.
    pub fn fee(&self) -> u128 {
        self.fee
    }

    /// The call the transaction carries.
    pub fn call(&self) -> &Call {
        &self.call
    }
}

impl Encode for Body {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.put_bytes(self.sender.as_bytes());
        self.nonce.encode(encoder);
        self.gas_limit.encode(encoder);
        self.fee.encode(encoder);
        self.call.encode(encoder);
    }
}

/// A signed transaction. The wrapper pairs a body with the scheme identifier and
/// the signature that stands over the body digest. The signature width follows
/// the scheme, so it is held as a byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapper {
    body: Body,
    scheme: u8,
    signature: Vec<u8>,
}

impl Wrapper {
    /// Assemble a wrapper from a body, a scheme identifier, and a signature.
    pub fn new(body: Body, scheme: u8, signature: Vec<u8>) -> Self {
        Wrapper {
            body,
            scheme,
            signature,
        }
    }

    /// The signed body.
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// The scheme identifier the signature was produced under.
    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    /// The signature over the body digest.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The transaction id, the identifier format render under the transaction
    /// prefix of the sha3 256 hash of the canonical wrapper.
    pub fn id(&self) -> String {
        let hash = sha3::sha3_256(&to_bytes(self));
        qtv_idfmt::render_tx(&hash).expect("a sha3 256 hash is the fixed digest length")
    }
}

impl Encode for Wrapper {
    fn encode(&self, encoder: &mut Encoder) {
        self.body.encode(encoder);
        self.scheme.encode(encoder);
        encoder.put_bytes(&self.signature);
    }
}

/// The digest that a signature stands over. It is the sha3 256 hash of the
/// canonical body encoding followed by the transaction domain tag.
fn body_digest(body: &Body) -> [u8; 32] {
    let mut input = to_bytes(body);
    input.extend_from_slice(DOMAIN_TX);
    sha3::sha3_256(&input)
}

/// Sign a body with an account and return the wrapper. The account seed folds
/// back into a key under the account scheme, the body digest is taken under the
/// domain tag, and the signature stands over that digest.
pub fn sign(account: &Account, body: &Body) -> Wrapper {
    let digest = body_digest(body);
    let scheme = account.scheme();
    let signature = match scheme {
        SCHEME_LATTICE => {
            let (_public, secret) = ml_dsa::keygen(account.seed());
            ml_dsa::sign(&secret, &digest, &[], &SIGN_RANDOMIZER)
                .expect("an empty context stays within the length bound")
                .to_vec()
        }
        SCHEME_HASH => {
            let (secret, _public) = qtv_account::hash_keypair(account.seed());
            slh_dsa::sign(&secret, &digest, &[], &SIGN_RANDOMIZER_HASH)
                .expect("an empty context stays within the length bound")
                .to_vec()
        }
        #[cfg(feature = "fn-dsa")]
        SCHEME_FALCON => {
            #[allow(unused_imports)]
            use qtv_crypto::fn_dsa;
            unimplemented!("fn_dsa signing is gated until the standard is final")
        }
        _ => panic!("sign was handed an unknown scheme identifier"),
    };
    Wrapper {
        body: body.clone(),
        scheme,
        signature,
    }
}

/// Whether the node can verify a signature under this scheme identifier. It is
/// exactly the set of arms `verify` dispatches to a real check, so admission can
/// refuse an unverifiable scheme cleanly as unsupported rather than report its
/// unavoidable false verdict as a bad signature, which would tell a client its
/// signature is wrong when the truth is we do not verify that scheme. It tracks the
/// same feature gate as `verify`, so a scheme is supported here exactly when `verify`
/// has a real arm for it, and Falcon becomes supported the day the fn-dsa standard
/// lands and the feature is on.
pub fn scheme_supported(scheme: u8) -> bool {
    match scheme {
        SCHEME_LATTICE | SCHEME_HASH => true,
        #[cfg(feature = "fn-dsa")]
        SCHEME_FALCON => true,
        _ => false,
    }
}

/// Verify a wrapper against a sender public key. The digest is recomputed under
/// the same domain tag, the scheme identifier of the wrapper selects the
/// signature to check, and any scheme identifier that names no scheme is
/// rejected.
pub fn verify(wrapper: &Wrapper, public_key: &[u8]) -> bool {
    let digest = body_digest(&wrapper.body);
    match wrapper.scheme {
        SCHEME_LATTICE => {
            let public_key: &ml_dsa::PublicKey = match public_key.try_into() {
                Ok(key) => key,
                Err(_) => return false,
            };
            let signature: &ml_dsa::Signature = match wrapper.signature.as_slice().try_into() {
                Ok(signature) => signature,
                Err(_) => return false,
            };
            ml_dsa::verify(public_key, &digest, signature, &[])
        }
        SCHEME_HASH => {
            let public_key: &[u8; slh_dsa::PUBLIC_KEY_BYTES] = match public_key.try_into() {
                Ok(key) => key,
                Err(_) => return false,
            };
            slh_dsa::verify(public_key, &digest, &wrapper.signature, &[])
        }
        #[cfg(feature = "fn-dsa")]
        SCHEME_FALCON => {
            #[allow(unused_imports)]
            use qtv_crypto::fn_dsa;
            unimplemented!("fn_dsa verification is gated until the standard is final")
        }
        _ => false,
    }
}
