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
//! machine lattice signature signs that digest, and the wrapper carries the
//! scheme identifier of that signature alongside it.
//!
//! Signing folds the account seed back into a machine lattice key and signs the
//! body digest. Verifying recomputes the digest under the same domain tag and
//! checks the signature under the scheme identifier of the wrapper against the
//! sender public key. The transaction id is the identifier format render under
//! the transaction prefix of the sha3 256 hash of the canonical wrapper.

#![forbid(unsafe_code)]

use qtv_account::Account;
use qtv_codec::{to_bytes, Encode, Encoder};
use qtv_crypto::{ml_dsa, sha3};

/// The scheme identifier for the machine lattice signature, the only scheme this
/// transaction model verifies under.
pub const SCHEME_LATTICE: u8 = qtv_account::SCHEME_LATTICE;

/// The fixed domain tag folded into every transaction digest. It separates a
/// transaction signature from any other signed message in the stack.
pub const DOMAIN_TX: &[u8] = b"quantova.transaction.v1";

/// The randomizer that drives deterministic machine lattice signing. A run of
/// zero bytes selects the deterministic variant, so a body signs the same way
/// every time.
const SIGN_RANDOMIZER: [u8; 32] = [0u8; 32];

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
/// the machine lattice signature that stands over the body digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapper {
    body: Body,
    scheme: u8,
    signature: ml_dsa::Signature,
}

impl Wrapper {
    /// Assemble a wrapper from a body, a scheme identifier, and a signature.
    pub fn new(body: Body, scheme: u8, signature: ml_dsa::Signature) -> Self {
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

    /// The machine lattice signature over the body digest.
    pub fn signature(&self) -> &ml_dsa::Signature {
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
/// back into a machine lattice key, the body digest is taken under the domain
/// tag, and the signature stands over that digest under the account scheme.
pub fn sign(account: &Account, body: &Body) -> Wrapper {
    let digest = body_digest(body);
    let (_public, secret) = ml_dsa::keygen(account.seed());
    let signature = ml_dsa::sign(&secret, &digest, &[], &SIGN_RANDOMIZER)
        .expect("an empty context stays within the length bound");
    Wrapper {
        body: body.clone(),
        scheme: account.scheme(),
        signature,
    }
}

/// Verify a wrapper against a sender public key. The scheme identifier of the
/// wrapper must name the machine lattice signature, the digest is recomputed
/// under the same domain tag, and the signature must stand over that digest.
pub fn verify(wrapper: &Wrapper, public_key: &ml_dsa::PublicKey) -> bool {
    if wrapper.scheme != SCHEME_LATTICE {
        return false;
    }
    let digest = body_digest(&wrapper.body);
    ml_dsa::verify(public_key, &digest, &wrapper.signature, &[])
}
