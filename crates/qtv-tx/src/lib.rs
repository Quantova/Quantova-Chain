// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


#![forbid(unsafe_code)]

use qtv_account::Account;
use qtv_codec::{to_bytes, Encode, Encoder};
use qtv_crypto::{ml_dsa, sha3, slh_dsa};
use zeroize::Zeroizing;

pub const SCHEME_LATTICE: u8 = qtv_account::SCHEME_LATTICE;

pub const SCHEME_HASH: u8 = qtv_account::SCHEME_HASH;

pub const SCHEME_FALCON: u8 = qtv_account::SCHEME_FALCON;

pub const DOMAIN_TX: &[u8] = b"quantova.transaction.v1";

pub const LOCAL_CHAIN_NAME: &str = "Q-dev-net-1";

pub const TESTNET_CHAIN_NAME: &str = "Q-test-net-1";

pub const MAINNET_CHAIN_NAME: &str = "Q-main-net-1";

pub const LOCAL_CHAIN_ID: u64 = 13749533161254861464;

pub const TESTNET_CHAIN_ID: u64 = 4032652574364075694;

pub const MAINNET_CHAIN_ID: u64 = 5296651311193914109;

pub fn chain_id_from_name(name: &str) -> u64 {
    let digest = sha3::sha3_256(name.as_bytes());
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("a sha3 256 digest carries eight leading bytes"),
    )
}

const SIGN_RANDOMIZER: [u8; 32] = [0u8; 32];

const SIGN_RANDOMIZER_HASH: [u8; slh_dsa::PUBLIC_KEY_BYTES / 2] =
    [0u8; slh_dsa::PUBLIC_KEY_BYTES / 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    target: String,
    args: Vec<u8>,
}

impl Call {
    pub fn new(target: String, args: Vec<u8>) -> Self {
        Call { target, args }
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn args(&self) -> &[u8] {
        &self.args
    }
}

impl Encode for Call {
    fn encode(&self, encoder: &mut Encoder) {
        let target = qtv_idfmt::parse_address(&self.target).unwrap_or_default();
        encoder.put_bytes(&target);
        encoder.put_bytes(&self.args);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    sender: String,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    value: u64,
    chain_id: u64,
    call: Call,
}

impl Body {
    pub fn new(sender: String, nonce: u64, meter_limit: u64, fee: u128, call: Call) -> Self {
        Body::with_context(sender, nonce, meter_limit, fee, call, 0, LOCAL_CHAIN_ID)
    }

    pub fn with_context(
        sender: String,
        nonce: u64,
        meter_limit: u64,
        fee: u128,
        call: Call,
        value: u64,
        chain_id: u64,
    ) -> Self {
        Body {
            sender,
            nonce,
            meter_limit,
            fee,
            value,
            chain_id,
            call,
        }
    }

    pub fn sender(&self) -> &str {
        &self.sender
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn meter_limit(&self) -> u64 {
        self.meter_limit
    }

    pub fn fee(&self) -> u128 {
        self.fee
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn call(&self) -> &Call {
        &self.call
    }
}

impl Encode for Body {
    fn encode(&self, encoder: &mut Encoder) {
        let sender = qtv_idfmt::parse_address(&self.sender).unwrap_or_default();
        encoder.put_bytes(&sender);
        self.nonce.encode(encoder);
        self.meter_limit.encode(encoder);
        self.fee.encode(encoder);
        self.call.encode(encoder);
        self.value.encode(encoder);
        self.chain_id.encode(encoder);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapper {
    body: Body,
    scheme: u8,
    signature: Vec<u8>,
}

impl Wrapper {
    pub fn new(body: Body, scheme: u8, signature: Vec<u8>) -> Self {
        Wrapper {
            body,
            scheme,
            signature,
        }
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

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

fn body_digest(body: &Body) -> [u8; 32] {
    let mut input = to_bytes(body);
    input.extend_from_slice(DOMAIN_TX);
    sha3::sha3_256(&input)
}

pub fn sign(account: &Account, body: &Body) -> Wrapper {
    // Fail closed. Call::encode and Body::encode reduce an address to its raw payload with
    // parse_address(..).unwrap_or_default(), so an unparseable sender or target would encode as
    // an empty payload and the signature would stand over a body that is not the one the caller
    // named. Encode cannot return an error without changing the whole codec, so the signer is the
    // place that refuses a bad address before it ever reaches encode. The higher level clients
    // already reject a bad target, this is the low level backstop that no path routes around.
    assert!(
        qtv_idfmt::parse_address(body.sender()).is_ok(),
        "sign refuses a sender address that does not parse to an address payload"
    );
    assert!(
        qtv_idfmt::parse_address(body.call().target()).is_ok(),
        "sign refuses a call target that does not parse to an address payload"
    );
    let digest = body_digest(body);
    let scheme = account.scheme();
    let signature = match scheme {
        SCHEME_LATTICE => {
            let (_public, secret) = ml_dsa::keygen(account.seed());
            let secret = Zeroizing::new(secret);
            ml_dsa::sign(&secret, &digest, &[], &SIGN_RANDOMIZER)
                .expect("an empty context stays within the length bound")
                .to_vec()
        }
        SCHEME_HASH => {
            let (secret, _public) = qtv_account::hash_keypair(account.seed());
            let secret = Zeroizing::new(secret);
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

pub fn scheme_supported(scheme: u8) -> bool {
    match scheme {
        SCHEME_LATTICE | SCHEME_HASH => true,
        #[cfg(feature = "fn-dsa")]
        SCHEME_FALCON => true,
        _ => false,
    }
}

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

#[cfg(test)]
mod fail_closed_tests {
    use super::*;
    use qtv_account::derive;

    #[test]
    #[should_panic(expected = "call target that does not parse")]
    fn signing_an_unparseable_target_is_refused() {
        let account = derive(&[7u8; 32], 0);
        let call = Call::new("not a Q1 address".to_string(), vec![1, 2, 3]);
        let body = Body::new(account.address(), 0, 1_210, 500, call);
        let _ = sign(&account, &body);
    }

    #[test]
    #[should_panic(expected = "sender address that does not parse")]
    fn signing_an_unparseable_sender_is_refused() {
        let account = derive(&[7u8; 32], 0);
        let target = derive(&[7u8; 32], 1).address();
        let call = Call::new(target, vec![1, 2, 3]);
        let body = Body::new("not a Q1 address".to_string(), 0, 1_210, 500, call);
        let _ = sign(&account, &body);
    }

    #[test]
    fn signing_a_derived_sender_and_target_still_succeeds() {
        let account = derive(&[7u8; 32], 0);
        let target = derive(&[7u8; 32], 1).address();
        let call = Call::new(target, vec![1, 2, 3]);
        let body = Body::new(account.address(), 0, 1_210, 500, call);
        let wrapper = sign(&account, &body);
        assert!(verify(&wrapper, account.public_key()));
    }

    #[test]
    fn address_case_does_not_move_the_signed_preimage_or_the_id() {
        let account = derive(&[7u8; 32], 0);
        let canonical_sender = account.address();
        let alias_sender = canonical_sender.to_ascii_lowercase();
        let canonical_target = derive(&[7u8; 32], 1).address();
        let alias_target = canonical_target.to_ascii_lowercase();
        assert_ne!(
            canonical_sender, alias_sender,
            "the alias is a distinct surface string, so the check is not vacuous"
        );
        assert_ne!(canonical_target, alias_target);
        assert_eq!(
            qtv_idfmt::parse_address(&alias_sender).unwrap(),
            qtv_idfmt::parse_address(&canonical_sender).unwrap(),
            "both surface forms decode to one payload"
        );

        let build = |sender: &str, target: &str| {
            let call = Call::new(target.to_string(), vec![1, 2, 3]);
            let body = Body::new(sender.to_string(), 0, 1_210, 500, call);
            sign(&account, &body)
        };
        let canonical = build(&canonical_sender, &canonical_target);
        let aliased = build(&alias_sender, &alias_target);

        assert_eq!(
            body_digest(canonical.body()),
            body_digest(aliased.body()),
            "the surface case reached the signed preimage"
        );
        assert_eq!(
            canonical.signature(),
            aliased.signature(),
            "the surface case moved the signature over one fixed randomizer"
        );
        assert_eq!(
            canonical.id(),
            aliased.id(),
            "the surface case moved the transaction id"
        );
        assert!(verify(&canonical, account.public_key()));
        assert!(
            verify(&aliased, account.public_key()),
            "the signature stands for either surface form because both bind one payload"
        );
    }
}
