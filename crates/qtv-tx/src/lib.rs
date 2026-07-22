
#![forbid(unsafe_code)]

use qtv_account::Account;
use qtv_codec::{to_bytes, Encode, Encoder};
use qtv_crypto::{ml_dsa, sha3, slh_dsa};

pub const SCHEME_LATTICE: u8 = qtv_account::SCHEME_LATTICE;

pub const SCHEME_HASH: u8 = qtv_account::SCHEME_HASH;

pub const SCHEME_FALCON: u8 = qtv_account::SCHEME_FALCON;

pub const DOMAIN_TX: &[u8] = b"quantova.transaction.v1";

pub const LOCAL_CHAIN_ID: u64 = 0x5154_5644_4556_4E31;

pub const MAINNET_CHAIN_ID: u64 = 0x5154_4F56_4D41_494E;

pub const TESTNET_CHAIN_ID: u64 = 0x5154_4F56_5445_5354;

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
        encoder.put_bytes(self.target.as_bytes());
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
        encoder.put_bytes(self.sender.as_bytes());
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
