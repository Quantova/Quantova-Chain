//! Per validator secret material for the node.
//!
//! Every private key a validator uses, its one time sortition tree, its ML-DSA-65
//! attestation signing key, and its ML-DSA-65 peer to peer network identity, is
//! derived from one 32 byte secret through the domain separated `from_secret`
//! constructors in the consensus crates and `p2p` derivation in qtv-devnet. Nothing
//! is derived from the public validator id alone.
//!
//! The secret itself is `node_secret(id)`, a derivation of a devnet master secret
//! and the id. The master comes from the `QTV_DEVNET_MASTER` environment variable
//! when set, so an operator running a devnet supplies one high entropy secret out of
//! band and every node's material follows from it and cannot be recomputed by a
//! party that does not hold it. When the variable is unset a fixed development master
//! is used so a single machine devnet and the test suite are reproducible; that
//! development master is not secret and must never carry a real network.
//!
//! FOUNDER DECISION, still open: where a real network's per validator secrets are
//! generated and held. The intended end state is one secret per validator, generated
//! by that validator from a real CSPRNG and held in its own keystore, with only the
//! commitments published at registration. This module is the single seam that a
//! keystore backend plugs into.

use std::env;

use qtv_crypto::sha3::shake256;

/// The environment variable carrying the devnet master secret as 64 hex characters.
pub const DEVNET_MASTER_ENV: &str = "QTV_DEVNET_MASTER";

const NODE_SECRET_DOMAIN: &[u8] = b"QORUS/devnet/node-secret/v1";

// A fixed, NON SECRET development master. It exists only so a single machine devnet
// and the tests are reproducible; a real network must set QTV_DEVNET_MASTER.
const DEV_MASTER: [u8; 32] = [
    0x11, 0x9a, 0x2c, 0x74, 0x3d, 0xe0, 0x5f, 0x88, 0x64, 0x1c, 0xb3, 0x27, 0x90, 0xda, 0x6f, 0xc1,
    0x0e, 0x53, 0xa8, 0x42, 0xbb, 0x71, 0x2f, 0x9d, 0xc4, 0x86, 0x37, 0xef, 0x50, 0x19, 0x7a, 0x35,
];

/// Whether a real master secret was supplied out of band. When this is false every
/// derived identity is recomputable from the public dev master and the id, which is
/// acceptable only for a single machine devnet or the tests.
pub fn master_is_operator_supplied() -> bool {
    env::var(DEVNET_MASTER_ENV).is_ok()
}

/// The devnet master secret. The operator supplied value when `QTV_DEVNET_MASTER` is
/// set to 64 hex characters, otherwise the fixed development master.
pub fn devnet_master() -> [u8; 32] {
    match env::var(DEVNET_MASTER_ENV) {
        Ok(hex) => parse_hex32(&hex)
            .unwrap_or_else(|| panic!("{DEVNET_MASTER_ENV} must be 64 hex characters")),
        Err(_) => DEV_MASTER,
    }
}

/// The 32 byte secret a validator holds. All of the validator's private key material
/// follows from this by domain separated derivation; the id alone never yields it
/// unless the caller also holds the master.
pub fn node_secret(id: u64) -> [u8; 32] {
    node_secret_from_master(&devnet_master(), id)
}

/// The per node secret under an explicit master, for a caller that resolves the
/// master once and derives the whole set.
pub fn node_secret_from_master(master: &[u8; 32], id: u64) -> [u8; 32] {
    const D: usize = NODE_SECRET_DOMAIN.len();
    let mut buf = [0u8; D + 32 + 8];
    buf[..D].copy_from_slice(NODE_SECRET_DOMAIN);
    buf[D..D + 32].copy_from_slice(master);
    buf[D + 32..].copy_from_slice(&id.to_le_bytes());
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_secret_depends_on_the_master_not_the_id_alone() {
        let a = node_secret_from_master(&[1u8; 32], 5);
        let b = node_secret_from_master(&[2u8; 32], 5);
        assert_ne!(a, b, "a different master gives a different secret for one id");
        let c = node_secret_from_master(&[1u8; 32], 6);
        assert_ne!(a, c, "a different id gives a different secret under one master");
    }

    #[test]
    fn the_secret_is_not_the_master() {
        assert_ne!(node_secret_from_master(&[7u8; 32], 1), [7u8; 32]);
    }

    #[test]
    fn hex_masters_parse() {
        assert_eq!(parse_hex32(&"ab".repeat(32)), Some([0xabu8; 32]));
        assert_eq!(parse_hex32("zz"), None);
        assert_eq!(parse_hex32(&"a".repeat(63)), None);
    }
}
