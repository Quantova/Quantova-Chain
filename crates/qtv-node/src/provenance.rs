// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use qtv_vm::container::Container;

pub const PROVENANCE_TAG: [u8; 4] = *b"QPRV";

pub const PROVENANCE_DOMAIN: &[u8] = b"QUANTOVA/QVM/PROVENANCE/v1";

const PRODUCTION_KEY_HEX: &str = "0b6b1fd273b794b0ceb36a4e142d5e3e23cae1427e0d9d4f287511457e160668ee99a5eee0d21bf39675511dc90119207b6e4956c81b95d2b3c6d129b7548971ff504e189c38673038ba008db1f95c6d9ff7136f5f43f290134b4c0e7b6eca5d362444fabe74c790ccd3b8791d7b71d3c069b12d72761908d1ab2c28b990a9312f0bfa710cdb5cb89cfbb58ac460124672b6d0b5a462bf2b461b3d77df37d131c9b49ebbe9f34c3d355ca778f13cd0791de66179842916f8169324ce976cee0e117038ab797bbe9f7d8eff6170c351fefb6b894dfc2684496fb367526a2e038cab826b4794f12d35257ce1a62dea9ad67b676099d2937e196293e524e70186f8718a9679e0b7f9a81c3da916be24504d40d8834cc48c03cb4b9f3045a2605e1e0f013b2c6f807732df5879a2df24d08d451de5a31ff7c7c602f89063eae3cc6c2e5cd14314e0805fbb1a430bed5dd4d7bee6774886cf532945186bdef2d325b75474454fd7c77c187c654b2722f5f2e5d573299fa9a66f1fcfa71d0f0f1ffe46caaf8703b2b08a1cabe2603dfb676fbaa67c5f91623889265eba395c1fdbb10591460265f64d87dd5194a2ad4e325b9a3d202aba1aff1a0ccbe9129d4703241b0a4f9bfda1d4a83654d4315ddeec0a70d86057a16efd3e398b74e53988d28be97702f964721ccf01e9052a8d75235dc14625cb47748af02f18ffbf2ee010217485747a709e001afffaea3bf400b0ee131ccf9639f9d779badcbcc6ec21bb98ae53d0ae8295903cf19257683b94659d07478fd8d0a933a53796cb0d27ecad7f9ab52f74938c8182475118357f149c7d2d510e691321c5a54432f4cb381e3b91b28a0b7c5f544bb0a6327146d0a47a3854d275ca8d01808f910dcd396a69cb4f63855156687057ae29034e199e088edbd4c71eed478314055aa3db342bbc87414d1ac49b3f1aa6b0805cd48280cde6f0b26c3d406eb0524306cbbef63998185c1645407bbaeeef0b0d4f2ac2799f9e3ce0ae2fa4c02eb0fd95ac4e0b8c1bd242e2fc74e91196eece45b5060680db4bba457b3e8ad1e3b983d5cc1bee34eb9c8b128165b94892c374ed959e652cc8f8634b44aed758737b2db9f971ed926a838797cd313e1034bc61d9d314db0b01249d60f8c8fec04e0826b587833ce4264c43eb9710ffe2ed6c80784bd5f1304d8fc062fcb2e98a6c91d1c7ca81eab654b1fa8495e5efd4876629677d764bb8cd5af19011dede1bb9ff2599b7ca3797e5d65b5fed0446dfbd85540cbbaa033002d6d9226de89abbb18f7cfb5848da0c4466d622cc587b3d65063df81647284f76177e049a9cfc7542600c680ad2df53e27a464f94bd2f0437a044eac79996cde0b2228b48344013d18c9d6c1423d9d2f849b98dd7d14ac7ea6c11c19773b2329f6984d8825276112d42e9156614aeeed4d3a7d249f49bf9a972524ac4559518be76acabb6138a4931dac99850b2ecdf4f991e0f51b90fcbe33d8fdcb19ca5dd23f0ce25d20773922855548f8111c9b86a07658f0a5f140769780592774f14a6f7aa4274603ba6a0a7de6a83dd077940ee83330a93c198dd65f33224cac5610732eaa131a1d62d9409d39dc503dd6167304bba91abef4d4d97423b963ca800d678b5051de9891854c5e9e294ea29ac0702f5001eae7bdaa7c5fdbe744c8810438afb63c2b11f51a976dcb33cfbd580a4cd75b98dfadf7eeb60abfbf7515b3eaaea38fe4ff9c4db4b9078e74fd6e50082c3f81b5db24970b478d80aae70bd061315aee3b99ea2164e267eef8bee6559a0a5e1f64f12f6da94d6fe7c4800e775d4050fdac10fd3d97e4b46a5e7df61accf3eee9ca5ca64b338afcaf500269d82be94644d0fe4a674ef5ad475fac693ca28d30aae3066d0992ba31bf1cee63a071a2bcfd3ce189fe419749a7f28249a8ab81bd1149d506b21ff978edb7328e075b3d7ce94a604c2e56b8f391dc8b7327dac6a8776696c49bd16055900584108b8aeebd0ce33c8e55abc5e6eb3966689bb3a7cef9d6e7b60b438f8115b414e381bc4959457b2b20e9fcaf3ee2f01a35cdae9ffaae84695180dc45ecd5ee73bcdd2a97428ee477b69bb12e7d44db5c45e838a3f0e4ad3eeabd9b1f33c2f7394556ddae5ce95214054be862704b7d66df8fbcd2583843a4248aaf487b52881a378e4f21a871ca60c4fad89efd9bfcef212274d64441e4cdf43967ce91d63e58e710f533b939c6642a3ee4203fcb325608836d46bb7b13136e8c323675403942db6d20ac5a69d24dd4ccf37b2734af378adc09905634a1f214d08ea86a74c817ef812800cb2e63a1d26e49ef12e0d99a9b39af09b70fe12f6cb08429a059096dbf5a4ccc9272ebfecb0a1d7e5a9e5a1f507915704b2a19fd671980a599a7a5d5efad4e33959f526022bb42c9797e65dcdf809314a7fc5132412535d6750ca9b2ff53856017d8371daa55b940856afed5f4762d68dc485607bccae4694c248b30f6263407aeaabce9ca041e0a0b590742b4e012326be4740de68bae2a1b2782f06e26eae2371648198cce4584fcabb5b1551a686a5a3d32d09d4de1dd03fded554df10f5551ffd738c74e47bddfa638e8c428b1e3ce38c7d625a1e6465602b72656284f00ac53f4c808d93b6fd6ebe1e157882a93956881f1ef88c02a4161e37d48d7791586b25ed608d1a162f05bc9ff80d589a1ddfaf2e7f4c6154f7e287ed7f4fb0e209f9cc7bb2549681d89270e4813dc1f13879b565";

fn production_key() -> [u8; PUBLIC_KEY_BYTES] {
    let mut key = [0u8; PUBLIC_KEY_BYTES];
    let hex = PRODUCTION_KEY_HEX.as_bytes();
    let mut i = 0;
    while i < PUBLIC_KEY_BYTES {
        key[i] = nibble(hex[i * 2]) << 4 | nibble(hex[i * 2 + 1]);
        i += 1;
    }
    key
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

#[derive(Debug, Clone)]
pub struct ProvenanceVerifier {
    key: [u8; PUBLIC_KEY_BYTES],
    #[cfg(all(feature = "test-fixtures", debug_assertions))]
    accept_unsigned: bool,
}

impl Default for ProvenanceVerifier {
    fn default() -> Self {
        ProvenanceVerifier {
            key: production_key(),
            #[cfg(all(feature = "test-fixtures", debug_assertions))]
            accept_unsigned: true,
        }
    }
}

impl ProvenanceVerifier {
    pub fn with_key(key: [u8; PUBLIC_KEY_BYTES]) -> Self {
        ProvenanceVerifier {
            key,
            #[cfg(all(feature = "test-fixtures", debug_assertions))]
            accept_unsigned: false,
        }
    }

    pub fn admit(&self, artifact: &[u8], container: &Container) -> Option<Vec<u8>> {
        let canonical = container.canonical_bytes();
        #[cfg(all(feature = "test-fixtures", debug_assertions))]
        if self.accept_unsigned && artifact == canonical.as_slice() {
            return Some(canonical);
        }
        let clen = canonical.len();
        if artifact.len() != clen + PROVENANCE_TAG.len() + SIGNATURE_BYTES {
            return None;
        }
        if artifact.get(..clen)? != canonical.as_slice() {
            return None;
        }
        if artifact.get(clen..clen + PROVENANCE_TAG.len())? != PROVENANCE_TAG {
            return None;
        }
        let sig_bytes = artifact.get(clen + PROVENANCE_TAG.len()..)?;
        let mut signature = [0u8; SIGNATURE_BYTES];
        signature.copy_from_slice(sig_bytes);
        if !ml_dsa::verify(
            &self.key,
            &container.identifier(),
            &signature,
            PROVENANCE_DOMAIN,
        ) {
            return None;
        }
        Some(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_vm::container::{selector, Entry, StateAccess};

    fn sample() -> Container {
        Container::new(
            vec![0, 1, 2],
            vec![10, 20],
            vec![Entry {
                selector: selector("transfer(Address,u64)"),
                offset: 0,
                access: StateAccess {
                    reads: vec![1],
                    writes: vec![2, 3],
                    ..Default::default()
                },
            }],
        )
    }

    fn sign_with(seed: &[u8; 32], container: &Container) -> Vec<u8> {
        let (_, sk) = ml_dsa::keygen(seed);
        let sig = ml_dsa::sign_os(&sk, &container.identifier(), PROVENANCE_DOMAIN)
            .expect("signing succeeds");
        let mut artifact = container.canonical_bytes();
        artifact.extend_from_slice(&PROVENANCE_TAG);
        artifact.extend_from_slice(&sig);
        artifact
    }

    #[test]
    fn a_container_signed_by_the_trusted_compiler_is_admitted() {
        let seed = [7u8; 32];
        let (pk, _) = ml_dsa::keygen(&seed);
        let verifier = ProvenanceVerifier::with_key(pk);
        let container = sample();
        let artifact = sign_with(&seed, &container);
        assert_eq!(
            verifier.admit(&artifact, &container),
            Some(container.canonical_bytes())
        );
    }

    #[test]
    fn an_unsigned_container_is_rejected() {
        let seed = [7u8; 32];
        let (pk, _) = ml_dsa::keygen(&seed);
        let verifier = ProvenanceVerifier::with_key(pk);
        let container = sample();
        assert_eq!(
            verifier.admit(&container.canonical_bytes(), &container),
            None
        );
    }

    #[test]
    fn a_container_signed_by_another_key_is_rejected() {
        let trusted = [7u8; 32];
        let (pk, _) = ml_dsa::keygen(&trusted);
        let verifier = ProvenanceVerifier::with_key(pk);
        let container = sample();
        let artifact = sign_with(&[9u8; 32], &container);
        assert_eq!(verifier.admit(&artifact, &container), None);
    }

    #[test]
    fn a_tampered_container_under_a_valid_signature_is_rejected() {
        let seed = [7u8; 32];
        let (pk, _) = ml_dsa::keygen(&seed);
        let verifier = ProvenanceVerifier::with_key(pk);
        let container = sample();
        let artifact = sign_with(&seed, &container);
        let mut tampered = sample();
        tampered.consts.push(99);
        assert_eq!(verifier.admit(&artifact, &tampered), None);
    }

    #[test]
    fn the_production_key_decodes_to_a_full_public_key() {
        let key = production_key();
        assert!(key.iter().any(|&b| b != 0));
    }
}
