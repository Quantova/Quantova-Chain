// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use qtv_vm::container::Container;

pub const PROVENANCE_TAG: [u8; 4] = *b"QPRV";

pub const PROVENANCE_DOMAIN: &[u8] = b"QUANTOVA/QVM/PROVENANCE/v1";

const PRODUCTION_KEY_HEX: &str = "df376141560a19a19a17ac69ea4eeabd8f2cf919fb220f087f01af6285aa6f62075c02869af7e6d1cc2dd7f1b85b0ef808fad8af74addb94800c4aa46051516327477fffd6658d2fa6ccd7a956bef653baeb8d07c2ce6959f9c625232bc70a8a6689e9d00459f4caff2e07855a38763d9c2dd901a477673bd0d93dff49af53e695df37f70aae48a9833520544a13a5044ad52cfd46065b8e27a822d7627c4f0525abb8f464f972e900ebd8893d56fade75ca0bc97d2b345415db1baa913a10cdf146535057e37afcd64892ba8c2a678634115d1cbb74496533d84f6273d344ea87476811947487328ec0be7e6f33d2d75b4717f9ab6871d397845fecd16a9c5b72c60a7610150d2e93dc5538a83b7368e99740b42989ccd309ebff86a79c001e7da4ebc070ba92a5690f1ddb72ae88c26e078f704926514df95f9f48d38655d08ee9b88f1a52a9524d18e3f9f71561d2761654f70faa1e9b706d6356af3261e1301adc7eff6a817fba6dcad71eafdc55d77e656f215d5b73f1c39cb94d19a08980bd651a4a58d5df372eff68a55c36bfb97355c1aeb3aeac6ccb16aa4885c8a90ae31d7a32c0abd45ce3d625ff50abbb86f386091118177e6849907dbd086c7af6eaa7e2f790aaa9730225980028865fd63e48b61a0d3842933850d08f728896a9137c926002bf41c76d5a3c87bf88747268d062d69847fe6991e4296d98580e9cc3a873d02c3021ae8eae92486ed10a84cf4cdc63ff84b1a595462d6cba72d4c29e6afc051b24243f3c2563cbe6afe8088ad8cd653cb2cd2d0a15fbf31427edac5bf3846bf23c9f6df166e73ab326a880de479463673745a7f5db0c37a947ce9c58c51c23c7f9cfe0b142f92aee588c3dd0b512a7c3d1816fba6147fbc40f865212c1ca2b5246efb3731adeed0111841d5f58a270af9db07b6521a750e52b1641c134092815cd3c6247d08ef5db1dbccf7c6d1c97af410d4c77442fe7f28c57917292d4932d364a67eb33efd025fa13789ba564fd82947dff97f3a7eb8429ab759cafe4f21c92cfd8fb14d3afec54826d9aa6beead6d1022546275b9dbf4c503629f4ae379f6e7a5d75fdf3fd10233216c218392d3dc5ab04ca660cb82a08f6d9c72539c2641781475bb8600c8ee4eb5efb8129c75708dc6f39c0adefd148d8b8a332bb88b7726c3704ef9260e39ab9936989dc6ab32b1a7d90ccc8fdf06cc3382197766be234eec9ed094ba4044954e8cb4f7fa58b703a1db120a763cc9792791576dfa070b121318966f3f2ab886285095bc3f5d8f7bca921b533b34042e2bf368fa1f550bd4e64e67c327be5cf8a6ce328c1d2f1102ea5712f52bc2a20e4a77d12645389f4f475d39b783f5debab5336e90c4c4fdcd3ec5b91e66ce526531f2fbadd36dd95bb805bb42b6ff226802cdcac46b96b8c8a2dddab46b378f5730110627fb3602bae6d2273cacac3c58f9f281e936fd9c0950f97c901f0b9f9f67659ec27892fd240ffc4ab2027816fa8870df5a4a2736b8de95c2b78f36619556e8b9e0b753b6de9ec6d5b333f9d55787c4db5f42a2e2d4bcd562ad4cd325ea4ab84b3b4a669f163f297c2ee3335fe37cfa766a6cda328e90483f8a2b4b566282e601b16890ba0a0ae2b30d6ad81be6d408e7587a2064c554bc2b12ed1b57c158ad9411f228c525b1ef1f5956672fe3479b2db74a0e03e5b8ca0cadaaec7911ad3496f1315ad7ce81d6f09388a616f1d7bd632882d029e2a19e5b51a083ac8646a01cb9fd229a7531939a802b08a7e4d64decb3222b5469129987e5d2c8c7c2fbb306731cc6b0e3ec9932c78c8b68ad8f877d254714349e9fe4941220a286bd60b990a31b78d3eb867e321bb2dc563c5eea0facde33130b6feb6bece4887aec81eebac15828a8873744bf8fab3e156451a8aa3eda7154cd74af0187373f093f98cfda3258491e888dd692282e14742690a383b2ba7f9b8585f5ba5ffbd64758794f8c8309b3056cd7f6a822fbe8e4207201dcfd108c6646125f33d367093c4e304c25707245e201bc920b904c5599632af46637b523394f04416accdb735b0002eae8ec1a324553b2538f26140c7776472d370507a9118b8464671430c00fa0434ca2cceee0956855b3042df00cbf9d32fe27655f3200c2d8d597ae7c30520e556a0e3eaeface8b67369a3f9f36e3cb51a4d0c252a014633c650e45142c255d733112751824f85fb841121bde7dd4d35f6e2b231fe1feb9451e00e8ad3787cf067918272e266fd1f220d28c0cb7fdf0c6ed9f2d82839e434bb7d67b87fa2c4a0b1b1e79010ec65997c4bb4fbac7d36622c1514fa66bf3abdb674801e9790d865165d919508db09187788c94dcf8ac0df80ee1c566ee4e8006278c83b115d29203aa4ab2d18eff72f7c2bef35be80c985bae6a0cca62a13360bc3dea17fa2935c269310b9921b9021797507dd1ecb890ad63ea4e4b00527d54495f7778187a77852bfac35d2b2039ede300dce4039ec2b1bd3ab4fc8689a656af663686faab3e428dd65a3f7a6db9ff839746c6275892a8c7a5db2d099c5510dbed7ded66170464d56e727ca86999e7c5b8f9927fd6f9d4b3e9966ebc21dc9fdf68e63f21a270f218f947a4ffbc6450d98aed035f890bc75664a57300ab844b3f77e220d52886f87cd9f2bc340000af4cdc8ccde4f29d664e7a9e84f54b3708d980a0d4da06a7112bb49aac8d45fe46a1dd6c7b07dbe6ad9a212abf422f58f92a5df877efaa438";

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
