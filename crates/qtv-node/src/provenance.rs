// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use qtv_vm::container::Container;

pub const PROVENANCE_TAG: [u8; 4] = *b"QPRV";

pub const PROVENANCE_DOMAIN: &[u8] = b"QUANTOVA/QVM/PROVENANCE/v1";

const PRODUCTION_KEY_HEX: &str = "0b6b1fd273b794b0ceb36a4e142d5e3e23cae1427e0d9d4f287511457e160668ee99a5eee0d21bf39675511dc90119207b6e4956c81b95d2b3c6d129b7548971ff504e189c38673038ba008db1f95c6d9ff7136f5f43f290134b4c0e7b6eca5d362444fabe74c790ccd3b8791d7b71d3c069b12d72761908d1ab2c28b990a9312f0bfa710cdb5cb89cfbb58ac460124672b6d0b5a462bf2b461b3d77df37d131c9b49ebbe9f34c3d355ca778f13cd0791de66179842916f8169324ce976cee0e117038ab797bbe9f7d8eff6170c351fefb6b894dfc2684496fb367526a2e038cab826b4794f12d35257ce1a62dea9ad67b676099d2937e196293e524e70186f8718a9679e0b7f9a81c3da916be24504d40d8834cc48c03cb4b9f3045a2605e1e0f013b2c6f807732df5879a2df24d08d451de5a31ff7c7c602f89063eae3cc6c2e5cd14314e0805fbb1a430bed5dd4d7bee6774886cf532945186bdef2d325b75474454fd7c77c187c654b2722f5f2e5d573299fa9a66f1fcfa71d0f0f1ffe46caaf8703b2b08a1cabe2603dfb676fbaa67c5f91623889265eba395c1fdbb10591460265f64d87dd5194a2ad4e325b9a3d202aba1aff1a0ccbe9129d4703241b0a4f9bfda1d4a83654d4315ddeec0a70d86057a16efd3e398b74e53988d28be97702f964721ccf01e9052a8d75235dc14625cb47748af02f18ffbf2ee010217485747a709e001afffaea3bf400b0ee131ccf9639f9d779badcbcc6ec21bb98ae53d0ae8295903cf19257683b94659d07478fd8d0a933a53796cb0d27ecad7f9ab52f74938c8182475118357f149c7d2d510e691321c5a54432f4cb381e3b91b28a0b7c5f544bb0a6327146d0a47a3854d275ca8d01808f910dcd396a69cb4f63855156687057ae29034e199e088edbd4c71eed478314055aa3db342bbc87414d1ac49b3f1aa6b0805cd48280cde6f0b26c3d406eb0524306cbbef63998185c1645407bbaeeef0b0d4f2ac2799f9e3ce0ae2fa4c02eb0fd95ac4e0b8c1bd242e2fc74e91196eece45b5060680db4bba457b3e8ad1e3b983d5cc1bee34eb9c8b128165b94892c374ed959e652cc8f8634b44aed758737b2db9f971ed926a838797cd313e1034bc61d9d314db0b01249d60f8c8fec04e0826b587833ce4264c43eb9710ffe2ed6c80784bd5f1304d8fc062fcb2e98a6c91d1c7ca81eab654b1fa8495e5efd4876629677d764bb8cd5af19011dede1bb9ff2599b7ca3797e5d65b5fed0446dfbd85540cbbaa033002d6d9226de89abbb18f7cfb5848da0c4466d622cc587b3d65063df81647284f76177e049a9cfc7542600c680ad2df53e27a464f94bd2f0437a044eac79996cde0b2228b48344013d18c9d6c1423d9d2f849b98dd7d14ac7ea6c11c19773b2329f6984d8825276112d42e9156614aeeed4d3a7d249f49bf9a972524ac4559518be76acabb6138a4931dac99850b2ecdf4f991e0f51b90fcbe33d8fdcb19ca5dd23f0ce25d20773922855548f8111c9b86a07658f0a5f140769780592774f14a6f7aa4274603ba6a0a7de6a83dd077940ee83330a93c198dd65f33224cac5610732eaa131a1d62d9409d39dc503dd6167304bba91abef4d4d97423b963ca800d678b5051de9891854c5e9e294ea29ac0702f5001eae7bdaa7c5fdbe744c8810438afb63c2b11f51a976dcb33cfbd580a4cd75b98dfadf7eeb60abfbf7515b3eaaea38fe4ff9c4db4b9078e74fd6e50082c3f81b5db24970b478d80aae70bd061315aee3b99ea2164e267eef8bee6559a0a5e1f64f12f6da94d6fe7c4800e775d4050fdac10fd3d97e4b46a5e7df61accf3eee9ca5ca64b338afcaf500269d82be94644d0fe4a674ef5ad475fac693ca28d30aae3066d0992ba31bf1cee63a071a2bcfd3ce189fe419749a7f28249a8ab81bd1149d506b21ff978edb7328e075b3d7ce94a604c2e56b8f391dc8b7327dac6a8776696c49bd16055900584108b8aeebd0ce33c8e55abc5e6eb3966689bb3a7cef9d6e7b60b438f8115b414e381bc4959457b2b20e9fcaf3ee2f01a35cdae9ffaae84695180dc45ecd5ee73bcdd2a97428ee477b69bb12e7d44db5c45e838a3f0e4ad3eeabd9b1f33c2f7394556ddae5ce95214054be862704b7d66df8fbcd2583843a4248aaf487b52881a378e4f21a871ca60c4fad89efd9bfcef212274d64441e4cdf43967ce91d63e58e710f533b939c6642a3ee4203fcb325608836d46bb7b13136e8c323675403942db6d20ac5a69d24dd4ccf37b2734af378adc09905634a1f214d08ea86a74c817ef812800cb2e63a1d26e49ef12e0d99a9b39af09b70fe12f6cb08429a059096dbf5a4ccc9272ebfecb0a1d7e5a9e5a1f507915704b2a19fd671980a599a7a5d5efad4e33959f526022bb42c9797e65dcdf809314a7fc5132412535d6750ca9b2ff53856017d8371daa55b940856afed5f4762d68dc485607bccae4694c248b30f6263407aeaabce9ca041e0a0b590742b4e012326be4740de68bae2a1b2782f06e26eae2371648198cce4584fcabb5b1551a686a5a3d32d09d4de1dd03fded554df10f5551ffd738c74e47bddfa638e8c428b1e3ce38c7d625a1e6465602b72656284f00ac53f4c808d93b6fd6ebe1e157882a93956881f1ef88c02a4161e37d48d7791586b25ed608d1a162f05bc9ff80d589a1ddfaf2e7f4c6154f7e287ed7f4fb0e209f9cc7bb2549681d89270e4813dc1f13879b565";

const LEGACY_TESTNET_KEY_HEX: &str = "df376141560a19a19a17ac69ea4eeabd8f2cf919fb220f087f01af6285aa6f62075c02869af7e6d1cc2dd7f1b85b0ef808fad8af74addb94800c4aa46051516327477fffd6658d2fa6ccd7a956bef653baeb8d07c2ce6959f9c625232bc70a8a6689e9d00459f4caff2e07855a38763d9c2dd901a477673bd0d93dff49af53e695df37f70aae48a9833520544a13a5044ad52cfd46065b8e27a822d7627c4f0525abb8f464f972e900ebd8893d56fade75ca0bc97d2b345415db1baa913a10cdf146535057e37afcd64892ba8c2a678634115d1cbb74496533d84f6273d344ea87476811947487328ec0be7e6f33d2d75b4717f9ab6871d397845fecd16a9c5b72c60a7610150d2e93dc5538a83b7368e99740b42989ccd309ebff86a79c001e7da4ebc070ba92a5690f1ddb72ae88c26e078f704926514df95f9f48d38655d08ee9b88f1a52a9524d18e3f9f71561d2761654f70faa1e9b706d6356af3261e1301adc7eff6a817fba6dcad71eafdc55d77e656f215d5b73f1c39cb94d19a08980bd651a4a58d5df372eff68a55c36bfb97355c1aeb3aeac6ccb16aa4885c8a90ae31d7a32c0abd45ce3d625ff50abbb86f386091118177e6849907dbd086c7af6eaa7e2f790aaa9730225980028865fd63e48b61a0d3842933850d08f728896a9137c926002bf41c76d5a3c87bf88747268d062d69847fe6991e4296d98580e9cc3a873d02c3021ae8eae92486ed10a84cf4cdc63ff84b1a595462d6cba72d4c29e6afc051b24243f3c2563cbe6afe8088ad8cd653cb2cd2d0a15fbf31427edac5bf3846bf23c9f6df166e73ab326a880de479463673745a7f5db0c37a947ce9c58c51c23c7f9cfe0b142f92aee588c3dd0b512a7c3d1816fba6147fbc40f865212c1ca2b5246efb3731adeed0111841d5f58a270af9db07b6521a750e52b1641c134092815cd3c6247d08ef5db1dbccf7c6d1c97af410d4c77442fe7f28c57917292d4932d364a67eb33efd025fa13789ba564fd82947dff97f3a7eb8429ab759cafe4f21c92cfd8fb14d3afec54826d9aa6beead6d1022546275b9dbf4c503629f4ae379f6e7a5d75fdf3fd10233216c218392d3dc5ab04ca660cb82a08f6d9c72539c2641781475bb8600c8ee4eb5efb8129c75708dc6f39c0adefd148d8b8a332bb88b7726c3704ef9260e39ab9936989dc6ab32b1a7d90ccc8fdf06cc3382197766be234eec9ed094ba4044954e8cb4f7fa58b703a1db120a763cc9792791576dfa070b121318966f3f2ab886285095bc3f5d8f7bca921b533b34042e2bf368fa1f550bd4e64e67c327be5cf8a6ce328c1d2f1102ea5712f52bc2a20e4a77d12645389f4f475d39b783f5debab5336e90c4c4fdcd3ec5b91e66ce526531f2fbadd36dd95bb805bb42b6ff226802cdcac46b96b8c8a2dddab46b378f5730110627fb3602bae6d2273cacac3c58f9f281e936fd9c0950f97c901f0b9f9f67659ec27892fd240ffc4ab2027816fa8870df5a4a2736b8de95c2b78f36619556e8b9e0b753b6de9ec6d5b333f9d55787c4db5f42a2e2d4bcd562ad4cd325ea4ab84b3b4a669f163f297c2ee3335fe37cfa766a6cda328e90483f8a2b4b566282e601b16890ba0a0ae2b30d6ad81be6d408e7587a2064c554bc2b12ed1b57c158ad9411f228c525b1ef1f5956672fe3479b2db74a0e03e5b8ca0cadaaec7911ad3496f1315ad7ce81d6f09388a616f1d7bd632882d029e2a19e5b51a083ac8646a01cb9fd229a7531939a802b08a7e4d64decb3222b5469129987e5d2c8c7c2fbb306731cc6b0e3ec9932c78c8b68ad8f877d254714349e9fe4941220a286bd60b990a31b78d3eb867e321bb2dc563c5eea0facde33130b6feb6bece4887aec81eebac15828a8873744bf8fab3e156451a8aa3eda7154cd74af0187373f093f98cfda3258491e888dd692282e14742690a383b2ba7f9b8585f5ba5ffbd64758794f8c8309b3056cd7f6a822fbe8e4207201dcfd108c6646125f33d367093c4e304c25707245e201bc920b904c5599632af46637b523394f04416accdb735b0002eae8ec1a324553b2538f26140c7776472d370507a9118b8464671430c00fa0434ca2cceee0956855b3042df00cbf9d32fe27655f3200c2d8d597ae7c30520e556a0e3eaeface8b67369a3f9f36e3cb51a4d0c252a014633c650e45142c255d733112751824f85fb841121bde7dd4d35f6e2b231fe1feb9451e00e8ad3787cf067918272e266fd1f220d28c0cb7fdf0c6ed9f2d82839e434bb7d67b87fa2c4a0b1b1e79010ec65997c4bb4fbac7d36622c1514fa66bf3abdb674801e9790d865165d919508db09187788c94dcf8ac0df80ee1c566ee4e8006278c83b115d29203aa4ab2d18eff72f7c2bef35be80c985bae6a0cca62a13360bc3dea17fa2935c269310b9921b9021797507dd1ecb890ad63ea4e4b00527d54495f7778187a77852bfac35d2b2039ede300dce4039ec2b1bd3ab4fc8689a656af663686faab3e428dd65a3f7a6db9ff839746c6275892a8c7a5db2d099c5510dbed7ded66170464d56e727ca86999e7c5b8f9927fd6f9d4b3e9966ebc21dc9fdf68e63f21a270f218f947a4ffbc6450d98aed035f890bc75664a57300ab844b3f77e220d52886f87cd9f2bc340000af4cdc8ccde4f29d664e7a9e84f54b3708d980a0d4da06a7112bb49aac8d45fe46a1dd6c7b07dbe6ad9a212abf422f58f92a5df877efaa438";

fn production_key() -> [u8; PUBLIC_KEY_BYTES] {
    key_from_hex(PRODUCTION_KEY_HEX)
}

fn legacy_testnet_key() -> [u8; PUBLIC_KEY_BYTES] {
    key_from_hex(LEGACY_TESTNET_KEY_HEX)
}

fn key_from_hex(text: &str) -> [u8; PUBLIC_KEY_BYTES] {
    let mut key = [0u8; PUBLIC_KEY_BYTES];
    let hex = text.as_bytes();
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
        self.admit_under(&self.key, artifact, container)
    }

    pub fn admit_legacy_testnet(&self, artifact: &[u8], container: &Container) -> Option<Vec<u8>> {
        self.admit_under(&legacy_testnet_key(), artifact, container)
    }

    fn admit_under(
        &self,
        key: &[u8; PUBLIC_KEY_BYTES],
        artifact: &[u8],
        container: &Container,
    ) -> Option<Vec<u8>> {
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
        if !ml_dsa::verify(key, &container.identifier(), &signature, PROVENANCE_DOMAIN) {
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
