// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_crypto::sha3::sha3_256;

pub const DIGEST_LEN: usize = 32;

pub const MAX_SHARDS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Parameters,
    ShardSet,
    ShardLength,
    Singular,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parameters => write!(f, "the erasure parameters were out of range"),
            Error::ShardSet => write!(f, "the shard set was not k distinct shards under n"),
            Error::ShardLength => write!(f, "a shard was not the committed length"),
            Error::Singular => write!(f, "the decode matrix over the chosen shards was singular"),
        }
    }
}

impl std::error::Error for Error {}


struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Field {
    fn build() -> Field {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        let mut power = 0usize;
        while power < 255 {
            exp[power] = x as u8;
            log[x as usize] = power as u8;
            x <<= 1;
            if x & 256 != 0 {
                x ^= 285;
            }
            power += 1;
        }
        exp.copy_within(0..257, 255);
        Field { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "zero has no inverse in the field");
        self.exp[255 - self.log[a as usize] as usize]
    }
}

fn field() -> &'static Field {
    use std::sync::OnceLock;
    static FIELD: OnceLock<Field> = OnceLock::new();
    FIELD.get_or_init(Field::build)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    pub index: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardProof {
    pub siblings: Vec<[u8; DIGEST_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub root: [u8; DIGEST_LEN],
    pub k: usize,
    pub n: usize,
    pub shard_len: usize,
    pub data_len: usize,
}

impl Commitment {
    pub fn verify_shard(&self, shard: &Shard, proof: &ShardProof) -> bool {
        if shard.index >= self.n || shard.bytes.len() != self.shard_len {
            return false;
        }
        let mut node = sha3_256(&shard.bytes);
        let mut index = shard.index;
        let mut width = self.n;
        let mut level = 0;
        while width > 1 {
            let sibling = match proof.siblings.get(level) {
                Some(hash) => hash,
                None => return false,
            };
            node = if index.is_multiple_of(2) {
                pair_hash(&node, sibling)
            } else {
                pair_hash(sibling, &node)
            };
            index /= 2;
            width = width.div_ceil(2);
            level += 1;
        }
        level == proof.siblings.len() && node == self.root
    }
}

pub struct Coded {
    commitment: Commitment,
    shards: Vec<Shard>,
    tree: Vec<Vec<[u8; DIGEST_LEN]>>,
}

impl Coded {
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }

    pub fn shard(&self, index: usize) -> &Shard {
        &self.shards[index]
    }

    pub fn proof(&self, index: usize) -> ShardProof {
        let mut siblings = Vec::new();
        let mut pos = index;
        for level in &self.tree {
            if level.len() <= 1 {
                break;
            }
            let sibling = if pos.is_multiple_of(2) {
                level.get(pos + 1).copied().unwrap_or(level[pos])
            } else {
                level[pos - 1]
            };
            siblings.push(sibling);
            pos /= 2;
        }
        ShardProof { siblings }
    }
}

fn pair_hash(left: &[u8; DIGEST_LEN], right: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut input = [0u8; DIGEST_LEN * 2];
    input[..DIGEST_LEN].copy_from_slice(left);
    input[DIGEST_LEN..].copy_from_slice(right);
    sha3_256(&input)
}

fn merkle_tree(leaves: Vec<[u8; DIGEST_LEN]>) -> Vec<Vec<[u8; DIGEST_LEN]>> {
    let mut levels = vec![leaves];
    while levels.last().expect("a level is present").len() > 1 {
        let level = levels.last().expect("a level is present");
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            let left = level[index];
            let right = if index + 1 < level.len() {
                level[index + 1]
            } else {
                left
            };
            next.push(pair_hash(&left, &right));
            index += 2;
        }
        levels.push(next);
    }
    levels
}

pub fn encode(data: &[u8], k: usize, n: usize) -> Result<Coded, Error> {
    if k == 0 || n < k || n > MAX_SHARDS {
        return Err(Error::Parameters);
    }
    let shard_len = data.len().div_ceil(k).max(1);

    let mut shard_bytes: Vec<Vec<u8>> = Vec::with_capacity(n);
    for piece in 0..k {
        let mut buf = vec![0u8; shard_len];
        let start = piece * shard_len;
        if start < data.len() {
            let end = (start + shard_len).min(data.len());
            buf[..end - start].copy_from_slice(&data[start..end]);
        }
        shard_bytes.push(buf);
    }

    let parity = parity_coefficients(k, n)?;
    for coeffs in &parity {
        shard_bytes.push(combine(coeffs, &shard_bytes[..k], shard_len));
    }

    let leaves: Vec<[u8; DIGEST_LEN]> = shard_bytes.iter().map(|b| sha3_256(b)).collect();
    let tree = merkle_tree(leaves);
    let root = tree.last().expect("the tree has a root")[0];

    let shards = shard_bytes
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| Shard { index, bytes })
        .collect();

    Ok(Coded {
        commitment: Commitment {
            root,
            k,
            n,
            shard_len,
            data_len: data.len(),
        },
        shards,
        tree,
    })
}

pub fn reconstruct(commitment: &Commitment, shards: &[Shard]) -> Result<Vec<u8>, Error> {
    if commitment.k == 0 || commitment.n < commitment.k || commitment.n > MAX_SHARDS {
        return Err(Error::Parameters);
    }
    let k = commitment.k;
    let mut indices: Vec<usize> = Vec::with_capacity(k);
    let mut rows: Vec<&[u8]> = Vec::with_capacity(k);
    for shard in shards {
        if indices.len() == k {
            break;
        }
        if shard.index >= commitment.n || indices.contains(&shard.index) {
            return Err(Error::ShardSet);
        }
        if shard.bytes.len() != commitment.shard_len {
            return Err(Error::ShardLength);
        }
        indices.push(shard.index);
        rows.push(&shard.bytes);
    }
    if indices.len() < k {
        return Err(Error::ShardSet);
    }

    let matrix = decode_matrix(&indices, commitment.n, k)?;
    let inverse = invert(matrix, k)?;

    let shard_len = commitment.shard_len;
    let mut data = Vec::with_capacity(k * shard_len);
    for out_row in inverse.iter().take(k) {
        data.extend_from_slice(&combine(out_row, &rows, shard_len));
    }
    data.truncate(commitment.data_len);
    Ok(data)
}

fn combine<T: AsRef<[u8]>>(coeffs: &[u8], shards: &[T], shard_len: usize) -> Vec<u8> {
    let f = field();
    let mut out = vec![0u8; shard_len];
    for (coeff, shard) in coeffs.iter().zip(shards.iter()) {
        let coeff = *coeff;
        if coeff == 0 {
            continue;
        }
        let bytes = shard.as_ref();
        for (slot, &byte) in out.iter_mut().zip(bytes.iter()) {
            *slot ^= f.mul(coeff, byte);
        }
    }
    out
}

fn parity_coefficients(k: usize, n: usize) -> Result<Vec<Vec<u8>>, Error> {
    let top_inverse = invert(vandermonde(&(0..k).collect::<Vec<_>>(), k), k)?;
    let mut parity = Vec::with_capacity(n - k);
    for index in k..n {
        let row = vandermonde_row(index, k);
        parity.push(row_times_matrix(&row, &top_inverse, k));
    }
    Ok(parity)
}

fn decode_matrix(indices: &[usize], _n: usize, k: usize) -> Result<Vec<Vec<u8>>, Error> {
    let top_inverse = invert(vandermonde(&(0..k).collect::<Vec<_>>(), k), k)?;
    let mut matrix = Vec::with_capacity(k);
    for &index in indices {
        if index < k {
            let mut row = vec![0u8; k];
            row[index] = 1;
            matrix.push(row);
        } else {
            let row = vandermonde_row(index, k);
            matrix.push(row_times_matrix(&row, &top_inverse, k));
        }
    }
    Ok(matrix)
}

fn vandermonde_row(point: usize, k: usize) -> Vec<u8> {
    let f = field();
    let alpha = point as u8;
    let mut row = Vec::with_capacity(k);
    let mut value = 1u8;
    for _ in 0..k {
        row.push(value);
        value = f.mul(value, alpha);
    }
    row
}

fn vandermonde(points: &[usize], k: usize) -> Vec<Vec<u8>> {
    points
        .iter()
        .map(|&point| vandermonde_row(point, k))
        .collect()
}

fn row_times_matrix(row: &[u8], matrix: &[Vec<u8>], k: usize) -> Vec<u8> {
    let f = field();
    let mut out = vec![0u8; k];
    for (r, &coeff) in row.iter().enumerate() {
        if coeff == 0 {
            continue;
        }
        for (slot, value) in out.iter_mut().zip(matrix[r].iter()) {
            *slot ^= f.mul(coeff, *value);
        }
    }
    out
}

fn invert(mut matrix: Vec<Vec<u8>>, k: usize) -> Result<Vec<Vec<u8>>, Error> {
    let f = field();
    let mut inverse: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            let mut row = vec![0u8; k];
            row[i] = 1;
            row
        })
        .collect();

    for col in 0..k {
        let pivot = (col..k)
            .find(|&r| matrix[r][col] != 0)
            .ok_or(Error::Singular)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);

        let scale = f.inv(matrix[col][col]);
        for value in matrix[col].iter_mut() {
            *value = f.mul(*value, scale);
        }
        for value in inverse[col].iter_mut() {
            *value = f.mul(*value, scale);
        }

        for row in 0..k {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                let m = f.mul(factor, matrix[col][c]);
                matrix[row][c] ^= m;
                let i = f.mul(factor, inverse[col][c]);
                inverse[row][c] ^= i;
            }
        }
    }
    Ok(inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = seed.wrapping_add(11400714819323198485);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push((state & 255) as u8);
        }
        out
    }

    #[test]
    fn the_field_multiplies_and_inverts() {
        let f = field();
        assert_eq!(f.mul(0, 5), 0);
        assert_eq!(f.mul(1, 5), 5);
        for a in 1u16..256 {
            let a = a as u8;
            assert_eq!(f.mul(a, f.inv(a)), 1, "element {a} did not invert");
        }
        for a in [1u8, 2, 17, 200, 255] {
            for b in [1u8, 3, 44, 199, 254] {
                assert_eq!(f.mul(a, b), f.mul(b, a));
                for c in [1u8, 7, 128] {
                    assert_eq!(f.mul(f.mul(a, b), c), f.mul(a, f.mul(b, c)));
                }
            }
        }
    }

    #[test]
    fn data_shards_carry_the_payload_untouched() {
        let data = payload(400, 1);
        let coded = encode(&data, 4, 8).expect("encode");
        let mut rebuilt = Vec::new();
        for shard in coded.shards().iter().take(4) {
            rebuilt.extend_from_slice(&shard.bytes);
        }
        rebuilt.truncate(data.len());
        assert_eq!(rebuilt, data);
    }

    #[test]
    fn any_k_of_n_reconstructs_byte_for_byte() {
        let data = payload(1000, 2);
        let k = 4;
        let n = 8;
        let coded = encode(&data, k, n).expect("encode");
        let commitment = coded.commitment().clone();
        let mut count = 0;
        for a in 0..n {
            for b in (a + 1)..n {
                for c in (b + 1)..n {
                    for d in (c + 1)..n {
                        let chosen = [a, b, c, d]
                            .iter()
                            .map(|&i| coded.shard(i).clone())
                            .collect::<Vec<_>>();
                        let out = reconstruct(&commitment, &chosen).expect("reconstruct");
                        assert_eq!(out, data, "subset {a}{b}{c}{d} did not reconstruct");
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, 70);
    }

    #[test]
    fn parity_only_reconstruction_holds() {
        let data = payload(777, 3);
        let coded = encode(&data, 4, 8).expect("encode");
        let parity: Vec<Shard> = coded.shards().iter().skip(4).cloned().collect();
        let out = reconstruct(coded.commitment(), &parity).expect("reconstruct");
        assert_eq!(out, data);
    }

    #[test]
    fn a_realistic_rate_reconstructs_from_a_random_subset() {
        let data = payload(64 * 1024, 4);
        let k = 16;
        let n = 32;
        let coded = encode(&data, k, n).expect("encode");
        let picks = [1, 3, 4, 7, 8, 11, 12, 15, 17, 19, 20, 23, 24, 27, 28, 31];
        let chosen: Vec<Shard> = picks.iter().map(|&i| coded.shard(i).clone()).collect();
        let out = reconstruct(coded.commitment(), &chosen).expect("reconstruct");
        assert_eq!(out, data);
    }

    #[test]
    fn every_shard_verifies_against_the_commitment() {
        let data = payload(2000, 5);
        let coded = encode(&data, 8, 12).expect("encode");
        let commitment = coded.commitment();
        for i in 0..commitment.n {
            assert!(
                commitment.verify_shard(coded.shard(i), &coded.proof(i)),
                "shard {i} did not verify"
            );
        }
    }

    #[test]
    fn a_wrong_shard_is_rejected() {
        let data = payload(2000, 6);
        let coded = encode(&data, 8, 12).expect("encode");
        let commitment = coded.commitment();

        let mut corrupt = coded.shard(3).clone();
        corrupt.bytes[0] ^= 1;
        assert!(!commitment.verify_shard(&corrupt, &coded.proof(3)));

        let mut misplaced = coded.shard(3).clone();
        misplaced.index = 5;
        assert!(!commitment.verify_shard(&misplaced, &coded.proof(3)));
        assert!(!commitment.verify_shard(&misplaced, &coded.proof(5)));

        let mut short = coded.shard(3).clone();
        short.bytes.pop();
        assert!(!commitment.verify_shard(&short, &coded.proof(3)));
    }

    #[test]
    fn the_coding_is_deterministic() {
        let data = payload(1234, 7);
        let a = encode(&data, 6, 10).expect("encode");
        let b = encode(&data, 6, 10).expect("encode");
        assert_eq!(a.commitment(), b.commitment());
        assert_eq!(a.shards(), b.shards());
    }

    #[test]
    fn odd_and_short_payloads_round_trip() {
        for (len, k, n) in [(1usize, 4usize, 8usize), (5, 4, 7), (101, 8, 11), (0, 3, 6)] {
            let data = payload(len, len as u64);
            let coded = encode(&data, k, n).expect("encode");
            let chosen: Vec<Shard> = coded.shards().iter().take(k).cloned().collect();
            let out = reconstruct(coded.commitment(), &chosen).expect("reconstruct");
            assert_eq!(out, data, "len {len} k {k} n {n} did not round trip");
        }
    }

    #[test]
    fn reconstruction_refuses_too_few_or_repeated_shards() {
        let data = payload(500, 8);
        let coded = encode(&data, 4, 8).expect("encode");
        let commitment = coded.commitment();
        let few: Vec<Shard> = coded.shards().iter().take(3).cloned().collect();
        assert_eq!(reconstruct(commitment, &few), Err(Error::ShardSet));
        let repeated = vec![
            coded.shard(0).clone(),
            coded.shard(0).clone(),
            coded.shard(1).clone(),
            coded.shard(2).clone(),
        ];
        assert_eq!(reconstruct(commitment, &repeated), Err(Error::ShardSet));
    }

    #[test]
    fn bad_parameters_are_refused() {
        assert_eq!(encode(&[1, 2, 3], 0, 4).err(), Some(Error::Parameters));
        assert_eq!(encode(&[1, 2, 3], 4, 3).err(), Some(Error::Parameters));
        assert_eq!(encode(&[1, 2, 3], 4, 300).err(), Some(Error::Parameters));
    }

    #[test]
    fn reconstruct_fails_closed_on_an_unbounded_commitment() {
        let hostile = Commitment {
            root: [0u8; DIGEST_LEN],
            k: usize::MAX,
            n: usize::MAX,
            shard_len: 1,
            data_len: 1,
        };
        assert_eq!(reconstruct(&hostile, &[]), Err(Error::Parameters));

        let over_cap = Commitment {
            root: [0u8; DIGEST_LEN],
            k: 2,
            n: MAX_SHARDS + 1,
            shard_len: 1,
            data_len: 1,
        };
        assert_eq!(reconstruct(&over_cap, &[]), Err(Error::Parameters));
    }
}
