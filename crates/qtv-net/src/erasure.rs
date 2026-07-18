//! Erasure coding of a payload into k data shards and n minus k parity shards, so
//! any k of the n shards reconstruct the payload byte for byte, together with a
//! SHA3 Merkle commitment over the shard hashes that authenticates a shard before
//! it is used and rejects a wrong one.
//!
//! The code is a systematic Reed Solomon code over the field of 256 elements. The
//! first k shards are the payload split into k equal pieces, so a node that already
//! holds the data shards reads the payload straight off them, and the remaining n
//! minus k shards are parity drawn from a Vandermonde generator, so any k of the n
//! shards, data or parity in any mix, invert back to the payload. The field
//! arithmetic and the linear algebra are the standard library alone. The only
//! cryptographic dependency is qtv-crypto, whose SHA3 fixes each shard hash and
//! their Merkle root.
//!
//! This is coding theory, not cryptography. It adds redundancy so a block survives
//! the loss of some shards, and it lowers the bytes a node downloads to take part
//! in propagation, since a node fetches its share of the shards rather than the
//! whole block. Shard integrity rests on the SHA3 commitment over the shard hashes,
//! not on any new primitive. The commitment travels bound to the block header, so a
//! shard is checked against the root before it is used and a reconstructed payload
//! is checked against the header the code committed to.

use qtv_crypto::sha3::sha3_256;

/// The length in bytes of a shard hash and of the Merkle root, the SHA3-256 digest
/// length.
pub const DIGEST_LEN: usize = 32;

/// The largest number of shards a payload codes into. The generator draws a
/// distinct field element for each shard, and the field holds 256 elements, so the
/// shard count cannot exceed the field size.
pub const MAX_SHARDS: usize = 256;

/// A reason erasure coding refused its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The parameters were out of range: k was zero, n was below k, or n exceeded
    /// the field size.
    Parameters,
    /// Reconstruction was given fewer than k shards, a shard index at or above n, or
    /// two shards at one index, so the decode matrix was not a full set of k rows.
    ShardSet,
    /// A shard did not carry the committed shard length.
    ShardLength,
    /// The decode matrix over the chosen shards was singular, which a distinct
    /// Vandermonde never produces and so only a malformed index set can reach.
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

// The field of 256 elements, built over the primitive polynomial
// x^8 + x^4 + x^3 + x^2 + 1 with generator two. Addition is exclusive or;
// multiplication runs through the log and exponent tables so a byte product is two
// lookups and an add.

/// The exponent and logarithm tables of the field, built once on first use.
struct Field {
    /// The generator raised to each power, doubled in length so a sum of two
    /// logarithms indexes it without a modular reduction.
    exp: [u8; 512],
    /// The logarithm of each nonzero element to the generator base.
    log: [u8; 256],
}

impl Field {
    /// Build the tables by walking the powers of the generator through the field.
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
        // The upper half repeats the lower so a sum of two logarithms, each below
        // 255, indexes the exponent table without a modular reduction.
        exp.copy_within(0..257, 255);
        Field { exp, log }
    }

    /// The product of two field elements.
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    /// The multiplicative inverse of a nonzero field element.
    fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "zero has no inverse in the field");
        self.exp[255 - self.log[a as usize] as usize]
    }
}

/// The field tables, initialized once and shared for the process.
fn field() -> &'static Field {
    use std::sync::OnceLock;
    static FIELD: OnceLock<Field> = OnceLock::new();
    FIELD.get_or_init(Field::build)
}

/// A single coded shard, its position among the n shards and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// The shard position, from zero below n. Positions under k are data shards, the
    /// rest are parity.
    pub index: usize,
    /// The shard bytes, all of the committed shard length.
    pub bytes: Vec<u8>,
}

/// A Merkle inclusion proof of one shard hash under the commitment root, the sibling
/// hashes from the leaf up to the root. The direction at each level follows from the
/// shard index and the shard count, so the proof carries only the siblings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardProof {
    /// The sibling hashes from the leaf level up to the level below the root.
    pub siblings: Vec<[u8; DIGEST_LEN]>,
}

/// The commitment a block header carries over its shards: the Merkle root over the
/// n shard hashes and the parameters that fix the coding. A shard is verified
/// against the root before it is used, and the parameters let any k verified shards
/// reconstruct the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The Merkle root over the n shard hashes under SHA3-256.
    pub root: [u8; DIGEST_LEN],
    /// The number of data shards, the count that reconstructs the payload.
    pub k: usize,
    /// The total number of shards, data plus parity.
    pub n: usize,
    /// The length in bytes of every shard.
    pub shard_len: usize,
    /// The length in bytes of the original payload, so reconstruction trims the
    /// padding the split added.
    pub data_len: usize,
}

impl Commitment {
    /// Verify a shard against the commitment: its index names one of the n shards,
    /// it carries the committed length, and its hash sits at that index under the
    /// root by the Merkle proof. A corrupted or misplaced shard fails here and is
    /// rejected before it is used.
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

/// A coded payload: its commitment, the n shards, and the Merkle tree that proves a
/// shard against the root. The producer disperses the shards over the overlay and
/// binds the commitment to the block header.
pub struct Coded {
    commitment: Commitment,
    shards: Vec<Shard>,
    tree: Vec<Vec<[u8; DIGEST_LEN]>>,
}

impl Coded {
    /// The commitment over the shards, the value the block header carries.
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// The n shards in index order.
    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }

    /// One shard by index.
    pub fn shard(&self, index: usize) -> &Shard {
        &self.shards[index]
    }

    /// The Merkle proof that authenticates the shard at an index against the root.
    pub fn proof(&self, index: usize) -> ShardProof {
        let mut siblings = Vec::new();
        let mut pos = index;
        for level in &self.tree {
            if level.len() <= 1 {
                break;
            }
            let sibling = if pos.is_multiple_of(2) {
                // The successor, or the node itself when it is the last of an odd
                // level and pairs with a copy of itself.
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

/// The SHA3-256 hash of a left node followed by a right node, the Merkle pairing.
fn pair_hash(left: &[u8; DIGEST_LEN], right: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut input = [0u8; DIGEST_LEN * 2];
    input[..DIGEST_LEN].copy_from_slice(left);
    input[DIGEST_LEN..].copy_from_slice(right);
    sha3_256(&input)
}

/// Build the Merkle tree over the leaf hashes, a vector of levels from the leaves up
/// to the single root. A level with an odd count pairs its last node with a copy of
/// itself, the same rule the block transaction root uses.
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

/// Split a payload into k data shards, extend it to n shards with n minus k parity,
/// and commit to the n shards under a SHA3 Merkle root. The first k shards are the
/// payload cut into k equal pieces, zero padded to a whole shard, so they carry the
/// data directly, and the parity shards come from a Vandermonde generator so any k
/// of the n reconstruct the payload. The coding is deterministic, so one payload
/// always yields the same shards and the same root.
pub fn encode(data: &[u8], k: usize, n: usize) -> Result<Coded, Error> {
    if k == 0 || n < k || n > MAX_SHARDS {
        return Err(Error::Parameters);
    }
    let shard_len = data.len().div_ceil(k).max(1);

    // The k data shards: the payload cut into k pieces of the shard length, the last
    // piece zero padded. Reconstruction trims back to the payload length.
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

    // The parity shards: each is a Vandermonde combination of the k data shards
    // under the systematic generator, so the data shards stay untouched and any k
    // shards invert back to them.
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

/// Reconstruct the payload from any k shards under a commitment. The caller has
/// verified each shard against the commitment root, so this trusts the bytes and
/// solves the k by k decode system the shard indices name, then trims the padding to
/// the committed payload length. The result is byte for byte the original payload.
pub fn reconstruct(commitment: &Commitment, shards: &[Shard]) -> Result<Vec<u8>, Error> {
    let k = commitment.k;
    // Take the first k distinct shards, refusing an index at or above n, a repeat, or
    // a shard of the wrong length.
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

    // The decode matrix: row r is the generator row for shard indices[r], an identity
    // row for a data shard and a Vandermonde parity row for a parity shard. Inverting
    // it maps the received shards back to the k data shards.
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

/// Combine a coefficient row over a set of equal length shards into one shard, the
/// field sum of each shard scaled by its coefficient. This is one row of a matrix by
/// shard product, the operation both encoding and decoding run.
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

/// The parity rows of the systematic generator, the bottom n minus k rows of the
/// Vandermonde generator once its top k by k block is reduced to the identity. Each
/// row combines the k data shards into one parity shard.
fn parity_coefficients(k: usize, n: usize) -> Result<Vec<Vec<u8>>, Error> {
    let top_inverse = invert(vandermonde(&(0..k).collect::<Vec<_>>(), k), k)?;
    let mut parity = Vec::with_capacity(n - k);
    for index in k..n {
        let row = vandermonde_row(index, k);
        parity.push(row_times_matrix(&row, &top_inverse, k));
    }
    Ok(parity)
}

/// The decode matrix over a set of received shard indices: the generator rows the
/// indices name. A data index gives an identity row, a parity index gives its
/// systematic parity row.
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

/// One row of the Vandermonde generator for an evaluation point, the point raised to
/// the powers zero through k minus one over the field.
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

/// The Vandermonde matrix over a set of evaluation points, one row per point.
fn vandermonde(points: &[usize], k: usize) -> Vec<Vec<u8>> {
    points
        .iter()
        .map(|&point| vandermonde_row(point, k))
        .collect()
}

/// A row vector times a matrix over the field, the product with each column.
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

/// Invert a k by k matrix over the field by Gauss Jordan elimination, or report that
/// it is singular. The generator is a distinct Vandermonde, so every k row selection
/// is invertible and a singular result only follows from a malformed index set.
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
        // Find a pivot row at or below the column with a nonzero entry in the column.
        let pivot = (col..k)
            .find(|&r| matrix[r][col] != 0)
            .ok_or(Error::Singular)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);

        // Scale the pivot row so its pivot entry is one.
        let scale = f.inv(matrix[col][col]);
        for value in matrix[col].iter_mut() {
            *value = f.mul(*value, scale);
        }
        for value in inverse[col].iter_mut() {
            *value = f.mul(*value, scale);
        }

        // Eliminate the column from every other row.
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

    /// A deterministic pseudo random payload of a length, so a test drives real bytes
    /// rather than a constant pattern the code could special case.
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
        // Every nonzero element times its inverse is one.
        for a in 1u16..256 {
            let a = a as u8;
            assert_eq!(f.mul(a, f.inv(a)), 1, "element {a} did not invert");
        }
        // Multiplication is commutative and associative over a sample.
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
        // The systematic data shards are the payload cut into k pieces.
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
        // Every choice of k of the n shards reconstructs the exact payload.
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
        // All seventy choices of four of eight were exercised.
        assert_eq!(count, 70);
    }

    #[test]
    fn parity_only_reconstruction_holds() {
        let data = payload(777, 3);
        let coded = encode(&data, 4, 8).expect("encode");
        // The four parity shards alone reconstruct the payload, the hardest subset.
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
        // A scattered choice of sixteen of thirty two, a mix of data and parity.
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

        // A flipped byte fails its Merkle proof.
        let mut corrupt = coded.shard(3).clone();
        corrupt.bytes[0] ^= 1;
        assert!(!commitment.verify_shard(&corrupt, &coded.proof(3)));

        // A shard offered under the wrong index fails against the sibling path of the
        // claimed position.
        let mut misplaced = coded.shard(3).clone();
        misplaced.index = 5;
        assert!(!commitment.verify_shard(&misplaced, &coded.proof(3)));
        assert!(!commitment.verify_shard(&misplaced, &coded.proof(5)));

        // A shard of the wrong length fails on the length check.
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
        // A payload that does not divide by k, and a payload shorter than k, both
        // reconstruct exactly after the zero padding is trimmed.
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
        // Fewer than k shards cannot reconstruct.
        let few: Vec<Shard> = coded.shards().iter().take(3).cloned().collect();
        assert_eq!(reconstruct(commitment, &few), Err(Error::ShardSet));
        // A repeated index is not k distinct rows.
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
}
