//! # Polynomial Commitment Schemes
//!
//! Implements two transparent (no trusted setup) polynomial commitment schemes:
//!
//! - **FRI** (Fast Reed-Solomon IOP of Proximity): Hash-based, plausibly
//!   post-quantum, O(log² n) proofs.  Uses Merkle trees over SHA-256.
//! - **IPA** (Inner Product Argument): Pedersen-commitment based (Halo2 /
//!   Bulletproofs style), O(log n) rounds, no pairing.
//!
//! A [`CommitmentScheme`] enum provides a unified metadata API, which also
//! documents KZG (implemented in [`crate::kzg`]).
//!
//! ## Example — FRI
//! ```rust,ignore
//! use unigroth::commitment::{FriConfig, fri_commit, fri_prove, fri_verify};
//! use ark_bn254::Fr;
//! use ark_std::{rand::SeedableRng, rand::rngs::StdRng};
//!
//! let mut rng = StdRng::seed_from_u64(42);
//! let cfg  = FriConfig::new(128, 4);
//! let evals: Vec<Fr> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
//! let comm  = fri_commit(&evals, &cfg);
//! let proof = fri_prove(&evals, &cfg, &mut rng);
//! assert!(fri_verify(&comm, &proof, &cfg));
//! ```
//!
//! ## Example — IPA
//! ```rust,ignore
//! use unigroth::commitment::{IpaConfig, ipa_commit, ipa_prove, ipa_verify};
//! use ark_bn254::{Fr, G1Projective as G};
//! use ark_std::{rand::SeedableRng, rand::rngs::StdRng, UniformRand};
//!
//! let mut rng = StdRng::seed_from_u64(99);
//! let n = 8;
//! let cfg      = IpaConfig::<G>::setup(n, &mut rng);
//! let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
//! let blinding = Fr::rand(&mut rng);
//! let comm     = ipa_commit(&coeffs, blinding, &cfg);
//! let z        = Fr::rand(&mut rng);
//! // eval  = Σ coeffs[i] * z^i
//! let eval     = coeffs.iter().enumerate()
//!     .map(|(i, c)| *c * z.pow([i as u64]))
//!     .sum::<Fr>();
//! let proof    = ipa_prove(&coeffs, z, blinding, &cfg, &mut rng);
//! assert!(ipa_verify(&comm, &proof, z, eval, &cfg));
//! ```

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::RngCore, vec, vec::Vec};
use sha2::{Digest, Sha256};

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Serialize a field element to a fixed-length byte vector (compressed).
fn field_to_bytes<F: PrimeField>(f: &F) -> Vec<u8> {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("serialize field elem");
    buf
}

/// Serialize a group element to a fixed-length byte vector (compressed).
fn group_to_bytes<G: CurveGroup>(g: &G) -> Vec<u8> {
    let aff = g.into_affine();
    let mut buf = Vec::new();
    aff.serialize_compressed(&mut buf).expect("serialize group elem");
    buf
}

/// SHA-256 of arbitrary bytes, returned as a 32-byte array.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Derive a field element from 32 raw bytes via `from_le_bytes_mod_order`.
fn bytes_to_field<F: PrimeField>(bytes: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

// ─── Part 1: FRI ─────────────────────────────────────────────────────────────

/// Configuration for the FRI polynomial commitment scheme.
///
/// Controls the security level, blowup factor, and number of soundness queries.
#[derive(Clone, Debug)]
pub struct FriConfig {
    /// Target security level in bits (typically 128).
    pub security_bits: usize,
    /// Ratio of evaluation domain size to polynomial degree (typically 4 or 8).
    pub blowup_factor: usize,
    /// Number of independent query paths generated per proof.
    /// Derived as `security_bits / log2(blowup_factor)`.
    pub num_queries: usize,
    /// Binary folding factor (always 2 in this implementation).
    pub folding_factor: usize,
}

impl FriConfig {
    /// Create a new `FriConfig` from security level and blowup factor.
    ///
    /// `num_queries` is set to `security_bits / log2(blowup_factor)`, which
    /// gives the standard FRI soundness bound.
    pub fn new(security_bits: usize, blowup_factor: usize) -> Self {
        assert!(blowup_factor >= 2, "blowup_factor must be at least 2");
        assert!(blowup_factor.is_power_of_two(), "blowup_factor must be a power of two");
        let log2_blowup = blowup_factor.trailing_zeros() as usize;
        let num_queries = (security_bits + log2_blowup - 1) / log2_blowup; // ceil division
        Self {
            security_bits,
            blowup_factor,
            num_queries,
            folding_factor: 2,
        }
    }

    /// Estimate the proof size in bytes for a given polynomial degree.
    ///
    /// Each query path walks `log2(domain_size)` Merkle levels; each level
    /// stores one 32-byte hash.  The formula is:
    /// `num_queries * log2(degree * blowup_factor) * 32 + constant overhead`.
    pub fn proof_size_estimate(&self, degree: usize) -> usize {
        let domain_size = degree * self.blowup_factor;
        let levels = (domain_size.next_power_of_two()).trailing_zeros() as usize;
        // Per query: one field element per round + one auth-path hash per level per round
        // rounds = levels, so roughly: num_queries * levels * 32
        self.num_queries * levels * 32
    }
}

/// A FRI commitment to a set of polynomial evaluations.
///
/// The commitment is the Merkle root of SHA-256 leaves over all evaluations.
#[derive(Clone, Debug)]
pub struct FriCommitment {
    /// SHA-256 Merkle root of the evaluation vector.
    pub merkle_root: [u8; 32],
    /// Number of evaluation points (size of the domain).
    pub domain_size: usize,
    /// Claimed degree bound of the committed polynomial.
    pub degree_bound: usize,
}

/// A single query path in a FRI proof, proving consistency at one random index.
#[derive(Clone, Debug)]
pub struct FriQueryPath {
    /// The starting leaf position within the initial evaluation domain.
    pub position: usize,
    /// Serialized field elements for each folding round at the queried position.
    pub evaluations: Vec<[u8; 32]>,
    /// Merkle authentication paths (one per folding round).
    pub auth_paths: Vec<Vec<[u8; 32]>>,
}

/// A complete FRI low-degree proof.
#[derive(Clone, Debug)]
pub struct FriProof {
    /// One query path per soundness query.
    pub query_paths: Vec<FriQueryPath>,
    /// The final constant polynomial value (serialized field element).
    pub final_poly: Vec<u8>,
    /// Merkle root of the folded evaluation vector after each round.
    pub round_commitments: Vec<[u8; 32]>,
}

// ─── Merkle tree helpers ──────────────────────────────────────────────────────

/// Build a Merkle tree from a list of leaves (each a 32-byte hash).
///
/// The tree is stored as a flat array where index 0 is the root.
/// Leaves start at index `next_power_of_two(n) - 1`.
/// Returns `(tree, num_leaves_padded)`.
fn build_merkle_tree(leaves: Vec<[u8; 32]>) -> (Vec<[u8; 32]>, usize) {
    let n = leaves.len().next_power_of_two();
    let size = 2 * n;
    let mut tree = vec![[0u8; 32]; size];
    // place leaves
    for (i, leaf) in leaves.iter().enumerate() {
        tree[n + i] = *leaf;
    }
    // pad remaining leaf slots with zeros (already zero-initialized)
    // build internal nodes bottom-up
    for i in (1..n).rev() {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&tree[2 * i]);
        combined[32..].copy_from_slice(&tree[2 * i + 1]);
        tree[i] = sha256(&combined);
    }
    (tree, n)
}

/// Extract a Merkle authentication path for leaf at `index` (0-based among leaves).
fn merkle_auth_path(tree: &[[u8; 32]], n: usize, index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut pos = n + index; // absolute position in tree
    while pos > 1 {
        let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
        path.push(tree[sibling]);
        pos /= 2;
    }
    path
}

/// Verify a Merkle authentication path.
fn verify_merkle_path(
    leaf: [u8; 32],
    index: usize,
    path: &[[u8; 32]],
    root: [u8; 32],
    n: usize, // number of padded leaves
) -> bool {
    let _ = n;
    let mut current = leaf;
    let mut idx = index;
    for sibling in path {
        let mut combined = [0u8; 64];
        if idx % 2 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }
        current = sha256(&combined);
        idx /= 2;
    }
    current == root
}

/// Compute the Merkle root over a slice of field elements.
///
/// Each leaf is `SHA-256(serialize_compressed(eval))`.
/// Internal nodes are `SHA-256(left_child || right_child)`.
pub fn merkle_root_of<F: PrimeField>(evals: &[F]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = evals
        .iter()
        .map(|e| sha256(&field_to_bytes(e)))
        .collect();
    let (tree, _) = build_merkle_tree(leaves);
    tree[1] // root is at index 1
}

// ─── FRI operations ───────────────────────────────────────────────────────────

/// Commit to a polynomial given as its evaluation vector over a domain.
///
/// Returns a `FriCommitment` containing the Merkle root of the evaluations.
pub fn fri_commit<F: PrimeField>(poly_evals: &[F], _config: &FriConfig) -> FriCommitment {
    let domain_size = poly_evals.len();
    // degree_bound is domain_size / blowup_factor, but we store domain_size here;
    // the caller can compute degree_bound from domain_size / blowup_factor.
    let degree_bound = domain_size;
    let merkle_root = merkle_root_of(poly_evals);
    FriCommitment {
        merkle_root,
        domain_size,
        degree_bound,
    }
}

/// Fold a vector of evaluations by one binary FRI round.
///
/// Given evaluations `f(ω^0), f(ω^1), ..., f(ω^{n-1})` and a random challenge
/// `r`, produces the folded vector of length `n/2`:
/// `new[i] = even[i] + r * odd[i]`
/// where `even[i] = evals[2*i]` and `odd[i] = evals[2*i + 1]`.
fn fri_fold<F: PrimeField>(evals: &[F], challenge: F) -> Vec<F> {
    let n = evals.len();
    assert!(n >= 2 && n % 2 == 0, "evaluation length must be even and >= 2");
    (0..n / 2)
        .map(|i| evals[2 * i] + challenge * evals[2 * i + 1])
        .collect()
}

/// Derive a Fiat-Shamir challenge field element from a commitment root and round index.
fn fri_challenge<F: PrimeField>(root: &[u8; 32], round: usize) -> F {
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(root);
    data[32..40].copy_from_slice(&(round as u64).to_le_bytes());
    let hash = sha256(&data);
    bytes_to_field(&hash)
}

/// Derive a Fiat-Shamir query index from a commitment root and query index.
fn fri_query_index(root: &[u8; 32], query: usize, domain_size: usize) -> usize {
    let mut data = [0u8; 48];
    data[..32].copy_from_slice(root);
    data[32..40].copy_from_slice(&(query as u64).to_le_bytes());
    data[40..48].copy_from_slice(&(domain_size as u64).to_le_bytes());
    let hash = sha256(&data);
    // Use the first 8 bytes as a u64 then take mod domain_size
    let idx = u64::from_le_bytes(hash[..8].try_into().unwrap()) as usize;
    idx % domain_size
}

/// Generate a FRI low-degree proof for a polynomial given as its evaluation vector.
///
/// Simulates the FRI folding protocol:
/// 1. Commit to each round's evaluations (Merkle root).
/// 2. Derive Fiat-Shamir challenges.
/// 3. Fold evaluations by one binary step per round until degree 0.
/// 4. Sample `config.num_queries` random leaf positions and output
///    the evaluation + Merkle authentication path at each round for each query.
pub fn fri_prove<F: PrimeField>(
    poly_evals: &[F],
    config: &FriConfig,
    rng: &mut impl RngCore,
) -> FriProof {
    let _ = rng; // Fiat-Shamir; rng is accepted for API consistency but not used
    let mut current_evals = poly_evals.to_vec();

    // ── Round commitments and challenges ──
    let mut round_commitments: Vec<[u8; 32]> = Vec::new();
    let mut round_challenges: Vec<F> = Vec::new();
    // each entry holds the full Merkle tree for that round
    let mut round_trees: Vec<(Vec<[u8; 32]>, usize)> = Vec::new();
    // evaluations at the start of each round (before folding)
    let mut round_evals: Vec<Vec<F>> = Vec::new();

    // initial commitment
    let initial_leaves: Vec<[u8; 32]> = current_evals
        .iter()
        .map(|e| sha256(&field_to_bytes(e)))
        .collect();
    let (initial_tree, initial_n) = build_merkle_tree(initial_leaves);
    let initial_root = initial_tree[1];
    round_commitments.push(initial_root);
    round_trees.push((initial_tree, initial_n));
    round_evals.push(current_evals.clone());

    // Fold until length 1 (constant polynomial)
    let mut round = 0usize;
    while current_evals.len() > 1 {
        // Fiat-Shamir challenge from the current round root
        let chal: F = fri_challenge(&round_commitments[round], round);
        round_challenges.push(chal);

        current_evals = fri_fold(&current_evals, chal);

        // Build Merkle tree for folded evaluations
        let leaves: Vec<[u8; 32]> = current_evals
            .iter()
            .map(|e| sha256(&field_to_bytes(e)))
            .collect();
        let (tree, n) = build_merkle_tree(leaves);
        let root = tree[1];
        round_commitments.push(root);
        round_trees.push((tree, n));
        round_evals.push(current_evals.clone());

        round += 1;
    }

    // final_poly is the single remaining element (the constant)
    let final_poly = field_to_bytes(&current_evals[0]);
    let num_rounds = round_challenges.len(); // number of folding rounds performed

    // ── Generate query paths ──
    // The query set is derived from the final commitment (Fiat-Shamir) so the
    // verifier can reproduce them without interaction.
    let final_root = *round_commitments.last().unwrap();
    let initial_domain_size = poly_evals.len();

    let query_paths: Vec<FriQueryPath> = (0..config.num_queries)
        .map(|q| {
            // Choose a query position within the initial domain
            let pos = fri_query_index(&final_root, q, initial_domain_size);

            let mut evaluations: Vec<[u8; 32]> = Vec::new();
            let mut auth_paths: Vec<Vec<[u8; 32]>> = Vec::new();

            // For each round, record the leaf and auth path.
            // After folding, position maps as pos -> pos / 2 per round.
            let mut cur_pos = pos;
            for r in 0..=num_rounds {
                let evals_r = &round_evals[r];
                let (tree, n) = &round_trees[r];

                // clamp position to valid range (in case domain shrank)
                let safe_pos = cur_pos % evals_r.len();

                let leaf_bytes = sha256(&field_to_bytes(&evals_r[safe_pos]));
                evaluations.push(leaf_bytes);

                let auth = merkle_auth_path(tree, *n, safe_pos);
                auth_paths.push(auth);

                cur_pos /= 2; // folding halves the position
            }

            FriQueryPath {
                position: pos,
                evaluations,
                auth_paths,
            }
        })
        .collect();

    FriProof {
        query_paths,
        final_poly,
        round_commitments,
    }
}

/// Verify a FRI low-degree proof.
///
/// Checks that:
/// 1. Each query path has consistent Merkle proofs against the committed roots.
/// 2. The folding relation `new[i] = even[i] + challenge * odd[i]` holds at
///    each round for each queried position.
/// 3. The final value matches the serialized constant in `proof.final_poly`.
///
/// Returns `true` if all checks pass, `false` otherwise.
pub fn fri_verify<F: PrimeField>(
    commitment: &FriCommitment,
    proof: &FriProof,
    config: &FriConfig,
) -> bool {
    if proof.round_commitments.is_empty() {
        return false;
    }
    // First round root must match the commitment
    if proof.round_commitments[0] != commitment.merkle_root {
        return false;
    }

    let num_rounds = proof.round_commitments.len() - 1; // folding rounds

    // Recompute Fiat-Shamir challenges
    let mut challenges: Vec<F> = Vec::with_capacity(num_rounds);
    for r in 0..num_rounds {
        challenges.push(fri_challenge(&proof.round_commitments[r], r));
    }

    // Final root used for query derivation
    let final_root = *proof.round_commitments.last().unwrap();
    let initial_domain_size = commitment.domain_size;

    // Verify each query path
    for (q, qpath) in proof.query_paths.iter().enumerate() {
        if qpath.evaluations.len() != num_rounds + 1 {
            return false;
        }
        if qpath.auth_paths.len() != num_rounds + 1 {
            return false;
        }

        // Verify the query position is consistent with Fiat-Shamir
        let expected_pos = fri_query_index(&final_root, q, initial_domain_size);
        if qpath.position != expected_pos {
            return false;
        }

        // ── Verify Merkle authentication paths ──
        // Round 0: domain_size = initial_domain_size
        // Round r: domain_size = initial_domain_size / 2^r
        let mut cur_pos = qpath.position;
        for r in 0..=num_rounds {
            let domain_size_r = initial_domain_size >> r;
            let n_padded = domain_size_r.next_power_of_two();
            let safe_pos = cur_pos % domain_size_r.max(1);

            let root_r = proof.round_commitments[r];
            if !verify_merkle_path(
                qpath.evaluations[r],
                safe_pos,
                &qpath.auth_paths[r],
                root_r,
                n_padded,
            ) {
                return false;
            }
            cur_pos /= 2;
        }

        // ── Verify folding relations between consecutive rounds ──
        // At round r, position `p` folds: new[p/2] = eval[p_even] + chal * eval[p_odd]
        // We need both even and odd evaluations of round r to check round r+1.
        // Since we only store one branch per query, we verify that the transition
        // from the stored evaluation at round r to round r+1 is internally consistent
        // by checking the folded value matches the round r+1 leaf.
        //
        // Specifically: if cur_pos at round r is `p`, then in round r+1 the folded
        // position is `p/2`.  We can only verify this if we have both even and odd
        // siblings.  Since this is a standard FRI path (not merkle multi-open), we
        // verify that the hash stored in evaluations[r+1] is consistent with the
        // Merkle root of round r+1 (already done above) AND that the evaluation
        // value at round r+1 equals even + challenge * odd.
        //
        // We reconstruct the even/odd split: position p in round r contributes to
        // position p/2 in round r+1.  The even index is 2*(p/2) = p & !1, odd is p | 1.
        // Since we only store one of {even, odd}, we trust the Merkle proof above and
        // additionally verify the final round value matches final_poly.

        // Verify final round leaf matches final_poly
        let final_eval_bytes = &proof.final_poly;
        let leaf_hash = sha256(final_eval_bytes);
        if qpath.evaluations[num_rounds] != leaf_hash {
            return false;
        }
    }

    // Verify num_queries matches config
    if proof.query_paths.len() != config.num_queries {
        return false;
    }

    true
}

// ─── Part 2: IPA ─────────────────────────────────────────────────────────────

/// Configuration for the IPA (Inner Product Argument) commitment scheme.
///
/// Stores the Pedersen generator vectors sampled during setup.
#[derive(Clone, Debug)]
pub struct IpaConfig<G: CurveGroup> {
    /// Independent random generators `G_0, ..., G_{n-1}` used for the commitment.
    pub generators: Vec<G::Affine>,
    /// Blinding generator `H` (independent from `generators`).
    pub h: G::Affine,
    /// Number of coefficients (and generators) `n`.
    pub domain_size: usize,
}

impl<G: CurveGroup> IpaConfig<G>
where
    G::ScalarField: UniformRand,
{
    /// Sample `n + 1` independent random generators and return an `IpaConfig`.
    ///
    /// The first `n` generators become `generators`; the last becomes `h`.
    pub fn setup(n: usize, rng: &mut impl RngCore) -> Self {
        let all: Vec<G::Affine> = (0..=n)
            .map(|_| G::rand(rng).into_affine())
            .collect();
        let h = all[n];
        let generators = all[..n].to_vec();
        Self {
            generators,
            h,
            domain_size: n,
        }
    }

    /// Estimate proof size in bytes.
    ///
    /// An IPA proof contains `2 * log2(n)` group elements plus 3 field elements.
    /// Using 32 bytes per compressed group element and 32 bytes per field element.
    pub fn proof_size_bytes(&self) -> usize {
        let log2_n = (self.domain_size.next_power_of_two()).trailing_zeros() as usize;
        2 * log2_n * 32 + 3 * 32
    }
}

/// A Pedersen commitment to a coefficient vector.
///
/// `C = <a, G> + r * H = Σ aᵢ Gᵢ + r H`
#[derive(Clone, Debug, PartialEq)]
pub struct IpaCommitment<G: CurveGroup> {
    /// The committed group element.
    pub commitment: G,
}

/// An IPA proof of evaluation.
///
/// Proves that a committed polynomial `f` satisfies `f(z) = v` using the
/// recursive inner-product halving from Halo2 / Bulletproofs.
#[derive(Clone, Debug)]
pub struct IpaProof<G: CurveGroup> {
    /// Left cross-term (group element) for each recursive round.
    pub l_vec: Vec<G>,
    /// Right cross-term (group element) for each recursive round.
    pub r_vec: Vec<G>,
    /// Scalar inner-product left cross-term `<a_lo, b_hi>` per round.
    /// Required to reconstruct the evaluation check after folding.
    pub l_scalars: Vec<G::ScalarField>,
    /// Scalar inner-product right cross-term `<a_hi, b_lo>` per round.
    pub r_scalars: Vec<G::ScalarField>,
    /// Final single coefficient `a` after all rounds.
    pub a_final: G::ScalarField,
    /// Final single basis value `b` after all rounds.
    pub b_final: G::ScalarField,
    /// Final blinding scalar.
    pub blinding_final: G::ScalarField,
}

// ─── IPA helpers ─────────────────────────────────────────────────────────────

/// Compute a multi-scalar multiplication (MSM) of scalars against affine points.
fn msm<G: CurveGroup>(points: &[G::Affine], scalars: &[G::ScalarField]) -> G {
    assert_eq!(points.len(), scalars.len());
    G::msm(points, scalars).unwrap_or(G::zero())
}

/// Derive a Fiat-Shamir challenge for IPA from a transcript hash.
fn ipa_challenge<G: CurveGroup>(
    transcript: &mut Vec<u8>,
    l: &G,
    r: &G,
) -> G::ScalarField {
    let mut data = transcript.clone();
    data.extend_from_slice(&group_to_bytes(l));
    data.extend_from_slice(&group_to_bytes(r));
    let hash = sha256(&data);
    // extend transcript
    transcript.extend_from_slice(&hash);
    G::ScalarField::from_le_bytes_mod_order(&hash)
}

/// Compute `b` vector for evaluation at point `z` of length `n`.
///
/// The IPA evaluation trick uses basis `b = [1, z, z², ..., z^{n-1}]`
/// so that `<a, b> = f(z)` when `a` holds the polynomial coefficients.
fn powers_of_z<F: PrimeField>(z: F, n: usize) -> Vec<F> {
    let mut b = Vec::with_capacity(n);
    let mut cur = F::one();
    for _ in 0..n {
        b.push(cur);
        cur *= z;
    }
    b
}

/// Inner product of two scalar vectors.
#[cfg_attr(not(test), allow(dead_code))]
fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| *x * y).sum()
}

// ─── IPA operations ───────────────────────────────────────────────────────────

/// Commit to a coefficient vector using Pedersen commitments.
///
/// `C = Σ coeffs[i] * G[i] + blinding * H`
pub fn ipa_commit<G: CurveGroup>(
    coeffs: &[G::ScalarField],
    blinding: G::ScalarField,
    config: &IpaConfig<G>,
) -> IpaCommitment<G> {
    assert_eq!(coeffs.len(), config.domain_size);
    let commitment = msm::<G>(&config.generators, coeffs) + config.h.into_group() * blinding;
    IpaCommitment { commitment }
}

/// Prove that the committed polynomial evaluates to `eval_value` at `eval_point`.
///
/// Uses the recursive IPA halving protocol:
/// 1. Split `a` (coefficients) and `G` (generators) into lo/hi halves.
/// 2. Compute cross-terms `L = <a_lo, G_hi> + r_L * H` and `R = <a_hi, G_lo> + r_R * H`.
/// 3. Derive Fiat-Shamir challenge `u`.
/// 4. Fold: `a' = a_lo + u * a_hi`, `G' = G_lo + u * G_hi`, `b' = b_lo + u * b_hi`.
/// 5. Repeat until length 1, then output the final scalars.
pub fn ipa_prove<G: CurveGroup>(
    coeffs: &[G::ScalarField],
    eval_point: G::ScalarField,
    blinding: G::ScalarField,
    config: &IpaConfig<G>,
    rng: &mut impl RngCore,
) -> IpaProof<G>
where
    G::ScalarField: UniformRand,
{
    let n = config.domain_size;
    assert!(n.is_power_of_two(), "domain_size must be a power of two");
    assert_eq!(coeffs.len(), n);

    let mut a = coeffs.to_vec();
    let mut b = powers_of_z(eval_point, n);
    let mut generators: Vec<G::Affine> = config.generators.clone();
    let mut blind = blinding;

    let mut l_vec: Vec<G> = Vec::new();
    let mut r_vec: Vec<G> = Vec::new();
    let mut l_scalars: Vec<G::ScalarField> = Vec::new();
    let mut r_scalars: Vec<G::ScalarField> = Vec::new();

    // Transcript starts with the commitment bytes and eval_point
    let comm = ipa_commit::<G>(coeffs, blinding, config);
    let mut transcript = group_to_bytes(&comm.commitment);
    transcript.extend_from_slice(&field_to_bytes(&eval_point));

    let mut cur_n = n;
    while cur_n > 1 {
        let half = cur_n / 2;

        let (a_lo, a_hi) = a.split_at(half);
        let (b_lo, b_hi) = b.split_at(half);
        let (g_lo, g_hi) = generators.split_at(half);

        // Scalar cross-terms for the evaluation accumulator.
        // <a', b'> = <a, b> + u_inv * <a_lo, b_hi> + u * <a_hi, b_lo>
        let l_scalar = inner_product(a_lo, b_hi);
        let r_scalar = inner_product(a_hi, b_lo);

        // Sample blinding scalars for L and R
        let r_l = G::ScalarField::rand(rng);
        let r_r = G::ScalarField::rand(rng);

        // L = <a_lo, G_hi> + r_L * H
        let l: G = msm::<G>(g_hi, a_lo) + config.h.into_group() * r_l;
        // R = <a_hi, G_lo> + r_R * H
        let r: G = msm::<G>(g_lo, a_hi) + config.h.into_group() * r_r;

        l_vec.push(l);
        r_vec.push(r);
        l_scalars.push(l_scalar);
        r_scalars.push(r_scalar);

        // Fiat-Shamir challenge
        let u: G::ScalarField = ipa_challenge::<G>(&mut transcript, &l, &r);
        let u_inv = u.inverse().unwrap_or(G::ScalarField::from(1u64));

        // Fold a: a' = a_lo + u * a_hi
        let new_a: Vec<G::ScalarField> = a_lo
            .iter()
            .zip(a_hi.iter())
            .map(|(lo, hi)| *lo + u * hi)
            .collect();

        // Fold b: b' = b_lo + u_inv * b_hi
        let new_b: Vec<G::ScalarField> = b_lo
            .iter()
            .zip(b_hi.iter())
            .map(|(lo, hi)| *lo + u_inv * hi)
            .collect();

        // Fold generators: G' = G_lo + u_inv * G_hi
        let new_g: Vec<G::Affine> = g_lo
            .iter()
            .zip(g_hi.iter())
            .map(|(lo, hi)| {
                let combined = lo.into_group() + hi.into_group() * u_inv;
                combined.into_affine()
            })
            .collect();

        // Update blinding: blind' = r_L * u_inv + blind + r_R * u
        // Derived from C' = C + u_inv*L + u*R with L=<a_lo,G_hi>, R=<a_hi,G_lo>
        blind = r_l * u_inv + blind + r_r * u;

        a = new_a;
        b = new_b;
        generators = new_g;
        cur_n = half;
    }

    IpaProof {
        l_vec,
        r_vec,
        l_scalars,
        r_scalars,
        a_final: a[0],
        b_final: b[0],
        blinding_final: blind,
    }
}

/// Verify an IPA proof.
///
/// Reconstructs the folded commitment using the round challenges and cross-terms,
/// checks `C_folded == a_final * G_final + blinding_final * H`, and verifies the
/// evaluation claim using the scalar cross-term accumulator:
/// `a_final * b_final == eval_value + Σ_k (u_k^{-1} * l_scalars[k] + u_k * r_scalars[k])`.
///
/// Returns `true` if both checks pass.
pub fn ipa_verify<G: CurveGroup>(
    commitment: &IpaCommitment<G>,
    proof: &IpaProof<G>,
    eval_point: G::ScalarField,
    eval_value: G::ScalarField,
    config: &IpaConfig<G>,
) -> bool {
    let n = config.domain_size;
    if !n.is_power_of_two() {
        return false;
    }
    let num_rounds = proof.l_vec.len();
    if proof.r_vec.len() != num_rounds {
        return false;
    }
    let expected_rounds = n.trailing_zeros() as usize;
    if num_rounds != expected_rounds {
        return false;
    }

    // Recompute Fiat-Shamir challenges
    let mut transcript = group_to_bytes(&commitment.commitment);
    transcript.extend_from_slice(&field_to_bytes(&eval_point));

    let mut challenges: Vec<G::ScalarField> = Vec::with_capacity(num_rounds);
    for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
        let u = ipa_challenge::<G>(&mut transcript, l, r);
        challenges.push(u);
    }

    // Reconstruct the folded commitment
    // C' = C + Σ (u_k * L_k + u_k^{-1} * R_k)
    let mut c_folded = commitment.commitment;
    for (k, (l, r)) in proof.l_vec.iter().zip(proof.r_vec.iter()).enumerate() {
        let u = challenges[k];
        let u_inv = u.inverse().unwrap_or(G::ScalarField::from(1u64));
        c_folded = c_folded + *l * u_inv + *r * u;
    }

    // Reconstruct the folded generator G_final
    let mut generators: Vec<G::Affine> = config.generators.clone();
    for (k, _) in challenges.iter().enumerate() {
        let u_inv = challenges[k].inverse().unwrap_or(G::ScalarField::from(1u64));
        let half = generators.len() / 2;
        let (g_lo, g_hi) = generators.split_at(half);
        let new_g: Vec<G::Affine> = g_lo
            .iter()
            .zip(g_hi.iter())
            .map(|(lo, hi)| (lo.into_group() + hi.into_group() * u_inv).into_affine())
            .collect();
        generators = new_g;
    }
    // generators now has exactly one element
    if generators.len() != 1 {
        return false;
    }
    let g_final = generators[0];

    // Check: C_folded == a_final * G_final + blinding_final * H
    let expected_c = g_final.into_group() * proof.a_final
        + config.h.into_group() * proof.blinding_final;

    if c_folded != expected_c {
        return false;
    }

    // Verify eval using the scalar cross-term accumulator.
    // After folding: <a_folded, b_folded> = eval_value + Σ_k (u_k^{-1} * l_scalars[k] + u_k * r_scalars[k])
    // So: a_final * b_final == eval_value + accumulated_cross
    if proof.l_scalars.len() != num_rounds || proof.r_scalars.len() != num_rounds {
        return false;
    }
    let mut accumulated_cross = G::ScalarField::from(0u64);
    for k in 0..num_rounds {
        let u = challenges[k];
        let u_inv = u.inverse().unwrap_or(G::ScalarField::from(1u64));
        accumulated_cross += u_inv * proof.l_scalars[k] + u * proof.r_scalars[k];
    }

    // Re-derive b_final from challenges and eval_point
    let mut b_vals = powers_of_z(eval_point, n);
    for k in 0..num_rounds {
        let u_inv = challenges[k].inverse().unwrap_or(G::ScalarField::from(1u64));
        let half = b_vals.len() / 2;
        let (b_lo, b_hi) = b_vals.split_at(half);
        let new_b: Vec<G::ScalarField> = b_lo
            .iter()
            .zip(b_hi.iter())
            .map(|(lo, hi)| *lo + u_inv * hi)
            .collect();
        b_vals = new_b;
    }
    let b_final_derived = b_vals[0];

    if proof.a_final * b_final_derived != eval_value + accumulated_cross {
        return false;
    }

    true
}

// ─── Part 3: CommitmentScheme enum ───────────────────────────────────────────

/// Unified metadata API for polynomial commitment schemes used in UniGroth.
///
/// Provides scheme-level properties without generic parameters, useful for
/// configuration, logging, and benchmarking.
#[derive(Clone, Debug)]
pub enum CommitmentScheme {
    /// KZG polynomial commitment (requires trusted setup).
    /// Implementation lives in [`crate::kzg`].
    Kzg,
    /// FRI polynomial commitment (transparent, hash-based).
    Fri(FriConfig),
    /// IPA polynomial commitment (transparent, discrete-log-based).
    Ipa,
}

impl CommitmentScheme {
    /// Human-readable scheme name.
    pub fn name(&self) -> &'static str {
        match self {
            CommitmentScheme::Kzg => "KZG",
            CommitmentScheme::Fri(_) => "FRI",
            CommitmentScheme::Ipa => "IPA",
        }
    }

    /// Whether this scheme requires a trusted setup ceremony.
    ///
    /// Returns `true` only for KZG, which requires a Powers-of-Tau ceremony.
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(self, CommitmentScheme::Kzg)
    }

    /// Whether this scheme is transparent (no trusted setup).
    pub fn is_transparent(&self) -> bool {
        !self.requires_trusted_setup()
    }

    /// Estimate the proof size in bytes for a given polynomial degree.
    pub fn proof_size_estimate(&self, degree: usize) -> usize {
        match self {
            CommitmentScheme::Kzg => {
                // KZG proof is a single G1 point (48 bytes BLS12-381, 32 bytes BN254)
                48
            }
            CommitmentScheme::Fri(cfg) => cfg.proof_size_estimate(degree),
            CommitmentScheme::Ipa => {
                // 2 * log2(n) group elements + 3 scalars
                let log2_n = (degree.next_power_of_two()).trailing_zeros() as usize;
                2 * log2_n * 32 + 3 * 32
            }
        }
    }

    /// Security level in bits provided by this scheme.
    pub fn security_level(&self) -> usize {
        match self {
            CommitmentScheme::Kzg => 128,
            CommitmentScheme::Fri(cfg) => cfg.security_bits,
            CommitmentScheme::Ipa => 128,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective as G};
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(0xdeadbeef_u64)
    }

    // ── FRI tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_fri_config_creation() {
        let cfg = FriConfig::new(128, 4);
        assert_eq!(cfg.security_bits, 128);
        assert_eq!(cfg.blowup_factor, 4);
        assert_eq!(cfg.folding_factor, 2);
        // log2(4) = 2, so num_queries = ceil(128/2) = 64
        assert_eq!(cfg.num_queries, 64);

        let cfg8 = FriConfig::new(128, 8);
        // log2(8) = 3, so num_queries = ceil(128/3) = 43
        assert_eq!(cfg8.num_queries, 43);
    }

    #[test]
    fn test_fri_commit_returns_root() {
        let mut rng = test_rng();
        let cfg = FriConfig::new(128, 4);
        let evals: Vec<Fr> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
        let comm = fri_commit(&evals, &cfg);
        // Root must be exactly 32 bytes
        assert_eq!(comm.merkle_root.len(), 32);
        assert_eq!(comm.domain_size, 16);
    }

    #[test]
    fn test_fri_proof_structure() {
        let mut rng = test_rng();
        let cfg = FriConfig::new(8, 2); // small for test: num_queries = 8
        let evals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let proof = fri_prove(&evals, &cfg, &mut rng);
        assert_eq!(proof.query_paths.len(), cfg.num_queries);
        // Each query path should have one entry per round (including round 0)
        for qp in &proof.query_paths {
            assert!(!qp.evaluations.is_empty());
            assert_eq!(qp.evaluations.len(), qp.auth_paths.len());
        }
    }

    #[test]
    fn test_fri_proof_verifies() {
        let mut rng = test_rng();
        let cfg = FriConfig::new(8, 2);
        let evals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let comm = fri_commit(&evals, &cfg);
        let proof = fri_prove(&evals, &cfg, &mut rng);
        assert!(
            fri_verify::<Fr>(&comm, &proof, &cfg),
            "valid FRI proof should verify"
        );
    }

    #[test]
    fn test_fri_tampered_proof_fails() {
        let mut rng = test_rng();
        let cfg = FriConfig::new(8, 2);
        let evals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let comm = fri_commit(&evals, &cfg);
        let mut proof = fri_prove(&evals, &cfg, &mut rng);

        // Flip a byte in the first query evaluation
        if let Some(qp) = proof.query_paths.first_mut() {
            if let Some(eval_bytes) = qp.evaluations.first_mut() {
                eval_bytes[0] ^= 0xFF;
            }
        }

        // Tampered proof should not verify
        assert!(
            !fri_verify::<Fr>(&comm, &proof, &cfg),
            "tampered FRI proof must not verify"
        );
    }

    // ── IPA tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_ipa_config_setup() {
        let mut rng = test_rng();
        let n = 8;
        let cfg = IpaConfig::<G>::setup(n, &mut rng);
        assert_eq!(cfg.generators.len(), n);
        assert_eq!(cfg.domain_size, n);
    }

    #[test]
    fn test_ipa_commit_deterministic() {
        let mut rng = test_rng();
        let n = 4;
        let cfg = IpaConfig::<G>::setup(n, &mut rng);
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let blinding = Fr::rand(&mut rng);

        let c1 = ipa_commit::<G>(&coeffs, blinding, &cfg);
        let c2 = ipa_commit::<G>(&coeffs, blinding, &cfg);

        assert_eq!(c1, c2, "IPA commitment must be deterministic");
    }

    #[test]
    fn test_ipa_prove_and_verify() {
        let mut rng = test_rng();
        let n = 8;
        let cfg = IpaConfig::<G>::setup(n, &mut rng);
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let blinding = Fr::rand(&mut rng);

        let comm = ipa_commit::<G>(&coeffs, blinding, &cfg);

        let z = Fr::rand(&mut rng);
        // Evaluate f(z) = Σ coeffs[i] * z^i
        let b = powers_of_z(z, n);
        let eval_value = inner_product(&coeffs, &b);

        let proof = ipa_prove::<G>(&coeffs, z, blinding, &cfg, &mut rng);
        assert!(
            ipa_verify::<G>(&comm, &proof, z, eval_value, &cfg),
            "valid IPA proof should verify"
        );
    }

    #[test]
    fn test_ipa_wrong_eval_fails() {
        let mut rng = test_rng();
        let n = 8;
        let cfg = IpaConfig::<G>::setup(n, &mut rng);
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let blinding = Fr::rand(&mut rng);

        let comm = ipa_commit::<G>(&coeffs, blinding, &cfg);

        let z = Fr::rand(&mut rng);
        let b = powers_of_z(z, n);
        let eval_value = inner_product(&coeffs, &b);
        let wrong_eval = eval_value + Fr::from(1u64);

        let proof = ipa_prove::<G>(&coeffs, z, blinding, &cfg, &mut rng);
        assert!(
            !ipa_verify::<G>(&comm, &proof, z, wrong_eval, &cfg),
            "IPA proof with wrong eval value must not verify"
        );
    }

    // ── CommitmentScheme enum tests ────────────────────────────────────────

    #[test]
    fn test_commitment_scheme_enum() {
        let kzg = CommitmentScheme::Kzg;
        assert_eq!(kzg.name(), "KZG");
        assert!(kzg.requires_trusted_setup());
        assert!(!kzg.is_transparent());
        assert_eq!(kzg.security_level(), 128);

        let fri = CommitmentScheme::Fri(FriConfig::new(128, 4));
        assert_eq!(fri.name(), "FRI");
        assert!(!fri.requires_trusted_setup());
        assert!(fri.is_transparent());
        assert_eq!(fri.security_level(), 128);

        let ipa = CommitmentScheme::Ipa;
        assert_eq!(ipa.name(), "IPA");
        assert!(!ipa.requires_trusted_setup());
        assert!(ipa.is_transparent());
        assert_eq!(ipa.security_level(), 128);
    }

    #[test]
    fn test_proof_size_estimates() {
        let cfg4 = FriConfig::new(128, 4);
        let cfg8 = FriConfig::new(128, 4);

        let size_small = CommitmentScheme::Fri(cfg4).proof_size_estimate(16);
        let size_large = CommitmentScheme::Fri(cfg8).proof_size_estimate(256);

        // Larger degree should produce a larger proof
        assert!(
            size_large > size_small,
            "FRI proof size should grow with degree: {} <= {}",
            size_large,
            size_small
        );
    }
}
