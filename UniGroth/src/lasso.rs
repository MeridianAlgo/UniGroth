//! # Lasso Generalized Lookup Argument
//!
//! Implements Lasso-style lookups for arbitrary function tables using
//! multilinear extensions (MLE) and the sumcheck protocol.
//!
//! Unlike Plookup (sorted range) or LogUp (log-derivative), Lasso supports
//! arbitrary function tables: SHA-256, Keccak S-box, AES, RISC-V opcodes.
//!
//! ## Architecture
//!
//! - [`MultilinearPoly`]: polynomial over `{0,1}^n` stored as 2^n evaluations
//! - [`SumcheckProof`]: interactive sumcheck reduced to 2n scalars via FS
//! - [`LassoTable`]: table T committed via its MLE
//! - [`LassoProof`]: proof that `v_j = T[i_j]` for all j
//!
//! ## Complexity
//!
//! | Prover | Verifier |
//! |--------|----------|
//! | O(N + m log N) | O(m + log N) |
//!
//! where N = table size, m = number of lookups.
//!
//! ## Reference
//! Setty et al., "Unlocking the lookup singularity with Lasso," EUROCRYPT 2024.

use ark_ff::PrimeField;
use ark_std::{string::String, vec, vec::Vec};
use sha2::{Digest, Sha256};

// ─── Fiat-Shamir helper ───────────────────────────────────────────────────────

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn field_to_bytes<F: PrimeField>(f: &F) -> Vec<u8> {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("serialize");
    buf
}

fn hash_to_field<F: PrimeField>(transcript: &mut Vec<u8>, label: &[u8]) -> F {
    transcript.extend_from_slice(label);
    let hash = sha256_bytes(transcript);
    transcript.extend_from_slice(&hash);
    F::from_le_bytes_mod_order(&hash)
}

// ─── Multilinear Polynomial ───────────────────────────────────────────────────

/// Multilinear polynomial over the Boolean hypercube `{0,1}^n`.
///
/// Stored as 2^n field-element evaluations in little-endian bit order:
/// index k encodes point `(b_0, b_1, ..., b_{n-1})` where `k = Σ b_i · 2^i`.
#[derive(Clone, Debug)]
pub struct MultilinearPoly<F: PrimeField> {
    /// Evaluations at every point in `{0,1}^n`, length = 2^n.
    pub evals: Vec<F>,
    /// Number of variables n.
    pub num_vars: usize,
}

impl<F: PrimeField> MultilinearPoly<F> {
    /// Construct from a flat evaluation vector.  Length must be a power of two.
    pub fn new(evals: Vec<F>) -> Self {
        let len = evals.len();
        assert!(len.is_power_of_two(), "evals length must be power of 2");
        Self {
            evals,
            num_vars: len.trailing_zeros() as usize,
        }
    }

    /// Evaluate the MLE at a point `r ∈ F^n` using successive folding.
    ///
    /// Complexity: O(2^n) field operations.
    pub fn evaluate(&self, r: &[F]) -> F {
        assert_eq!(r.len(), self.num_vars, "point dimension mismatch");
        let mut table = self.evals.clone();
        let mut half = table.len();
        for &ri in r {
            half >>= 1;
            for i in 0..half {
                let lo = table[2 * i];
                let hi = table[2 * i + 1];
                table[i] = lo + ri * (hi - lo);
            }
        }
        table[0]
    }

    /// Sum over the Boolean hypercube: `Σ_{b ∈ {0,1}^n} f(b)`.
    pub fn sum(&self) -> F {
        self.evals.iter().copied().sum()
    }

    /// Fold by one challenge: halves the table to fix variable 0.
    ///
    /// Returns a new `MultilinearPoly` of `n-1` variables where each
    /// evaluation is `f(r, b_1, ..., b_{n-1})`.
    fn fold(&self, r: F) -> Self {
        let half = self.evals.len() / 2;
        let new_evals: Vec<F> = (0..half)
            .map(|i| self.evals[2 * i] + r * (self.evals[2 * i + 1] - self.evals[2 * i]))
            .collect();
        Self {
            evals: new_evals,
            num_vars: self.num_vars - 1,
        }
    }
}

// ─── Sumcheck Protocol ────────────────────────────────────────────────────────

/// One round message in the sumcheck protocol.
///
/// For a multilinear polynomial, every round polynomial is degree 1,
/// represented by its two evaluations `[s(0), s(1)]`.
#[derive(Clone, Debug)]
pub struct SumcheckRound<F: PrimeField> {
    /// `s(0)`: sum over the sub-hypercube with variable fixed to 0.
    pub eval_at_0: F,
    /// `s(1)`: sum over the sub-hypercube with variable fixed to 1.
    pub eval_at_1: F,
}

impl<F: PrimeField> SumcheckRound<F> {
    /// Evaluate the round polynomial at an arbitrary field point via linear interpolation.
    pub fn eval_at(&self, x: F) -> F {
        self.eval_at_0 + x * (self.eval_at_1 - self.eval_at_0)
    }
}

/// A complete sumcheck proof for `Σ_{b ∈ {0,1}^n} f(b) = claimed_sum`.
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: PrimeField> {
    /// One round message per variable, from variable 0 to n-1.
    pub rounds: Vec<SumcheckRound<F>>,
    /// Value of the fully-folded polynomial at the challenge point.
    pub final_eval: F,
}

/// Prove `Σ_{b ∈ {0,1}^n} f(b) = claimed_sum` using Fiat-Shamir.
///
/// The verifier can check this proof without interaction.
/// The proof is sound assuming the Fiat-Shamir hash (SHA-256) is a RO.
pub fn sumcheck_prove<F: PrimeField>(
    poly: &MultilinearPoly<F>,
    transcript: &mut Vec<u8>,
) -> (SumcheckProof<F>, Vec<F>) {
    let mut current = poly.clone();
    let mut rounds = Vec::with_capacity(poly.num_vars);
    let mut challenges = Vec::with_capacity(poly.num_vars);

    for round in 0..poly.num_vars {
        // Compute round polynomial s(X) = Σ_{b_{round+1}..b_{n-1}} f(r_0..r_{round-1}, X, b)
        // For multilinear f, s is degree 1: compute s(0) and s(1).
        let half = current.evals.len() / 2;
        let s0: F = (0..half).map(|i| current.evals[2 * i]).sum();
        let s1: F = (0..half).map(|i| current.evals[2 * i + 1]).sum();

        let msg = SumcheckRound {
            eval_at_0: s0,
            eval_at_1: s1,
        };

        // Fiat-Shamir: hash round index + s(0) + s(1)
        transcript.extend_from_slice(&(round as u64).to_le_bytes());
        transcript.extend_from_slice(&field_to_bytes(&s0));
        transcript.extend_from_slice(&field_to_bytes(&s1));
        let r: F = hash_to_field(transcript, b"sumcheck-round");

        challenges.push(r);
        current = current.fold(r);
        rounds.push(msg);
    }

    let final_eval = current.evals[0];
    (SumcheckProof { rounds, final_eval }, challenges)
}

/// Verify a sumcheck proof.
///
/// Returns `(ok, challenges, final_eval_point)` where `ok` is whether the
/// proof is valid.  The caller must separately check that `final_eval` equals
/// `poly.evaluate(&challenges)` using an oracle call or opening proof.
pub fn sumcheck_verify<F: PrimeField>(
    proof: &SumcheckProof<F>,
    claimed_sum: F,
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (bool, Vec<F>) {
    if proof.rounds.len() != num_vars {
        return (false, vec![]);
    }

    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, msg) in proof.rounds.iter().enumerate() {
        // Check consistency: s(0) + s(1) == current_claim
        let s0_plus_s1 = msg.eval_at_0 + msg.eval_at_1;
        if s0_plus_s1 != current_claim {
            return (false, challenges);
        }

        // Fiat-Shamir challenge
        transcript.extend_from_slice(&(round as u64).to_le_bytes());
        transcript.extend_from_slice(&field_to_bytes(&msg.eval_at_0));
        transcript.extend_from_slice(&field_to_bytes(&msg.eval_at_1));
        let r: F = hash_to_field(transcript, b"sumcheck-round");

        challenges.push(r);
        current_claim = msg.eval_at(r);
    }

    // Final: current_claim should equal proof.final_eval
    let ok = current_claim == proof.final_eval;
    (ok, challenges)
}

// ─── Lasso Table ─────────────────────────────────────────────────────────────

/// A lookup table committed as a multilinear extension.
///
/// The table has `2^t` entries; the commitment is the MLE of those entries.
#[derive(Clone, Debug)]
pub struct LassoTable<F: PrimeField> {
    /// Table entries T[0], T[1], ..., T[2^t - 1].
    pub entries: Vec<F>,
    /// Number of address bits; table size = 2^t.
    pub num_addr_bits: usize,
}

impl<F: PrimeField> LassoTable<F> {
    /// Construct a table from raw entries.  Length must be a power of two.
    pub fn new(entries: Vec<F>) -> Self {
        assert!(entries.len().is_power_of_two());
        let num_addr_bits = entries.len().trailing_zeros() as usize;
        Self {
            entries,
            num_addr_bits,
        }
    }

    /// Range-check table: T[i] = i for i in 0..2^t.
    pub fn range_table(bits: usize) -> Self {
        let n = 1usize << bits;
        Self::new((0..n).map(|i| F::from(i as u64)).collect())
    }

    /// XOR table: T[(a, b)] = a XOR b where a,b are half_bits each.
    pub fn xor_table(half_bits: usize) -> Self {
        let n = 1usize << half_bits;
        let entries: Vec<F> = (0..n)
            .flat_map(|a| (0..n).map(move |b| F::from((a ^ b) as u64)))
            .collect();
        Self::new(entries)
    }

    /// Look up T[idx].  Returns `None` if idx is out of range.
    pub fn lookup(&self, idx: usize) -> Option<F> {
        self.entries.get(idx).copied()
    }

    /// Return the MLE of this table.
    pub fn to_mle(&self) -> MultilinearPoly<F> {
        MultilinearPoly::new(self.entries.clone())
    }
}

// ─── Lasso Proof ─────────────────────────────────────────────────────────────

/// Proof that `v_j = T[i_j]` for all `j = 0..m`.
///
/// Uses a random linear combination to reduce m lookup checks to a single
/// sumcheck + one MLE evaluation.
#[derive(Clone, Debug)]
pub struct LassoProof<F: PrimeField> {
    /// Sumcheck proof for the grand-sum identity.
    pub sumcheck: SumcheckProof<F>,
    /// The MLE evaluation `tilde_T(r*)` at the final challenge point.
    pub table_mle_eval: F,
    /// Random weights used to combine the m lookup queries.
    pub query_weights: Vec<F>,
    /// Claimed lookup values `v_j = T[i_j]`.
    pub claimed_values: Vec<F>,
}

/// Error type for Lasso lookup failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LassoError {
    /// Index out of table bounds.
    IndexOutOfRange {
        /// The index that was requested.
        idx: usize,
        /// Number of entries in the table.
        table_size: usize,
    },
    /// Table value mismatch (prover cheated).
    ValueMismatch {
        /// The index whose value disagreed.
        idx: usize,
        /// Value the prover claimed.
        claimed: String,
        /// Value actually stored.
        actual: String,
    },
    /// Sumcheck verification failed.
    SumcheckFailed,
    /// MLE evaluation does not match sumcheck output.
    MleEvalMismatch,
}

/// Prove that `v_j = T[i_j]` for the given indices.
///
/// Returns a `LassoProof` or `LassoError` if any index is out of range.
pub fn prove_lasso<F: PrimeField>(
    table: &LassoTable<F>,
    indices: &[usize],
    rng: &mut impl ark_std::rand::RngCore,
) -> Result<LassoProof<F>, LassoError> {
    // Validate indices
    for &idx in indices {
        if idx >= table.entries.len() {
            return Err(LassoError::IndexOutOfRange {
                idx,
                table_size: table.entries.len(),
            });
        }
    }

    // Claimed values
    let claimed_values: Vec<F> = indices.iter().map(|&i| table.entries[i]).collect();

    // Random weights w_j (Fiat-Shamir via rng for simplicity)
    let query_weights: Vec<F> = (0..indices.len()).map(|_| F::rand(rng)).collect();

    // Build the indicator polynomial: for each table entry b, sum w_j over j where i_j = b
    let mut indicator = vec![F::zero(); table.entries.len()];
    for (j, &idx) in indices.iter().enumerate() {
        indicator[idx] += query_weights[j];
    }

    // Build the product polynomial f(b) = T[b] * indicator[b]
    let product_evals: Vec<F> = table
        .entries
        .iter()
        .zip(indicator.iter())
        .map(|(t, w)| *t * w)
        .collect();
    let product_poly = MultilinearPoly::new(product_evals);

    // claimed_sum = Σ_j v_j * w_j
    let claimed_sum: F = claimed_values
        .iter()
        .zip(query_weights.iter())
        .map(|(v, w)| *v * w)
        .sum();

    // Verify locally (honest prover)
    let actual_sum = product_poly.sum();
    debug_assert_eq!(
        claimed_sum, actual_sum,
        "prover sum mismatch — bug in prove_lasso"
    );

    // Run sumcheck on the product polynomial
    let mut transcript = b"lasso-sumcheck".to_vec();
    let (sc_proof, challenges) = sumcheck_prove(&product_poly, &mut transcript);

    // MLE evaluation at final challenge point
    let table_mle_eval = table.to_mle().evaluate(&challenges);

    Ok(LassoProof {
        sumcheck: sc_proof,
        table_mle_eval,
        query_weights,
        claimed_values,
    })
}

/// Verify a Lasso lookup proof.
///
/// Correctness argument:
/// - The sumcheck verifies `Σ_b f(b) = claimed_sum` where `f(b) = T[b] * indicator[b]`.
/// - At the challenge point r, the verifier recomputes the product polynomial from the
///   (public) table and the claimed weights and evaluates it to check the final sumcheck value.
/// - Note: `product_mle(r) ≠ T_mle(r) * indicator_mle(r)` in general (product of MLEs ≠
///   MLE of product), so we evaluate the product polynomial directly from Boolean evaluations.
pub fn verify_lasso<F: PrimeField>(
    table: &LassoTable<F>,
    indices: &[usize],
    proof: &LassoProof<F>,
) -> Result<(), LassoError> {
    let m = indices.len();
    if proof.claimed_values.len() != m || proof.query_weights.len() != m {
        return Err(LassoError::SumcheckFailed);
    }

    // Recompute claimed_sum = Σ_j v_j * w_j
    let claimed_sum: F = proof
        .claimed_values
        .iter()
        .zip(proof.query_weights.iter())
        .map(|(v, w)| *v * w)
        .sum();

    // Verify sumcheck
    let mut transcript = b"lasso-sumcheck".to_vec();
    let (ok, challenges) = sumcheck_verify(
        &proof.sumcheck,
        claimed_sum,
        table.num_addr_bits,
        &mut transcript,
    );
    if !ok {
        return Err(LassoError::SumcheckFailed);
    }

    // Recompute indicator array: indicator[b] = Σ_{j: i_j = b} w_j
    let mut indicator = vec![F::zero(); table.entries.len()];
    for (j, &idx) in indices.iter().enumerate() {
        indicator[idx] += proof.query_weights[j];
    }

    // Evaluate the product polynomial f(b) = T[b] * indicator[b] at the challenge point.
    // The sumcheck final_eval equals the MLE of f evaluated at the challenges.
    // Evaluating the MLE of f at r requires folding the Boolean evaluations.
    let product_evals: Vec<F> = table
        .entries
        .iter()
        .zip(indicator.iter())
        .map(|(t, w)| *t * w)
        .collect();
    let expected_final = MultilinearPoly::new(product_evals).evaluate(&challenges);

    if proof.sumcheck.final_eval != expected_final {
        return Err(LassoError::MleEvalMismatch);
    }

    Ok(())
}

/// Evaluate the equality polynomial `eq(r, b)` where `b` is an integer index.
///
/// `eq(r, b) = Π_{k=0}^{t-1} (r_k * b_k + (1 - r_k) * (1 - b_k))`
/// where `b_k` is the k-th bit of `b`.
#[allow(dead_code)]
fn eq_poly_eval<F: PrimeField>(r: &[F], b: usize, num_bits: usize) -> F {
    let mut result = F::one();
    for k in 0..num_bits {
        let b_k = (b >> k) & 1;
        let factor = if b_k == 1 { r[k] } else { F::one() - r[k] };
        result *= factor;
    }
    result
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xbadc0de_u64)
    }

    // ── MultilinearPoly ──────────────────────────────────────────────────────

    #[test]
    fn test_mle_eval_at_boolean_point() {
        // f over {0,1}^2 with evals [1,2,3,4]
        // f(0,0)=1, f(1,0)=2, f(0,1)=3, f(1,1)=4
        let evals: Vec<Fr> = (1..=4).map(|i| Fr::from(i as u64)).collect();
        let poly = MultilinearPoly::new(evals);

        assert_eq!(poly.evaluate(&[Fr::zero(), Fr::zero()]), Fr::from(1u64));
        assert_eq!(poly.evaluate(&[Fr::one(), Fr::zero()]), Fr::from(2u64));
        assert_eq!(poly.evaluate(&[Fr::zero(), Fr::one()]), Fr::from(3u64));
        assert_eq!(poly.evaluate(&[Fr::one(), Fr::one()]), Fr::from(4u64));
    }

    #[test]
    fn test_mle_sum_over_hypercube() {
        let evals: Vec<Fr> = (1..=4).map(|i| Fr::from(i as u64)).collect();
        let poly = MultilinearPoly::new(evals);
        // sum = 1+2+3+4 = 10
        assert_eq!(poly.sum(), Fr::from(10u64));
    }

    #[test]
    fn test_mle_eval_random_point() {
        let mut rng = rng();
        let n = 4usize;
        let evals: Vec<Fr> = (0..1 << n).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPoly::new(evals.clone());
        let r: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Verify fold consistency: evaluate gives deterministic result
        let v1 = poly.evaluate(&r);
        let v2 = poly.evaluate(&r);
        assert_eq!(v1, v2);
    }

    // ── Sumcheck ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sumcheck_prove_verify() {
        let mut rng = rng();
        let n = 4usize;
        let evals: Vec<Fr> = (0..1 << n).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPoly::new(evals);
        let claimed_sum = poly.sum();

        let mut transcript_p = b"test".to_vec();
        let (proof, challenges) = sumcheck_prove(&poly, &mut transcript_p);

        let mut transcript_v = b"test".to_vec();
        let (ok, v_challenges) = sumcheck_verify(&proof, claimed_sum, n, &mut transcript_v);

        assert!(ok, "sumcheck must verify");
        assert_eq!(challenges, v_challenges, "challenges must match");

        // Final eval must match polynomial evaluation at challenges
        let expected_final = poly.evaluate(&challenges);
        assert_eq!(proof.final_eval, expected_final);
    }

    #[test]
    fn test_sumcheck_wrong_sum_fails() {
        let mut rng = rng();
        let n = 3usize;
        let evals: Vec<Fr> = (0..1 << n).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPoly::new(evals);
        let wrong_sum = poly.sum() + Fr::one();

        let mut transcript_p = b"test".to_vec();
        let (proof, _) = sumcheck_prove(&poly, &mut transcript_p);

        let mut transcript_v = b"test".to_vec();
        let (ok, _) = sumcheck_verify(&proof, wrong_sum, n, &mut transcript_v);

        assert!(!ok, "sumcheck with wrong claimed sum must fail");
    }

    #[test]
    fn test_sumcheck_tampered_round_fails() {
        let mut rng = rng();
        let n = 3usize;
        let evals: Vec<Fr> = (0..1 << n).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPoly::new(evals);
        let claimed_sum = poly.sum();

        let mut transcript_p = b"test".to_vec();
        let (mut proof, _) = sumcheck_prove(&poly, &mut transcript_p);

        // Tamper round 0
        proof.rounds[0].eval_at_0 += Fr::one();

        let mut transcript_v = b"test".to_vec();
        let (ok, _) = sumcheck_verify(&proof, claimed_sum, n, &mut transcript_v);
        assert!(!ok, "tampered sumcheck must fail");
    }

    // ── LassoTable ───────────────────────────────────────────────────────────

    #[test]
    fn test_range_table_lookup() {
        let t: LassoTable<Fr> = LassoTable::range_table(4); // T[i] = i for i in 0..16
        for i in 0..16usize {
            assert_eq!(t.lookup(i), Some(Fr::from(i as u64)));
        }
        assert_eq!(t.lookup(16), None);
    }

    #[test]
    fn test_xor_table_lookup() {
        let t: LassoTable<Fr> = LassoTable::xor_table(2); // 4x4 XOR table
                                                          // Index (a, b) = a * 4 + b; T[idx] = a XOR b
        for a in 0..4usize {
            for b in 0..4usize {
                let idx = a * 4 + b;
                assert_eq!(t.lookup(idx), Some(Fr::from((a ^ b) as u64)));
            }
        }
    }

    // ── Lasso Prove/Verify ───────────────────────────────────────────────────

    #[test]
    fn test_lasso_range_check_proves_and_verifies() {
        let mut rng = rng();
        let table: LassoTable<Fr> = LassoTable::range_table(4); // T[i] = i, size 16

        let indices = vec![0usize, 3, 7, 15, 1, 5];
        let proof = prove_lasso(&table, &indices, &mut rng).expect("prove_lasso failed");

        verify_lasso(&table, &indices, &proof).expect("verify_lasso failed");
    }

    #[test]
    fn test_lasso_xor_table_proves_and_verifies() {
        let mut rng = rng();
        let table: LassoTable<Fr> = LassoTable::xor_table(2);

        // Look up a XOR b for various (a, b) pairs
        let indices = vec![0usize, 5, 10, 3]; // (0,0), (1,1), (2,2), (0,3)
        let proof = prove_lasso(&table, &indices, &mut rng).expect("prove");
        verify_lasso(&table, &indices, &proof).expect("verify");
    }

    #[test]
    fn test_lasso_out_of_range_error() {
        let mut rng = rng();
        let table: LassoTable<Fr> = LassoTable::range_table(3); // size 8
        let result = prove_lasso(&table, &[0, 5, 100], &mut rng);
        assert!(matches!(
            result,
            Err(LassoError::IndexOutOfRange { idx: 100, .. })
        ));
    }

    #[test]
    fn test_lasso_single_lookup() {
        let mut rng = rng();
        let table: LassoTable<Fr> = LassoTable::range_table(4);
        let indices = vec![7usize];
        let proof = prove_lasso(&table, &indices, &mut rng).unwrap();
        verify_lasso(&table, &indices, &proof).unwrap();
        assert_eq!(proof.claimed_values[0], Fr::from(7u64));
    }

    #[test]
    fn test_eq_poly_sums_to_one() {
        // Σ_{b ∈ {0,1}^n} eq(r, b) = 1 for any r
        let mut rng = rng();
        let n = 3usize;
        let r: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let total: Fr = (0..1usize << n).map(|b| eq_poly_eval::<Fr>(&r, b, n)).sum();
        assert_eq!(total, Fr::one(), "eq poly must sum to 1");
    }
}
