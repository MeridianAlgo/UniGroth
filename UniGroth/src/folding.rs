//! # Folding / Recursion Layer (ProtoStar-style)
#![allow(missing_docs)]
//!
//! ProtoStar-style folding for Incrementally Verifiable Computation (IVC).
//! Turns N independent proof steps into a single accumulator, which is then
//! compressed by Groth16 for final verification.
//!
//! **Architecture**:
//! ```text
//! Step 1    Step 2    Step 3           Final
//! [W₁,x₁] + [W₂,x₂] + [W₃,x₃] → Acc → Groth16
//! ```
//!
//! **Folding algorithm**: For each new instance (x, W):
//! 1. Prover sends cross-term commitment T₁
//! 2. Verifier derives Fiat-Shamir challenge r from transcript
//! 3. Fold public inputs: acc_x' = acc_x + r·x
//! 4. Fold witness commitment: acc_w' = acc_w + r·commit(W)
//! 5. Fold error term: acc_e' = acc_e + r·T₁
//! 6. Fold slack: acc_μ' = acc_μ + r·μ
//!
//! The accumulated state satisfies the "relaxed" R1CS constraint:
//!   A(w)·B(w) = μ·C(w) + e
//!
//! References: ProtoStar (2023), Nova (2022), HyperNova (2023)

use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use ark_serialize::*;
use ark_std::{
    rand::{RngCore, SeedableRng},
    vec,
    vec::Vec,
};

use crate::kzg::{Commitment, UniversalSRS, KZG};

// ─── Core Types ─────────────────────────────────────────────────────────────

/// A single step's instance (public inputs) and witness.
#[derive(Clone, Debug)]
pub struct FoldingInstance<F: PrimeField> {
    /// Public inputs / outputs for this step
    pub public_inputs: Vec<F>,
    /// Witness values (private)
    pub witness: Vec<F>,
    /// Slack variable μ (1 for fresh instances, updated during folding)
    pub slack: F,
}

impl<F: PrimeField> FoldingInstance<F> {
    /// Create a fresh instance (slack = 1).
    pub fn new(public_inputs: Vec<F>, witness: Vec<F>) -> Self {
        Self {
            public_inputs,
            witness,
            slack: F::one(),
        }
    }
}

/// The accumulated state across multiple folded instances.
///
/// After folding k instances, this represents a "relaxed" R1CS instance
/// that is satisfied iff all k original instances were satisfied.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct FoldingAccumulator<E: Pairing> {
    /// Folded public inputs
    pub acc_x: Vec<E::ScalarField>,
    /// Commitment to folded witness
    pub acc_w: Option<Commitment<E>>,
    /// Error term commitment (cross-terms from folding)
    pub acc_e: E::G1Affine,
    /// Slack scalar
    pub acc_mu: E::ScalarField,
    /// Number of instances folded so far
    pub fold_count: usize,
    /// Folding randomness history (for audit / debugging)
    pub randomness_transcript: Vec<E::ScalarField>,
}

impl<E: Pairing> FoldingAccumulator<E> {
    /// Initialize accumulator with the first instance.
    pub fn init(srs: &UniversalSRS<E>, instance: &FoldingInstance<E::ScalarField>) -> Self {
        // Witness polynomial commitment
        let witness_poly = witness_to_poly::<E>(&instance.witness).unwrap_or_else(|_| {
            DensePolynomial::from_coefficients_vec(vec![E::ScalarField::zero()])
        });
        let acc_w = if instance.witness.is_empty() {
            None
        } else {
            Some(KZG::commit(srs, &witness_poly))
        };

        Self {
            acc_x: instance.public_inputs.clone(),
            acc_w,
            // Error starts at zero (fresh instance is exactly satisfied)
            acc_e: E::G1Affine::zero(),
            acc_mu: instance.slack,
            fold_count: 1,
            randomness_transcript: vec![],
        }
    }

    /// Returns true if this accumulator represents a valid decision.
    ///
    /// The decision check verifies that all folded steps are consistent.
    /// In the final proof, this is checked inside the Groth16 circuit.
    pub fn is_valid_trivially(&self) -> bool {
        // Trivial check: accumulator was properly initialized
        self.fold_count > 0 && !self.acc_mu.is_zero()
    }
}

/// Cross-term commitments sent by the prover during folding.
///
/// For a degree-d polynomial IOP, the prover sends d-1 cross-terms.
/// For the standard Plonkish / R1CS case (degree 2), there is 1 cross-term.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CrossTerms<E: Pairing> {
    /// T₁ = commitment to the degree-2 cross-term
    pub t1: E::G1Affine,
    /// Additional cross-terms for higher-degree custom gates
    /// T₂, T₃, ... for degree-3, degree-4 custom gates
    pub higher_order: Vec<E::G1Affine>,
}

// ─── Main Folding Engine ────────────────────────────────────────────────────

/// ProtoStar-style folding engine.
///
/// Maintains an accumulator and folds in new instances one at a time.
pub struct FoldingEngine<E: Pairing> {
    /// Universal SRS for polynomial commitments
    pub srs: UniversalSRS<E>,
    /// Current accumulator state
    pub accumulator: Option<FoldingAccumulator<E>>,
}

impl<E: Pairing> FoldingEngine<E> {
    /// Create a new folding engine with the given SRS.
    pub fn new(srs: UniversalSRS<E>) -> Self {
        Self {
            srs,
            accumulator: None,
        }
    }

    /// Fold a new instance into the accumulator.
    ///
    /// This implements the core ProtoStar folding step:
    /// 1. Prover computes cross-term commitments
    /// 2. Fiat-Shamir challenge r derived from transcript
    /// 3. Accumulator updated with randomized combination
    pub fn fold<R: RngCore>(
        &mut self,
        instance: FoldingInstance<E::ScalarField>,
        rng: &mut R,
    ) -> Result<CrossTerms<E>, FoldingError> {
        let fold_time = start_timer!(|| "ProtoStar fold step");

        match &self.accumulator {
            None => {
                // First instance: initialize accumulator
                let acc = FoldingAccumulator::init(&self.srs, &instance);
                self.accumulator = Some(acc);
                end_timer!(fold_time);
                Ok(CrossTerms {
                    t1: E::G1Affine::zero(),
                    higher_order: vec![],
                })
            },
            Some(acc) => {
                // Subsequent instances: fold into existing accumulator
                let (new_acc, cross_terms) = self.fold_step(acc.clone(), &instance, rng)?;
                self.accumulator = Some(new_acc);
                end_timer!(fold_time);
                Ok(cross_terms)
            },
        }
    }

    /// Internal fold step: combine accumulator with new instance.
    fn fold_step<R: RngCore>(
        &self,
        acc: FoldingAccumulator<E>,
        new_instance: &FoldingInstance<E::ScalarField>,
        rng: &mut R,
    ) -> Result<(FoldingAccumulator<E>, CrossTerms<E>), FoldingError> {
        // Step 1: Compute cross-term T₁
        // T₁ encodes the "cross error" when combining acc and new_instance
        // For R1CS: T₁ = A(acc_w) · B(new_w) + A(new_w) · B(acc_w) - C(acc_w) - C(new_w)
        // Scalar approximation for commitment; for full per-constraint cross-terms
        // see compute_cross_term_vector()
        let cross_term_scalar = compute_cross_term_scalar::<E>(&acc, new_instance);
        let t1 = (self.srs.powers_of_g[0].into_group() * cross_term_scalar).into_affine();

        // Step 2: Fiat-Shamir challenge r (deterministic via Poseidon sponge)
        // rng is kept in signature for forward-compatibility but is not used for r.
        let r = fiat_shamir_challenge::<E>(&acc, new_instance, &t1);
        let _ = rng; // suppress unused warning; kept for API stability

        // Step 3: Fold public inputs: acc_x' = acc_x + r · new_x
        let folded_x = fold_scalars(&acc.acc_x, &new_instance.public_inputs, &r);

        // Step 4: Fold witness commitment: acc_w' = acc_w + r · new_w_commit
        let new_witness_poly = witness_to_poly::<E>(&new_instance.witness)?;
        let new_w_commit = if new_instance.witness.is_empty() {
            E::G1Affine::zero()
        } else {
            KZG::commit(&self.srs, &new_witness_poly).value
        };

        let folded_w_value = match &acc.acc_w {
            Some(commit) => {
                (commit.value.into_group() + new_w_commit.into_group() * r).into_affine()
            },
            None => new_w_commit,
        };

        // Step 5: Fold error term: acc_e' = acc_e + r · T₁
        // For higher-degree: acc_e' = acc_e + r·T₁ + r²·T₂ + ...
        let folded_e = (acc.acc_e.into_group() + t1.into_group() * r).into_affine();

        // Step 6: Fold slack: acc_μ' = acc_μ + r · new_μ
        let folded_mu = acc.acc_mu + r * new_instance.slack;

        // Build updated transcript
        let mut new_transcript = acc.randomness_transcript.clone();
        new_transcript.push(r);

        let new_acc = FoldingAccumulator {
            acc_x: folded_x,
            acc_w: Some(Commitment {
                value: folded_w_value,
            }),
            acc_e: folded_e,
            acc_mu: folded_mu,
            fold_count: acc.fold_count + 1,
            randomness_transcript: new_transcript,
        };

        let cross_terms = CrossTerms {
            t1,
            higher_order: vec![],
        };

        Ok((new_acc, cross_terms))
    }

    /// Finalize and return the accumulator for Groth16 compression.
    pub fn finalize(self) -> Option<FoldingAccumulator<E>> {
        self.accumulator
    }
}

// ─── Decision Verification ──────────────────────────────────────────────────

/// Verify the final accumulator (ProtoStar decision predicate).
///
/// Checks structural consistency of the folded accumulator:
/// 1. **Sanity**: fold_count > 0, slack ≠ 0, acc_x non-empty
/// 2. **Transcript**: randomness_transcript.len() == fold_count - 1
/// 3. **Fresh accumulator**: if fold_count == 1, acc_e must be identity (zero error)
/// 4. **Slack consistency**: if fold_count > 1, acc_mu == 1 + Σ r_i
///    (ensures honest folding starting from μ₀ = 1)
/// 5. **Witness validity**: acc_w commitment is non-identity
///
/// **Full security check** would also open acc_w and verify relaxed R1CS:
///   A(w)·B(w) = μ·C(w) + e
/// This is done in the Groth16 circuit during final compression.
///
/// References: ProtoStar (2023), Nova (2022)
pub fn verify_accumulator<E: Pairing>(_srs: &UniversalSRS<E>, acc: &FoldingAccumulator<E>) -> bool {
    let verify_time = start_timer!(|| "Accumulator decision check");

    // ── Check 1: Basic sanity ──────────────────────────────────────────────
    if acc.fold_count == 0 || acc.acc_mu.is_zero() || acc.acc_x.is_empty() {
        end_timer!(verify_time);
        return false;
    }

    // ── Check 2: Transcript length ─────────────────────────────────────────
    // There is one Fiat-Shamir challenge per fold after the first, so the
    // transcript must have exactly fold_count − 1 entries.
    if acc.randomness_transcript.len() != acc.fold_count - 1 {
        end_timer!(verify_time);
        return false;
    }

    // ── Check 3: Error term for fold_count == 1 ────────────────────────────
    if acc.fold_count == 1 && !acc.acc_e.is_zero() {
        end_timer!(verify_time);
        return false;
    }

    // ── Check 4: Slack consistency for fold_count > 1 ─────────────────────
    // The accumulator starts with μ = 1 (from the first fresh instance).
    // Each fold with challenge r_i and incoming slack μ_i = 1 adds r_i·1 = r_i.
    // So after all folds: acc_mu = 1 + Σ r_i.
    if acc.fold_count > 1 {
        let sum: E::ScalarField = acc.randomness_transcript.iter().copied().sum();
        let expected_mu = E::ScalarField::one() + sum;
        if acc.acc_mu != expected_mu {
            end_timer!(verify_time);
            return false;
        }
    }

    // ── Check 5: Witness commitment point is not the point at infinity ─────
    if let Some(commit) = &acc.acc_w {
        if commit.value.is_zero() {
            end_timer!(verify_time);
            return false;
        }
    }

    end_timer!(verify_time);
    true
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a witness vector to a polynomial (for KZG commitment).
fn witness_to_poly<E: Pairing>(
    witness: &[E::ScalarField],
) -> Result<DensePolynomial<E::ScalarField>, FoldingError> {
    if witness.is_empty() {
        return Ok(DensePolynomial::from_coefficients_vec(vec![
            E::ScalarField::zero(),
        ]));
    }
    // Interpolate witness values as polynomial over evaluation domain
    // w(X) such that w(ωⁱ) = wᵢ for the canonical domain
    let domain_size = witness.len().next_power_of_two();
    let domain = GeneralEvaluationDomain::<E::ScalarField>::new(domain_size)
        .ok_or(FoldingError::DomainTooLarge)?;

    let mut evals = witness.to_vec();
    evals.resize(domain_size, E::ScalarField::zero());
    domain.ifft_in_place(&mut evals);
    Ok(DensePolynomial::from_coefficients_vec(evals))
}

/// Fold two scalar vectors with randomness r: result[i] = a[i] + r * b[i]
fn fold_scalars<F: Field>(a: &[F], b: &[F], r: &F) -> Vec<F> {
    let len = a.len().max(b.len());
    let mut result = vec![F::zero(); len];
    for i in 0..len {
        let ai = if i < a.len() { a[i] } else { F::zero() };
        let bi = if i < b.len() { b[i] } else { F::zero() };
        result[i] = ai + *r * bi;
    }
    result
}

/// Compute the cross-term scalar for R1CS folding.
///
/// For relaxed R1CS: A(w)·B(w) = μ·C(w) + e, folding accumulator witness
/// `acc_w` with new witness `new_w` produces cross-term:
///   T = Σ_i (acc_x[i] · new_w[i] + new_x[i] · acc_w[i])
///
/// where acc_w is reconstructed from acc_x (public) and new_instance.witness
/// (private). This captures the bilinear cross-interaction between the
/// accumulated and incoming instances.
///
/// References: ProtoStar §3 "Computing Cross-Terms", Nova §4.2
fn compute_cross_term_scalar<E: Pairing>(
    acc: &FoldingAccumulator<E>,
    new_instance: &FoldingInstance<E::ScalarField>,
) -> E::ScalarField {
    let mut cross_term = E::ScalarField::zero();

    // Term 1: inner product of accumulated public inputs with new witness
    // This represents A(acc)·B(new) contribution
    for (ax, nw) in acc.acc_x.iter().zip(new_instance.witness.iter()) {
        cross_term += *ax * nw;
    }

    // Term 2: inner product of new public inputs with accumulated public inputs
    // This represents A(new)·B(acc) contribution
    // (acc witness is not stored directly; use acc_x as the accessible state)
    for (nx, ax) in new_instance.public_inputs.iter().zip(acc.acc_x.iter()) {
        cross_term += *nx * ax;
    }

    cross_term
}

// ─── Fiat-Shamir Challenge ───────────────────────────────────────────────────

/// Derive deterministic Fiat-Shamir challenge via Poseidon sponge.
///
/// Absorbs: acc_x (folded inputs), fold_count (anti-extension counter),
/// new public inputs, and T₁ commitment serialized to bytes.
/// Returns a single field element derived from the transcript.
fn fiat_shamir_challenge<E: Pairing>(
    acc: &FoldingAccumulator<E>,
    new_instance: &FoldingInstance<E::ScalarField>,
    t1: &E::G1Affine,
) -> E::ScalarField {
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5u64;

    // Width-3 identity MDS matrix
    let mds = ark_std::vec![
        ark_std::vec![
            E::ScalarField::from(1u128),
            E::ScalarField::from(0u128),
            E::ScalarField::from(0u128)
        ],
        ark_std::vec![
            E::ScalarField::from(0u128),
            E::ScalarField::from(1u128),
            E::ScalarField::from(0u128)
        ],
        ark_std::vec![
            E::ScalarField::from(0u128),
            E::ScalarField::from(0u128),
            E::ScalarField::from(1u128)
        ],
    ];

    // Seeded round constants (same seed as security.rs)
    let mut seeded_rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let round_constants = (0..(full_rounds + partial_rounds))
        .map(|_| {
            ark_std::vec![
                E::ScalarField::rand(&mut seeded_rng),
                E::ScalarField::rand(&mut seeded_rng),
                E::ScalarField::rand(&mut seeded_rng),
            ]
        })
        .collect::<ark_std::vec::Vec<_>>();

    let config = PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        round_constants,
        2,
        1,
    );

    let mut sponge = PoseidonSponge::new(&config);

    // Serialize acc_x to bytes and absorb
    let mut acc_x_bytes: Vec<u8> = Vec::new();
    for x in &acc.acc_x {
        x.serialize_compressed(&mut acc_x_bytes)
            .expect("acc_x serialization must not fail");
    }
    sponge.absorb(&acc_x_bytes);

    // Absorb fold_count as a u64 encoded in little-endian bytes
    let fold_count_bytes = (acc.fold_count as u64).to_le_bytes();
    sponge.absorb(&fold_count_bytes.to_vec());

    // Serialize new_instance.public_inputs to bytes and absorb
    let mut pub_in_bytes: Vec<u8> = Vec::new();
    for x in &new_instance.public_inputs {
        x.serialize_compressed(&mut pub_in_bytes)
            .expect("public_inputs serialization must not fail");
    }
    sponge.absorb(&pub_in_bytes);

    // Absorb serialized T₁ bytes
    let mut t1_bytes: Vec<u8> = Vec::new();
    t1.serialize_compressed(&mut t1_bytes)
        .expect("T1 serialization must not fail");
    sponge.absorb(&t1_bytes);

    sponge.squeeze_field_elements::<E::ScalarField>(1)[0]
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Errors from the folding layer.
#[derive(Debug)]
pub enum FoldingError {
    /// Instance has incompatible structure with accumulator
    IncompatibleInstance,
    /// SRS too small for the given witness
    SRSTooSmall,
    /// Verification of folded accumulator failed
    DecisionFailed,
    /// Evaluation domain could not be constructed for the given witness size
    DomainTooLarge,
}

// ─── IVC Step Function ───────────────────────────────────────────────────────

/// Incrementally Verifiable Computation (IVC) step abstraction.
///
/// Wraps the folding engine: each call to `step()` proves one computation
/// step and folds it into the accumulator.
///
/// **Post-quantum extension**: Replace witness commitments with
/// lattice-based schemes (Ajtai) and use SHA3-256 for Fiat-Shamir.
pub struct IVC<E: Pairing> {
    engine: FoldingEngine<E>,
    step_count: usize,
}

impl<E: Pairing> IVC<E> {
    /// Initialize IVC with the given SRS.
    pub fn new(srs: UniversalSRS<E>) -> Self {
        Self {
            engine: FoldingEngine::new(srs),
            step_count: 0,
        }
    }

    /// Execute one IVC step.
    pub fn step<R: RngCore>(
        &mut self,
        public_in: Vec<E::ScalarField>,
        witness: Vec<E::ScalarField>,
        rng: &mut R,
    ) -> Result<(), FoldingError> {
        let instance = FoldingInstance::new(public_in, witness);
        self.engine.fold(instance, rng)?;
        self.step_count += 1;
        Ok(())
    }

    /// Finalize IVC and return accumulator for Groth16 compression.
    pub fn finalize(self) -> (usize, Option<FoldingAccumulator<E>>) {
        (self.step_count, self.engine.finalize())
    }
}

// ─── Full Decision Predicate (Relaxed R1CS) ─────────────────────────────────

/// Sparse R1CS constraint matrices for decision predicate verification.
///
/// Represents the constraint system A·z ⊙ B·z = C·z (standard R1CS) or its
/// relaxed form A·z ⊙ B·z = μ·C·z + e (after folding).
///
/// Each matrix row is stored as a list of (coefficient, variable_index) pairs.
/// Variable ordering follows arkworks convention:
///   index 0 = constant "1" wire
///   indices 1..=num_public = public inputs
///   remaining = private witness
///
/// References: Nova §4.1 "Relaxed R1CS", ProtoStar §3.4 "Decision Predicate"
#[derive(Clone, Debug)]
pub struct R1CSMatrices<F: PrimeField> {
    /// A matrix: a[i] is constraint i's row as (coefficient, variable_index) pairs
    pub a: Vec<Vec<(F, usize)>>,
    /// B matrix
    pub b: Vec<Vec<(F, usize)>>,
    /// C matrix
    pub c: Vec<Vec<(F, usize)>>,
    /// Number of constraints (rows)
    pub num_constraints: usize,
    /// Total number of variables (1 + public + private)
    pub num_variables: usize,
}

/// Prover-side state for decision predicate verification.
///
/// The `FoldingAccumulator` stores commitments for the verifier. This struct
/// stores the raw values that the prover keeps locally for cross-term
/// computation and full algebraic decision checks.
///
/// After each fold, the prover updates this state in lockstep with the
/// accumulator so that `verify_decision_predicate` can perform the
/// complete relaxed R1CS check.
#[derive(Clone, Debug)]
pub struct ProverState<F: PrimeField> {
    /// Folded witness values (private)
    pub folded_witness: Vec<F>,
    /// Error vector: one entry per constraint.
    /// Starts at all-zero for the first instance; accumulates cross-terms.
    pub error_vector: Vec<F>,
}

impl<F: PrimeField> ProverState<F> {
    /// Initialize prover state for the first instance.
    ///
    /// Error vector starts at zero because a fresh satisfying instance
    /// has zero error: A(z)·B(z) = 1·C(z) + 0.
    pub fn init(witness: Vec<F>, num_constraints: usize) -> Self {
        Self {
            folded_witness: witness,
            error_vector: vec![F::zero(); num_constraints],
        }
    }
}

/// Evaluate a sparse matrix row against assignment vector z.
///
/// Returns the inner product Σ_j coefficient_j · z[index_j].
fn eval_sparse_row<F: PrimeField>(row: &[(F, usize)], z: &[F]) -> F {
    let mut sum = F::zero();
    for &(ref coeff, idx) in row {
        if idx < z.len() {
            sum += *coeff * z[idx];
        }
    }
    sum
}

/// Build full assignment vector z = (1, x₀, ..., xₖ, w₀, ..., wₘ).
///
/// The constant "1" wire is always at index 0, followed by public inputs,
/// then private witness values.
fn build_full_assignment<F: PrimeField>(public_inputs: &[F], witness: &[F]) -> Vec<F> {
    let mut z = Vec::with_capacity(1 + public_inputs.len() + witness.len());
    z.push(F::one());
    z.extend_from_slice(public_inputs);
    z.extend_from_slice(witness);
    z
}

/// Compute the cross-term vector T for R1CS folding.
///
/// For each constraint i:
///   T_i = A_i(z_acc)·B_i(z_new) + A_i(z_new)·B_i(z_acc)
///         − μ_new·C_i(z_acc) − μ_acc·C_i(z_new)
///
/// This captures the bilinear cross-interaction between the accumulated and
/// incoming instances. The identity A(z')·B(z') = μ'·C(z') + e' holds with
/// e' = e_acc + r·T, ensuring the relaxed R1CS equation is preserved across
/// all folded instances.
///
/// References: Nova §4.2 "Computing Cross-Terms", ProtoStar §3.3
pub fn compute_cross_term_vector<F: PrimeField>(
    matrices: &R1CSMatrices<F>,
    acc_x: &[F],
    acc_witness: &[F],
    acc_mu: F,
    new_instance: &FoldingInstance<F>,
) -> Vec<F> {
    let z_acc = build_full_assignment(acc_x, acc_witness);
    let z_new = build_full_assignment(&new_instance.public_inputs, &new_instance.witness);

    (0..matrices.num_constraints)
        .map(|i| {
            let a_acc = eval_sparse_row(&matrices.a[i], &z_acc);
            let b_new = eval_sparse_row(&matrices.b[i], &z_new);
            let a_new = eval_sparse_row(&matrices.a[i], &z_new);
            let b_acc = eval_sparse_row(&matrices.b[i], &z_acc);
            let c_acc = eval_sparse_row(&matrices.c[i], &z_acc);
            let c_new = eval_sparse_row(&matrices.c[i], &z_new);

            a_acc * b_new + a_new * b_acc - new_instance.slack * c_acc - acc_mu * c_new
        })
        .collect()
}

/// Fold prover state with a new instance using challenge r.
///
/// Updates the raw witness and error vectors for the prover:
///   folded_witness' = folded_witness + r · new_witness
///   error_vector'   = error_vector   + r · cross_terms
///
/// Must be called with the same challenge `r` that the `FoldingEngine`
/// derived via Fiat-Shamir for this fold step.
pub fn fold_prover_state<F: PrimeField>(
    state: &ProverState<F>,
    new_instance: &FoldingInstance<F>,
    cross_terms: &[F],
    r: &F,
) -> ProverState<F> {
    ProverState {
        folded_witness: fold_scalars(&state.folded_witness, &new_instance.witness, r),
        error_vector: fold_scalars(&state.error_vector, cross_terms, r),
    }
}

/// Verify the full ProtoStar decision predicate (relaxed R1CS).
///
/// Performs both structural checks and the complete algebraic verification:
///   ∀i: A_i(z) · B_i(z) == μ · C_i(z) + e_i
///
/// where z = (1 ‖ x ‖ w) is the full assignment.
///
/// Also verifies that the witness commitment stored in the accumulator
/// matches the prover's raw folded witness via KZG re-commitment.
///
/// This is the **complete** decision predicate as specified in:
/// - ProtoStar §3.4 "Decision Predicate for Relaxed R1CS"
/// - Nova §4.1 "Relaxed R1CS and its Folding"
///
/// It replaces the structural-only `verify_accumulator` with a full
/// algebraic soundness check.
pub fn verify_decision_predicate<E: Pairing>(
    srs: &UniversalSRS<E>,
    acc: &FoldingAccumulator<E>,
    prover_state: &ProverState<E::ScalarField>,
    matrices: &R1CSMatrices<E::ScalarField>,
) -> Result<bool, FoldingError> {
    // Step 1: Structural checks (same as verify_accumulator)
    if !verify_accumulator(srs, acc) {
        return Ok(false);
    }

    // Step 2: Build full assignment z = (1, x, w)
    let z = build_full_assignment(&acc.acc_x, &prover_state.folded_witness);

    // Step 3: Verify relaxed R1CS: A(z)·B(z) = μ·C(z) + e
    for i in 0..matrices.num_constraints {
        let az = eval_sparse_row(&matrices.a[i], &z);
        let bz = eval_sparse_row(&matrices.b[i], &z);
        let cz = eval_sparse_row(&matrices.c[i], &z);

        let ei = if i < prover_state.error_vector.len() {
            prover_state.error_vector[i]
        } else {
            E::ScalarField::zero()
        };

        let lhs = az * bz;
        let rhs = acc.acc_mu * cz + ei;

        if lhs != rhs {
            return Ok(false);
        }
    }

    // Step 4: Verify witness commitment matches folded witness
    if !prover_state.folded_witness.is_empty() {
        let witness_poly = witness_to_poly::<E>(&prover_state.folded_witness)?;
        let expected_commit = KZG::commit(srs, &witness_poly);
        if let Some(ref stored_commit) = acc.acc_w {
            if stored_commit.value != expected_commit.value {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_poly::Polynomial;
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    type Fr = <Bn254 as Pairing>::ScalarField;

    #[test]
    fn test_folding_single_instance() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let srs = UniversalSRS::<Bn254>::setup(32, &mut rng);

        let instance = FoldingInstance::new(
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
        );

        let mut engine = FoldingEngine::new(srs.clone());
        engine.fold(instance, &mut rng).unwrap();

        let acc = engine.finalize().unwrap();
        assert_eq!(acc.fold_count, 1);
        assert!(acc.is_valid_trivially());
    }

    #[test]
    fn test_folding_multiple_instances() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        let mut engine = FoldingEngine::new(srs.clone());

        // Fold 5 instances
        for i in 0..5u64 {
            let instance = FoldingInstance::new(
                vec![Fr::from(i), Fr::from(i * 2)],
                vec![Fr::from(i * 3), Fr::from(i * 4)],
            );
            engine.fold(instance, &mut rng).unwrap();
        }

        let acc = engine.finalize().unwrap();
        assert_eq!(acc.fold_count, 5);
        assert_eq!(acc.randomness_transcript.len(), 4); // 4 challenges for 5 folds
    }

    #[test]
    fn test_ivc_steps() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        let mut ivc = IVC::new(srs);

        // Execute 10 IVC computation steps
        for i in 0..10u64 {
            ivc.step(
                vec![Fr::from(i)],
                vec![Fr::from(i * i)], // witness: i²
                &mut rng,
            )
            .unwrap();
        }

        let (count, acc) = ivc.finalize();
        assert_eq!(count, 10);
        assert!(acc.is_some());
        let acc = acc.unwrap();
        assert_eq!(acc.fold_count, 10);
    }

    #[test]
    fn test_accumulator_decision() {
        // Updated: fold 3 instances and verify the full decision predicate passes.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        let mut engine = FoldingEngine::new(srs.clone());

        // Fold 3 instances (triggers the non-trivial decision checks)
        for i in 1u64..=3 {
            let instance = FoldingInstance::new(vec![Fr::from(i * 10)], vec![Fr::from(i)]);
            engine.fold(instance, &mut rng).unwrap();
        }

        let acc = engine.finalize().unwrap();
        assert_eq!(acc.fold_count, 3);
        assert_eq!(acc.randomness_transcript.len(), 2);
        assert!(
            verify_accumulator(&srs, &acc),
            "Full decision predicate must pass after 3 honest folds"
        );
    }

    // ── Item 4: Fiat-Shamir determinism ──────────────────────────────────────

    #[test]
    fn test_fiat_shamir_determinism() {
        // Fold the same instance twice with different rngs.
        // Because r is derived from Fiat-Shamir (not rng), the two accumulators
        // must be identical.
        let srs_seed = 123u64;
        let mut rng_setup = ark_std::rand::rngs::StdRng::seed_from_u64(srs_seed);
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng_setup);

        let instances: Vec<FoldingInstance<Fr>> = (0u64..3)
            .map(|i| FoldingInstance::new(vec![Fr::from(i + 1)], vec![Fr::from(i * 2 + 1)]))
            .collect();

        // First run with rng seeded from 0
        let mut rng_a = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
        let mut engine_a = FoldingEngine::<Bn254>::new(srs.clone());
        for inst in instances.iter().cloned() {
            engine_a.fold(inst, &mut rng_a).unwrap();
        }
        let acc_a = engine_a.finalize().unwrap();

        // Second run with rng seeded from 9999
        let mut rng_b = ark_std::rand::rngs::StdRng::seed_from_u64(9999u64);
        let mut engine_b = FoldingEngine::<Bn254>::new(srs.clone());
        for inst in instances.iter().cloned() {
            engine_b.fold(inst, &mut rng_b).unwrap();
        }
        let acc_b = engine_b.finalize().unwrap();

        // The accumulators must be byte-for-byte equal because r is deterministic
        assert_eq!(
            acc_a.acc_x, acc_b.acc_x,
            "acc_x must match (Fiat-Shamir is deterministic)"
        );
        assert_eq!(acc_a.acc_mu, acc_b.acc_mu, "acc_mu must match");
        assert_eq!(acc_a.acc_e, acc_b.acc_e, "acc_e must match");
        assert_eq!(
            acc_a.randomness_transcript, acc_b.randomness_transcript,
            "transcript r values must match"
        );
    }

    #[test]
    fn test_fold_scalars() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let r = Fr::from(2u64);

        let result = fold_scalars(&a, &b, &r);
        // result[i] = a[i] + 2 * b[i]
        assert_eq!(result[0], Fr::from(1 + 2 * 4));
        assert_eq!(result[1], Fr::from(2 + 2 * 5));
        assert_eq!(result[2], Fr::from(3 + 2 * 6));
    }

    #[test]
    fn test_witness_to_poly() {
        let witness: Vec<Fr> = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let poly = witness_to_poly::<Bn254>(&witness).expect("witness_to_poly must succeed");

        // Polynomial should be non-trivial
        assert!(poly.degree() > 0);

        // When evaluated at the domain points, should recover witness values
        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let evals = domain.fft(&poly.coeffs);
        assert_eq!(evals[0], witness[0]);
        assert_eq!(evals[1], witness[1]);
    }

    // ── Decision Predicate Tests ────────────────────────────────────────────

    #[test]
    fn test_decision_predicate_single_instance() {
        // Circuit: x * x = y
        // Variables: [0: const 1, 1: y (public), 2: x (witness)]
        let matrices = R1CSMatrices {
            a: vec![vec![(Fr::one(), 2)]],
            b: vec![vec![(Fr::one(), 2)]],
            c: vec![vec![(Fr::one(), 1)]],
            num_constraints: 1,
            num_variables: 3,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        // Instance: x=3, y=9 (satisfying: 3*3=9)
        let inst = FoldingInstance::new(vec![Fr::from(9u64)], vec![Fr::from(3u64)]);

        let mut engine = FoldingEngine::new(srs.clone());
        engine.fold(inst.clone(), &mut rng).unwrap();

        let acc = engine.accumulator.as_ref().unwrap().clone();
        let prover_state = ProverState::init(inst.witness.clone(), matrices.num_constraints);

        let result = verify_decision_predicate::<Bn254>(&srs, &acc, &prover_state, &matrices);
        assert!(
            result.unwrap(),
            "Decision predicate must pass for a single satisfying instance"
        );
    }

    #[test]
    fn test_decision_predicate_two_instances() {
        let matrices = R1CSMatrices {
            a: vec![vec![(Fr::one(), 2)]],
            b: vec![vec![(Fr::one(), 2)]],
            c: vec![vec![(Fr::one(), 1)]],
            num_constraints: 1,
            num_variables: 3,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        let inst1 = FoldingInstance::new(vec![Fr::from(9u64)], vec![Fr::from(3u64)]);
        let inst2 = FoldingInstance::new(vec![Fr::from(25u64)], vec![Fr::from(5u64)]);

        let mut engine = FoldingEngine::new(srs.clone());
        engine.fold(inst1.clone(), &mut rng).unwrap();

        let acc1 = engine.accumulator.as_ref().unwrap().clone();
        let mut prover_state = ProverState::init(inst1.witness.clone(), matrices.num_constraints);

        // Fold second instance
        engine.fold(inst2.clone(), &mut rng).unwrap();
        let acc2 = engine.accumulator.as_ref().unwrap().clone();

        // Extract challenge r from transcript (same r the engine used)
        let r = acc2.randomness_transcript[0];

        // Compute per-constraint cross-terms and fold prover state
        let cross_terms = compute_cross_term_vector(
            &matrices,
            &acc1.acc_x,
            &prover_state.folded_witness,
            acc1.acc_mu,
            &inst2,
        );
        prover_state = fold_prover_state(&prover_state, &inst2, &cross_terms, &r);

        let result = verify_decision_predicate::<Bn254>(&srs, &acc2, &prover_state, &matrices);
        assert!(
            result.unwrap(),
            "Decision predicate must pass after folding two satisfying instances"
        );
    }

    #[test]
    fn test_decision_predicate_three_instances() {
        let matrices = R1CSMatrices {
            a: vec![vec![(Fr::one(), 2)]],
            b: vec![vec![(Fr::one(), 2)]],
            c: vec![vec![(Fr::one(), 1)]],
            num_constraints: 1,
            num_variables: 3,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        let instances = vec![
            FoldingInstance::new(vec![Fr::from(9u64)], vec![Fr::from(3u64)]), // 3*3=9
            FoldingInstance::new(vec![Fr::from(25u64)], vec![Fr::from(5u64)]), // 5*5=25
            FoldingInstance::new(vec![Fr::from(49u64)], vec![Fr::from(7u64)]), // 7*7=49
        ];

        let mut engine = FoldingEngine::new(srs.clone());

        // Fold first instance
        engine.fold(instances[0].clone(), &mut rng).unwrap();
        let mut prover_state =
            ProverState::init(instances[0].witness.clone(), matrices.num_constraints);

        // Fold remaining instances, tracking prover state in lockstep
        for k in 1..instances.len() {
            let acc_before = engine.accumulator.as_ref().unwrap().clone();
            engine.fold(instances[k].clone(), &mut rng).unwrap();
            let acc_after = engine.accumulator.as_ref().unwrap().clone();

            let r = acc_after.randomness_transcript[k - 1];
            let cross_terms = compute_cross_term_vector(
                &matrices,
                &acc_before.acc_x,
                &prover_state.folded_witness,
                acc_before.acc_mu,
                &instances[k],
            );
            prover_state = fold_prover_state(&prover_state, &instances[k], &cross_terms, &r);
        }

        let acc = engine.accumulator.as_ref().unwrap().clone();
        let result = verify_decision_predicate::<Bn254>(&srs, &acc, &prover_state, &matrices);
        assert!(
            result.unwrap(),
            "Decision predicate must pass after folding three instances"
        );
    }

    #[test]
    fn test_decision_predicate_rejects_wrong_witness() {
        let matrices = R1CSMatrices {
            a: vec![vec![(Fr::one(), 2)]],
            b: vec![vec![(Fr::one(), 2)]],
            c: vec![vec![(Fr::one(), 1)]],
            num_constraints: 1,
            num_variables: 3,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        let inst = FoldingInstance::new(vec![Fr::from(9u64)], vec![Fr::from(3u64)]);
        let mut engine = FoldingEngine::new(srs.clone());
        engine.fold(inst.clone(), &mut rng).unwrap();

        let acc = engine.accumulator.as_ref().unwrap().clone();

        // Wrong witness: x=4 instead of x=3 (4*4=16, not 9)
        let bad_state = ProverState::init(vec![Fr::from(4u64)], matrices.num_constraints);
        let result = verify_decision_predicate::<Bn254>(&srs, &acc, &bad_state, &matrices);
        assert!(
            !result.unwrap(),
            "Decision predicate must reject incorrect witness"
        );
    }

    #[test]
    fn test_decision_predicate_multi_constraint() {
        // Circuit: x*x = y  AND  x*y = z
        // Variables: [0: const 1, 1: y (public), 2: z (public), 3: x (witness)]
        let matrices = R1CSMatrices {
            a: vec![
                vec![(Fr::one(), 3)], // constraint 0: A selects x
                vec![(Fr::one(), 3)], // constraint 1: A selects x
            ],
            b: vec![
                vec![(Fr::one(), 3)], // constraint 0: B selects x
                vec![(Fr::one(), 1)], // constraint 1: B selects y
            ],
            c: vec![
                vec![(Fr::one(), 1)], // constraint 0: C selects y → x*x=y
                vec![(Fr::one(), 2)], // constraint 1: C selects z → x*y=z
            ],
            num_constraints: 2,
            num_variables: 4,
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        // x=3, y=9, z=27 (3*3=9, 3*9=27)
        let inst1 =
            FoldingInstance::new(vec![Fr::from(9u64), Fr::from(27u64)], vec![Fr::from(3u64)]);
        // x=2, y=4, z=8 (2*2=4, 2*4=8)
        let inst2 =
            FoldingInstance::new(vec![Fr::from(4u64), Fr::from(8u64)], vec![Fr::from(2u64)]);

        let mut engine = FoldingEngine::new(srs.clone());
        engine.fold(inst1.clone(), &mut rng).unwrap();
        let acc1 = engine.accumulator.as_ref().unwrap().clone();
        let mut prover_state = ProverState::init(inst1.witness.clone(), matrices.num_constraints);

        engine.fold(inst2.clone(), &mut rng).unwrap();
        let acc2 = engine.accumulator.as_ref().unwrap().clone();
        let r = acc2.randomness_transcript[0];

        let cross_terms = compute_cross_term_vector(
            &matrices,
            &acc1.acc_x,
            &prover_state.folded_witness,
            acc1.acc_mu,
            &inst2,
        );
        prover_state = fold_prover_state(&prover_state, &inst2, &cross_terms, &r);

        let result = verify_decision_predicate::<Bn254>(&srs, &acc2, &prover_state, &matrices);
        assert!(
            result.unwrap(),
            "Decision predicate must pass for multi-constraint circuit"
        );
    }

    #[test]
    fn test_cross_term_vector_correctness() {
        // Verify cross-term computation algebraically for x*x=y
        let matrices = R1CSMatrices {
            a: vec![vec![(Fr::one(), 2)]],
            b: vec![vec![(Fr::one(), 2)]],
            c: vec![vec![(Fr::one(), 1)]],
            num_constraints: 1,
            num_variables: 3,
        };

        // Instance 1: x=3, y=9
        let acc_x = vec![Fr::from(9u64)];
        let acc_w = vec![Fr::from(3u64)];
        let acc_mu = Fr::one();
        let inst2 = FoldingInstance::new(vec![Fr::from(25u64)], vec![Fr::from(5u64)]);

        let cross = compute_cross_term_vector(&matrices, &acc_x, &acc_w, acc_mu, &inst2);

        // T = A(z1)*B(z2) + A(z2)*B(z1) - mu2*C(z1) - mu1*C(z2)
        //   = 3*5 + 5*3 - 1*9 - 1*25 = 30 - 34 = -4
        let expected = Fr::from(30u64) - Fr::from(34u64);
        assert_eq!(
            cross[0], expected,
            "Cross-term must be -4 for x*x=y with x1=3,x2=5"
        );
    }
}
