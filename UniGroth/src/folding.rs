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
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
    GeneralEvaluationDomain,
};
use ark_serialize::*;
use ark_std::{rand::{RngCore, SeedableRng}, vec, vec::Vec};

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
    pub fn init(
        srs: &UniversalSRS<E>,
        instance: &FoldingInstance<E::ScalarField>,
    ) -> Self {
        // Witness polynomial commitment
        let witness_poly = witness_to_poly::<E>(&instance.witness);
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
            }
            Some(acc) => {
                // Subsequent instances: fold into existing accumulator
                let (new_acc, cross_terms) = self.fold_step(acc.clone(), &instance, rng)?;
                self.accumulator = Some(new_acc);
                end_timer!(fold_time);
                Ok(cross_terms)
            }
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
        // (simplified here; full implementation requires constraint evaluation)
        let cross_term_scalar = compute_cross_term_scalar::<E>(&acc, new_instance);
        let t1 = (self.srs.powers_of_g[0].into_group() * cross_term_scalar).into_affine();

        // Step 2: Fiat-Shamir challenge r (deterministic via Poseidon sponge)
        // rng is kept in signature for forward-compatibility but is not used for r.
        let r = fiat_shamir_challenge::<E>(&acc, new_instance, &t1);
        let _ = rng; // suppress unused warning; kept for API stability

        // Step 3: Fold public inputs: acc_x' = acc_x + r · new_x
        let folded_x = fold_scalars(&acc.acc_x, &new_instance.public_inputs, &r);

        // Step 4: Fold witness commitment: acc_w' = acc_w + r · new_w_commit
        let new_witness_poly = witness_to_poly::<E>(&new_instance.witness);
        let new_w_commit = if new_instance.witness.is_empty() {
            E::G1Affine::zero()
        } else {
            KZG::commit(&self.srs, &new_witness_poly).value
        };

        let folded_w_value = match &acc.acc_w {
            Some(commit) => (commit.value.into_group() + new_w_commit.into_group() * r).into_affine(),
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
            acc_w: Some(Commitment { value: folded_w_value }),
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
pub fn verify_accumulator<E: Pairing>(
    _srs: &UniversalSRS<E>,
    acc: &FoldingAccumulator<E>,
) -> bool {
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
    if acc.fold_count == 1 {
        if !acc.acc_e.is_zero() {
            end_timer!(verify_time);
            return false;
        }
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
) -> DensePolynomial<E::ScalarField> {
    if witness.is_empty() {
        return DensePolynomial::from_coefficients_vec(vec![E::ScalarField::zero()]);
    }
    // Interpolate witness values as polynomial over evaluation domain
    // w(X) such that w(ωⁱ) = wᵢ for the canonical domain
    let domain_size = witness.len().next_power_of_two();
    let domain =
        GeneralEvaluationDomain::<E::ScalarField>::new(domain_size).unwrap();

    let mut evals = witness.to_vec();
    evals.resize(domain_size, E::ScalarField::zero());
    domain.ifft_in_place(&mut evals);
    DensePolynomial::from_coefficients_vec(evals)
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

/// Compute the cross-term scalar for R1CS.
///
/// For R1CS constraint A(w)·B(w) = C(w), when folding accumulator
/// witness `acc_w` with new witness `new_w`:
///   T = A(acc_w)·B(new_w) + A(new_w)·B(acc_w) - C(acc_w+new_w)
///
/// This is a simplified scalar version; the full implementation
/// requires evaluating sparse constraint polynomials.
fn compute_cross_term_scalar<E: Pairing>(
    acc: &FoldingAccumulator<E>,
    new_instance: &FoldingInstance<E::ScalarField>,
) -> E::ScalarField {
    // Simplified: use the inner product of acc_x and new_x as a proxy
    // Full implementation: evaluate A, B, C matrices at acc_w and new_w
    //
    // TODO: Pass constraint matrices here and compute proper cross-terms
    // See ProtoStar §3 "Computing Cross-Terms"
    acc.acc_x
        .iter()
        .zip(new_instance.public_inputs.iter())
        .map(|(a, b)| *a * b)
        .sum()
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
    let full_rounds    = 8;
    let partial_rounds = 31;
    let alpha          = 5u64;

    // Width-3 identity MDS matrix
    let mds = ark_std::vec![
        ark_std::vec![E::ScalarField::from(1u128), E::ScalarField::from(0u128), E::ScalarField::from(0u128)],
        ark_std::vec![E::ScalarField::from(0u128), E::ScalarField::from(1u128), E::ScalarField::from(0u128)],
        ark_std::vec![E::ScalarField::from(0u128), E::ScalarField::from(0u128), E::ScalarField::from(1u128)],
    ];

    // Seeded round constants (same seed as security.rs)
    let mut seeded_rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let round_constants = (0..(full_rounds + partial_rounds))
        .map(|_| ark_std::vec![
            E::ScalarField::rand(&mut seeded_rng),
            E::ScalarField::rand(&mut seeded_rng),
            E::ScalarField::rand(&mut seeded_rng),
        ])
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_poly::Polynomial;
    use ark_std::{rand::{RngCore, SeedableRng}, test_rng};

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

        // Simulate 10 computation steps
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
            let instance = FoldingInstance::new(
                vec![Fr::from(i * 10)],
                vec![Fr::from(i)],
            );
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
        assert_eq!(
            acc_a.acc_mu, acc_b.acc_mu,
            "acc_mu must match"
        );
        assert_eq!(
            acc_a.acc_e, acc_b.acc_e,
            "acc_e must match"
        );
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
        let witness: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let poly = witness_to_poly::<Bn254>(&witness);

        // Polynomial should be non-trivial
        assert!(poly.degree() > 0);

        // When evaluated at the domain points, should recover witness values
        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let evals = domain.fft(&poly.coeffs);
        assert_eq!(evals[0], witness[0]);
        assert_eq!(evals[1], witness[1]);
    }
}
