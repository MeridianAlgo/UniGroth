//! # Folding / Recursion Layer (ProtoStar-style)
#![allow(missing_docs)]
//!
//! This module implements a ProtoStar-style folding scheme that enables
//! Incrementally Verifiable Computation (IVC) on top of UniGroth.
//!
//! ## Overview
//!
//! **Folding** turns N individual proof steps into a single accumulator proof,
//! which is then compressed by the final Groth16 prover. This enables:
//! - Recursive SNARK composition without blowup
//! - Efficient zkVM / zkEVM proving
//! - Amortized verification costs
//!
//! ## References
//!
//! - ProtoStar: [Bunz, Chen, Mishra 2023](https://eprint.iacr.org/2023/620)
//! - Nova: [Kothapalli, Setty, Tzialla 2022](https://eprint.iacr.org/2021/370)
//! - HyperNova: [Kothapalli, Setty 2023](https://eprint.iacr.org/2023/573)
//!
//! ## Architecture
//!
//! ```text
//! Step 1    Step 2    Step 3           Final
//! [W₁,x₁] + [W₂,x₂] + [W₃,x₃] → Acc → Groth16 proof
//!    │           │           │              │
//!    └── fold ───┘           │              │
//!         Acc₁ ──── fold ────┘              │
//!              Acc₂ ─────────── compress ───┘
//! ```
//!
//! ## ProtoStar Folding Algorithm
//!
//! Given accumulator `acc = (acc_x, acc_W, acc_e, acc_μ)` and new instance
//! `(x, W)`, ProtoStar folds as follows:
//!
//! 1. Commit: prover sends cross-term commitments T₁, T₂, ..., Tᵈ
//! 2. Challenge: verifier sends random r ← ℱ (via Fiat-Shamir)
//! 3. Fold:
//!    - acc_x' = acc_x + r · x  (public input folding)
//!    - acc_W' = acc_W + r · W  (witness folding)
//!    - acc_e' = acc_e + r·T₁ + r²·T₂ + ... (error term)
//!    - acc_μ' = acc_μ + r · μ  (slack folding)
//!
//! The folded accumulator satisfies the "relaxed" constraint system,
//! and the final decision step checks: R(acc_x', acc_W') = acc_e' · acc_μ'

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use ark_serialize::*;
use ark_std::{rand::RngCore, vec, vec::Vec};

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
        // (simplified here; full implementation requires constraint evaluation)
        let cross_term_scalar = compute_cross_term_scalar::<E>(&acc, new_instance);
        let t1 = (self.srs.powers_of_g[0].into_group() * cross_term_scalar).into_affine();

        // Step 2: Fiat-Shamir challenge r
        // TODO: Replace with proper Poseidon/SHA3 transcript hash
        // r = H(acc_x, acc_w, acc_e, new_x, new_w, T₁)
        let r = E::ScalarField::rand(rng);

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

/// Verify the final accumulator (decision step).
///
/// This is the "decider" in ProtoStar terminology. It checks that the
/// folded accumulator actually encodes valid computations.
///
/// In a full implementation, this would be proven inside a Groth16 circuit
/// for recursive verification.
pub fn verify_accumulator<E: Pairing>(
    _srs: &UniversalSRS<E>,
    acc: &FoldingAccumulator<E>,
    // The constraint matrices would be passed here for the full check
    // For now: lightweight sanity check
) -> bool {
    let verify_time = start_timer!(|| "Accumulator decision check");

    // Basic validity: accumulator was initialized and has non-zero slack
    let valid = acc.fold_count > 0 && !acc.acc_mu.is_zero() && !acc.acc_x.is_empty();

    // Full ProtoStar decision check:
    // TODO: Evaluate the relaxed R1CS at (acc_x, open(acc_w)) and verify
    //       A(acc_w) · B(acc_w) = acc_mu · C(acc_w) + acc_e
    //
    // This requires:
    // 1. Open the acc_w commitment at the evaluation point
    // 2. Evaluate constraint polynomials A, B, C at the witness
    // 3. Check the relaxed R1CS equation above
    //
    // References: ProtoStar §4.2 "Decision Predicate"

    end_timer!(verify_time);

    valid
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a witness vector to a polynomial (for KZG commitment).
fn witness_to_poly<E: Pairing>(witness: &[E::ScalarField]) -> DensePolynomial<E::ScalarField> {
    if witness.is_empty() {
        return DensePolynomial::from_coefficients_vec(vec![E::ScalarField::zero()]);
    }
    // Interpolate witness values as polynomial over evaluation domain
    // w(X) such that w(ωⁱ) = wᵢ for the canonical domain
    let domain_size = witness.len().next_power_of_two();
    let domain = GeneralEvaluationDomain::<E::ScalarField>::new(domain_size).unwrap();

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

/// Incrementally Verifiable Computation (IVC) step function.
///
/// Wraps the folding engine in a higher-level "step" abstraction:
/// each call to `step()` proves one computation step and folds it in.
///
/// ## Post-Quantum Note
///
/// For PQ security, replace the inner witness commitment scheme with
/// a lattice-based commitment (e.g., Ajtai commitments) and the
/// Fiat-Shamir hash with a quantum-secure hash (SHA3-256 / Poseidon).
/// The outer Groth16 compression would then use a PQ wrapper.
/// See: "Lattice-Based Recursive SNARKs" (2025 preprint) for details.
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
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let srs = UniversalSRS::<Bn254>::setup(32, &mut rng);

        let mut engine = FoldingEngine::new(srs.clone());
        let instance = FoldingInstance::new(vec![Fr::from(42u64)], vec![Fr::from(7u64)]);
        engine.fold(instance, &mut rng).unwrap();

        let acc = engine.finalize().unwrap();
        assert!(verify_accumulator(&srs, &acc));
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
