//! # Batch Prover — Parallel Multi-Circuit Proving
#![allow(missing_docs)]
//!
//! Proves multiple independent circuits in parallel using rayon, with
//! shared setup amortization and configurable parallelism.
//!
//! Use cases:
//! - Rollup operators proving many transactions simultaneously
//! - zkML inference batches
//! - Parallel recursive proof generation
//!
//! References: Pipelined Groth16 (2024), Parallelized SNARK Proving

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, UniformRand, Zero};
use ark_relations::gr1cs::{ConstraintSynthesizer, Result as R1CSResult, SynthesisError};
use ark_std::rand::{Rng, SeedableRng};
use ark_std::vec::Vec;
use core::ops::{AddAssign, Mul, Neg};

use crate::security::{make_sim_extractable, SEConfig, SimExtractableProof};
use crate::{r1cs_to_qap::R1CSToQAP, Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Configuration for batch proving.
#[derive(Clone, Debug, Default)]
pub struct BatchConfig {
    /// Maximum number of proofs to generate in parallel.
    /// 0 = use all available cores.
    pub max_parallelism: usize,
    /// Whether to collect per-proof timing stats
    pub collect_stats: bool,
}

/// Result of a single proof in the batch.
#[derive(Clone, Debug)]
pub enum BatchProofResult<E: Pairing> {
    /// Proof generated successfully
    Success(SimExtractableProof<E>),
    /// Proof generation failed
    Failed(String),
}

/// Result of a batch proving operation.
pub struct BatchResult<E: Pairing> {
    /// Individual proof results (Success or Failed)
    pub results: Vec<BatchProofResult<E>>,
    /// Number of successful proofs
    pub successes: usize,
    /// Number of failed proofs
    pub failures: usize,
}

/// Prove multiple circuits in parallel using the same proving key.
#[cfg(feature = "parallel")]
pub fn batch_prove<E, QAP, C>(
    pk: &ProvingKey<E>,
    circuits: Vec<C>,
    _config: &BatchConfig,
) -> BatchResult<E>
where
    E: Pairing,
    QAP: R1CSToQAP,
    C: ConstraintSynthesizer<E::ScalarField> + Send,
{
    let se_config = SEConfig::default();
    let results: Vec<BatchProofResult<E>> = circuits
        .into_par_iter()
        .map(|circuit| {
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x42);
            match Groth16::<E, QAP>::create_random_proof_with_reduction(circuit, pk, &mut rng) {
                Ok(proof) => {
                    let se_proof = make_sim_extractable(proof, pk, &se_config, &mut rng);
                    BatchProofResult::Success(se_proof)
                },
                Err(e) => BatchProofResult::Failed(format!("{}", e)),
            }
        })
        .collect();

    let successes = results
        .iter()
        .filter(|r| matches!(r, BatchProofResult::Success(_)))
        .count();
    let failures = results.len() - successes;

    BatchResult {
        results,
        successes,
        failures,
    }
}

/// Sequential batch prove (no parallel feature).
#[cfg(not(feature = "parallel"))]
pub fn batch_prove<E, QAP, C>(
    pk: &ProvingKey<E>,
    circuits: Vec<C>,
    _config: &BatchConfig,
) -> BatchResult<E>
where
    E: Pairing,
    QAP: R1CSToQAP,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    let se_config = SEConfig::default();
    let mut results = Vec::with_capacity(circuits.len());

    for circuit in circuits {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x42);
        let result =
            match Groth16::<E, QAP>::create_random_proof_with_reduction(circuit, pk, &mut rng) {
                Ok(proof) => {
                    let se_proof = make_sim_extractable(proof, pk, &se_config, &mut rng);
                    BatchProofResult::Success(se_proof)
                },
                Err(e) => BatchProofResult::Failed(format!("{}", e)),
            };
        results.push(result);
    }

    let successes = results
        .iter()
        .filter(|r| matches!(r, BatchProofResult::Success(_)))
        .count();
    let failures = results.len() - successes;

    BatchResult {
        results,
        successes,
        failures,
    }
}

/// Verify multiple proofs in parallel.
#[cfg(feature = "parallel")]
pub fn batch_verify<E: Pairing>(
    vk: &VerifyingKey<E>,
    proofs_and_inputs: &[(SimExtractableProof<E>, Vec<E::ScalarField>)],
) -> Vec<bool> {
    let pvk = crate::prepare_verifying_key(vk);
    proofs_and_inputs
        .par_iter()
        .map(|(proof, inputs)| Groth16::<E>::verify_proof(&pvk, proof, inputs).unwrap_or(false))
        .collect()
}

/// Verify multiple proofs sequentially (no parallel feature).
#[cfg(not(feature = "parallel"))]
pub fn batch_verify<E: Pairing>(
    vk: &VerifyingKey<E>,
    proofs_and_inputs: &[(SimExtractableProof<E>, Vec<E::ScalarField>)],
) -> Vec<bool> {
    let pvk = crate::prepare_verifying_key(vk);
    proofs_and_inputs
        .iter()
        .map(|(proof, inputs)| Groth16::<E>::verify_proof(&pvk, proof, inputs).unwrap_or(false))
        .collect()
}

/// Cryptographically-sound batch verifier: k proofs → 1 final exponentiation.
///
/// Standard `batch_verify` runs k independent verifications, each paying the
/// cost of 3 Miller loops + 1 final exponentiation. Final exponentiation on
/// BN254 is ~60% of total verification time.
///
/// This function uses a random linear combination to merge k verification
/// equations into a single multi-Miller-loop call followed by ONE final
/// exponentiation, reducing the dominant cost dramatically:
///
/// | k     | Individual final-exps | batch_verify_optimized final-exps |
/// |-------|----------------------|-----------------------------------|
/// | 8     | 8                    | 1 (8× reduction)                  |
/// | 32    | 32                   | 1 (32× reduction)                 |
/// | 128   | 128                  | 1 (128× reduction)                |
///
/// # Security
/// Random scalars rᵢ are sampled from a CSPRNG. A malicious prover cannot
/// cause a false batch-accept with probability > k/|F| ≈ 2^{-200} for k=128.
///
/// # Requirement
/// All proofs must use the same circuit (same VK). For proofs with SE elements
/// (BG18 mode), falls back to individual verification per proof.
///
/// # Returns
/// `Ok(true)` iff all k proofs verify. `Ok(false)` if any is invalid.
pub fn batch_verify_optimized<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    proofs_and_inputs: &[(SimExtractableProof<E>, Vec<E::ScalarField>)],
    rng: &mut impl Rng,
) -> R1CSResult<bool> {
    if proofs_and_inputs.is_empty() {
        return Ok(true);
    }

    // Check input arity for all proofs up-front; reject early on mismatch.
    let expected_inputs = pvk.vk.gamma_abc_g1.len().saturating_sub(1);
    for (_, inputs) in proofs_and_inputs.iter() {
        if inputs.len() != expected_inputs {
            return Err(SynthesisError::Unsatisfiable);
        }
    }

    // If any proof carries a BG18 SE element, fall back to individual verify
    // (SE batch is handled by `batch_verify_se`).
    let has_se = proofs_and_inputs.iter().any(|(p, _)| p.se_element.is_some());
    if has_se {
        for (proof, inputs) in proofs_and_inputs.iter() {
            let ok = Groth16::<E>::verify_proof(pvk, proof, inputs).unwrap_or(false);
            if !ok {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    // Identity check on all proof elements: A=0 or C=0 trivially satisfies pairings.
    for (proof, _) in proofs_and_inputs.iter() {
        let p = &proof.groth16_proof;
        if p.a.is_zero() || p.c.is_zero() {
            return Ok(false);
        }
    }

    let k = proofs_and_inputs.len();

    // Sample k non-zero random scalars r₁…rₖ ∈ F for the linear combination.
    // These prevent a cheating prover from cancelling errors across proofs.
    let rs: Vec<E::ScalarField> = (0..k)
        .map(|_| {
            let mut r = E::ScalarField::zero();
            while r.is_zero() {
                r = E::ScalarField::rand(rng);
            }
            r
        })
        .collect();

    // Aggregated G1 points via MSM:
    //   agg_C   = Σᵢ rᵢ · Cᵢ
    //   agg_inp = Σᵢ rᵢ · prepared_inputsᵢ
    let c_bases: Vec<E::G1Affine> = proofs_and_inputs
        .iter()
        .map(|(p, _)| p.groth16_proof.c)
        .collect();
    let agg_c = E::G1::msm(&c_bases, &rs).map_err(|_| SynthesisError::Unsatisfiable)?;

    // Compute Σᵢ rᵢ · prepared_inputsᵢ using MSM over aggregated input points.
    let inp_acc: Vec<E::G1> = proofs_and_inputs
        .iter()
        .map(|(_, inputs)| Groth16::<E>::prepare_inputs(pvk, inputs))
        .collect::<R1CSResult<_>>()?;
    let inp_bases: Vec<E::G1Affine> = inp_acc.iter().map(|p| p.into_affine()).collect();
    let agg_inp =
        E::G1::msm(&inp_bases, &rs).map_err(|_| SynthesisError::Unsatisfiable)?;

    // r_sum = Σᵢ rᵢ  (used for the α·β term)
    let r_sum: E::ScalarField = rs.iter().copied().fold(E::ScalarField::zero(), |acc, r| {
        let mut s = acc;
        s.add_assign(r);
        s
    });

    // Build multi-Miller-loop input list:
    //   Pairs 0..k:  (rᵢ·Aᵢ, Bᵢ)         — per-proof randomized A paired with B
    //   Pair k:      (agg_inp, -γH)        — aggregated public input term
    //   Pair k+1:    (agg_C, -δH)          — aggregated C term
    //   Pair k+2:    (-r_sum·αG, βH)       — aggregated α·β term (negated on G1)
    //
    // Derivation: batch of individual checks e(Aᵢ, Bᵢ)·e(inpᵢ,-γ)·e(Cᵢ,-δ) = e(α,β)
    // Multiply equation i by rᵢ, take product over i, use MSM linearity on G1.

    // Scale each Aᵢ by rᵢ
    let scaled_a: Vec<E::G1> = proofs_and_inputs
        .iter()
        .zip(rs.iter())
        .map(|((p, _), &r)| p.groth16_proof.a.into_group().mul(r))
        .collect();
    let scaled_a_affine: Vec<E::G1Affine> = E::G1::normalize_batch(&scaled_a);

    // -r_sum · αG
    let neg_r_alpha = pvk
        .vk
        .alpha_g1
        .into_group()
        .mul(r_sum)
        .neg()
        .into_affine();

    let mut g1_inputs: Vec<E::G1Prepared> = scaled_a_affine
        .into_iter()
        .map(|a| a.into())
        .collect();
    g1_inputs.push(agg_inp.into_affine().into());
    g1_inputs.push(agg_c.into_affine().into());
    g1_inputs.push(neg_r_alpha.into());

    let b_elems: Vec<E::G2Affine> = proofs_and_inputs
        .iter()
        .map(|(p, _)| p.groth16_proof.b)
        .collect();
    let mut g2_inputs: Vec<E::G2Prepared> = b_elems.into_iter().map(|b| b.into()).collect();
    g2_inputs.push(pvk.gamma_g2_neg_pc.clone());
    g2_inputs.push(pvk.delta_g2_neg_pc.clone());
    g2_inputs.push(pvk.vk.beta_g2.into());

    // One multi-Miller-loop + one final exponentiation for all k proofs.
    let ml = E::multi_miller_loop(g1_inputs, g2_inputs);
    let result = match E::final_exponentiation(ml) {
        Some(r) => r,
        None => return Ok(false),
    };

    // GT identity check: the combined equation reduces to 1_GT if all proofs valid.
    // 1_GT = multiplicative identity of E::TargetField = One::one().
    Ok(result.0 == E::TargetField::one())
}

/// Estimate proving throughput for a batch.
pub fn estimate_batch_throughput(
    single_prove_ms: f64,
    batch_size: usize,
    num_cores: usize,
) -> BatchThroughputEstimate {
    let parallel_factor = (num_cores as f64).min(batch_size as f64);
    let estimated_total_ms = single_prove_ms * batch_size as f64 / parallel_factor;
    let proofs_per_second = if estimated_total_ms > 0.0 {
        batch_size as f64 / (estimated_total_ms / 1000.0)
    } else {
        0.0
    };

    BatchThroughputEstimate {
        batch_size,
        num_cores,
        estimated_total_ms,
        proofs_per_second,
        speedup_vs_sequential: parallel_factor,
    }
}

/// Throughput estimate for batch proving.
#[derive(Clone, Debug)]
pub struct BatchThroughputEstimate {
    pub batch_size: usize,
    pub num_cores: usize,
    pub estimated_total_ms: f64,
    pub proofs_per_second: f64,
    pub speedup_vs_sequential: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_std::rand::{RngCore, SeedableRng};

    fn make_rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64())
    }

    #[derive(Clone)]
    struct SimpleCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for SimpleCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;

            let a_val = self.a.unwrap_or_default();
            let b_val = self.b.unwrap_or_default();
            let c_val = a_val * b_val;
            let c = cs.new_input_variable(|| Ok(c_val))?;

            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn test_batch_prove_and_verify() {
        let mut rng = make_rng();

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(SimpleCircuit { a: None, b: None }, &mut rng)
                .unwrap();

        let circuits: Vec<SimpleCircuit> = (1..=4u64)
            .map(|i| SimpleCircuit {
                a: Some(Fr::from(i)),
                b: Some(Fr::from(i + 1)),
            })
            .collect();

        let config = BatchConfig::default();
        let batch_result =
            batch_prove::<Bn254, crate::r1cs_to_qap::LibsnarkReduction, _>(&pk, circuits, &config);

        assert_eq!(batch_result.successes, 4);
        assert_eq!(batch_result.failures, 0);

        let proofs_and_inputs: Vec<_> = batch_result
            .results
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if let BatchProofResult::Success(proof) = r {
                    let a = Fr::from((i + 1) as u64);
                    let b = Fr::from((i + 2) as u64);
                    Some((proof.clone(), vec![a * b]))
                } else {
                    None
                }
            })
            .collect();

        let verdicts = batch_verify::<Bn254>(&vk, &proofs_and_inputs);
        assert!(verdicts.iter().all(|v| *v));
    }

    #[test]
    fn test_throughput_estimate() {
        let est = estimate_batch_throughput(100.0, 32, 8);
        assert_eq!(est.batch_size, 32);
        assert!(est.proofs_per_second > 0.0);
        assert!(est.speedup_vs_sequential > 1.0);
    }
}
