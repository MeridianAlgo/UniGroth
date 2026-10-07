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

use ark_ec::pairing::Pairing;
use ark_relations::gr1cs::{ConstraintSynthesizer, Result as R1CSResult, SynthesisError};
use ark_std::rand::{Rng, SeedableRng};
use ark_std::vec::Vec;

use crate::{
    r1cs_to_qap::R1CSToQAP, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};

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
    Success(Proof<E>),
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

/// Prove multiple circuits with the same proving key (in parallel with the
/// `parallel` feature).
///
/// Each proof gets its own 32-byte seed drawn from `rng` up front, so `rng`
/// must be a cryptographically secure generator (e.g. `OsRng` or a seeded
/// `ChaCha20Rng`). Proof randomness `r, s` that an attacker can predict breaks
/// zero-knowledge.
pub fn batch_prove<E, QAP, C, R>(
    pk: &ProvingKey<E>,
    circuits: Vec<C>,
    _config: &BatchConfig,
    rng: &mut R,
) -> BatchResult<E>
where
    E: Pairing,
    QAP: R1CSToQAP,
    C: ConstraintSynthesizer<E::ScalarField> + Send,
    R: Rng,
{
    let jobs: Vec<(C, [u8; 32])> = circuits
        .into_iter()
        .map(|c| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            (c, seed)
        })
        .collect();

    let prove_one = |(circuit, seed): (C, [u8; 32])| {
        let mut rng = ark_std::rand::rngs::StdRng::from_seed(seed);
        match Groth16::<E, QAP>::create_random_proof_with_reduction(circuit, pk, &mut rng) {
            Ok(proof) => BatchProofResult::Success(proof),
            Err(e) => BatchProofResult::Failed(format!("{}", e)),
        }
    };

    #[cfg(feature = "parallel")]
    let results: Vec<BatchProofResult<E>> = jobs.into_par_iter().map(prove_one).collect();
    #[cfg(not(feature = "parallel"))]
    let results: Vec<BatchProofResult<E>> = jobs.into_iter().map(prove_one).collect();

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
    proofs_and_inputs: &[(Proof<E>, Vec<E::ScalarField>)],
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
    proofs_and_inputs: &[(Proof<E>, Vec<E::ScalarField>)],
) -> Vec<bool> {
    let pvk = crate::prepare_verifying_key(vk);
    proofs_and_inputs
        .iter()
        .map(|(proof, inputs)| Groth16::<E>::verify_proof(&pvk, proof, inputs).unwrap_or(false))
        .collect()
}

/// Batch verifier: k proofs → one multi-pairing and one final exponentiation.
///
/// Delegates to [`crate::aggregation::verify_batch`]. The random-linear-combination
/// challenge is a Fiat-Shamir hash of the key, every statement and every proof,
/// mixed with 32 bytes from `rng`. Unlike a challenge taken from `rng` alone,
/// a predictable or attacker-seeded `rng` cannot be used to cancel errors
/// across proofs; a false accept needs a hash collision-level event (≈ k/|F|).
///
/// All proofs must be for the same verifying key.
///
/// # Returns
/// `Ok(true)` iff all k proofs verify, `Ok(false)` if any is invalid, and
/// `Err` if any public-input vector has the wrong length.
pub fn batch_verify_optimized<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    proofs_and_inputs: &[(Proof<E>, Vec<E::ScalarField>)],
    rng: &mut impl Rng,
) -> R1CSResult<bool> {
    if proofs_and_inputs.is_empty() {
        return Ok(true);
    }
    let expected_inputs = pvk.vk.gamma_abc_g1.len().saturating_sub(1);
    if proofs_and_inputs
        .iter()
        .any(|(_, x)| x.len() != expected_inputs)
    {
        return Err(SynthesisError::Unsatisfiable);
    }

    let (proofs, inputs): (Vec<Proof<E>>, Vec<Vec<E::ScalarField>>) =
        proofs_and_inputs.iter().cloned().unzip();
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    Ok(crate::aggregation::verify_batch(
        &pvk.vk, &inputs, &proofs, &entropy,
    ))
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
        let batch_result = batch_prove::<Bn254, crate::r1cs_to_qap::LibsnarkReduction, _, _>(
            &pk, circuits, &config, &mut rng,
        );

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
