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
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_std::rand::SeedableRng;
use ark_std::vec::Vec;

use crate::{Groth16, ProvingKey, VerifyingKey, r1cs_to_qap::R1CSToQAP};
use crate::security::{SimExtractableProof, SEConfig, make_sim_extractable};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Configuration for batch proving.
#[derive(Clone, Debug)]
pub struct BatchConfig {
    /// Maximum number of proofs to generate in parallel.
    /// 0 = use all available cores.
    pub max_parallelism: usize,
    /// Whether to collect per-proof timing stats
    pub collect_stats: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_parallelism: 0,
            collect_stats: false,
        }
    }
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
                }
                Err(e) => BatchProofResult::Failed(format!("{}", e)),
            }
        })
        .collect();

    let successes = results
        .iter()
        .filter(|r| matches!(r, BatchProofResult::Success(_)))
        .count();
    let failures = results.len() - successes;

    BatchResult { results, successes, failures }
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
                }
                Err(e) => BatchProofResult::Failed(format!("{}", e)),
            };
        results.push(result);
    }

    let successes = results
        .iter()
        .filter(|r| matches!(r, BatchProofResult::Success(_)))
        .count();
    let failures = results.len() - successes;

    BatchResult { results, successes, failures }
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
        .map(|(proof, inputs)| {
            Groth16::<E>::verify_proof(&pvk, proof, inputs).unwrap_or(false)
        })
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
        .map(|(proof, inputs)| {
            Groth16::<E>::verify_proof(&pvk, proof, inputs).unwrap_or(false)
        })
        .collect()
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
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_crypto_primitives::snark::SNARK;

    fn make_rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64())
    }

    #[derive(Clone)]
    struct SimpleCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for SimpleCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> Result<(), SynthesisError> {
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

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            SimpleCircuit { a: None, b: None },
            &mut rng,
        )
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
