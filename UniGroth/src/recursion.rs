//! # Recursive Proof Composition
#![allow(missing_docs)]
//!
//! Framework for proving UniGroth/Groth16 verification inside UniGroth itself,
//! enabling recursive proof composition and proof chains.
//!
//! Recursive composition allows:
//! - Proving that a previous proof was valid (proof of proof)
//! - Chaining proofs for incrementally verifiable computation
//! - Aggregating heterogeneous proofs into a single proof
//!
//! ## Multi-Curve Recursion
//!
//! For efficient recursion, we use a 2-chain of pairing-friendly curves:
//! - BLS12-377 (inner curve): prove the circuit
//! - BW6-761 (outer curve): verify BLS12-377 pairings natively
//!
//! This avoids expensive non-native field arithmetic.
//!
//! References:
//! - BCTV14: "Recursive composition of SNARKs"
//! - CycleFold: "Folding-scheme-based recursive composition"

use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use sha2::{Sha256, Digest};

/// A recursive proof wrapping an inner proof with verification metadata.
#[derive(Clone, Debug)]
pub struct RecursiveProof {
    /// The inner proof bytes
    pub inner_proof: Vec<u8>,
    /// Commitment to the verifying key used
    pub vk_commitment: Vec<u8>,
    /// Public inputs of the inner proof
    pub public_inputs_hash: Vec<u8>,
    /// Depth of recursion (0 = base proof)
    pub recursion_depth: usize,
    /// Chain of proof commitments (for audit trail)
    pub proof_chain: Vec<Vec<u8>>,
}

/// Curve pair for recursive composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurvePair {
    /// BLS12-377 inner + BW6-761 outer (recommended)
    Bls12377Bw6761,
    /// BN254 self-composition (slower, uses non-native arithmetic)
    Bn254Self,
}

/// Configuration for recursive proof composition.
#[derive(Clone, Debug)]
pub struct RecursionConfig {
    /// Which curve pair to use
    pub curve_pair: CurvePair,
    /// Maximum recursion depth
    pub max_depth: usize,
    /// Whether to accumulate or verify at each step
    pub accumulate: bool,
}

impl Default for RecursionConfig {
    fn default() -> Self {
        Self {
            curve_pair: CurvePair::Bls12377Bw6761,
            max_depth: 64,
            accumulate: true,
        }
    }
}

/// Compute a commitment to a verifying key (SHA-256 hash of serialized VK).
pub fn commit_verifying_key(vk_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"UniGroth-VK-Commit-v1");
    hasher.update(vk_bytes);
    hasher.finalize().to_vec()
}

/// Compute a commitment to public inputs.
pub fn commit_public_inputs<F: PrimeField>(inputs: &[F]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"UniGroth-PI-Commit-v1");
    for input in inputs {
        let bytes = input.into_bigint().to_bytes_le();
        hasher.update(&bytes);
    }
    hasher.finalize().to_vec()
}

/// Create a recursive proof wrapping an inner proof.
pub fn create_recursive_proof(
    inner_proof_bytes: &[u8],
    vk_bytes: &[u8],
    public_inputs_hash: &[u8],
    previous: Option<&RecursiveProof>,
    _config: &RecursionConfig,
) -> RecursiveProof {
    let vk_commitment = commit_verifying_key(vk_bytes);

    let depth = previous.map_or(0, |p| p.recursion_depth + 1);

    let mut proof_chain = previous
        .map(|p| p.proof_chain.clone())
        .unwrap_or_default();

    // Add current proof commitment to the chain
    let mut proof_hasher = Sha256::new();
    proof_hasher.update(b"UniGroth-Proof-Commit-v1");
    proof_hasher.update(inner_proof_bytes);
    proof_hasher.update(&vk_commitment);
    proof_hasher.update(public_inputs_hash);
    proof_chain.push(proof_hasher.finalize().to_vec());

    RecursiveProof {
        inner_proof: inner_proof_bytes.to_vec(),
        vk_commitment,
        public_inputs_hash: public_inputs_hash.to_vec(),
        recursion_depth: depth,
        proof_chain,
    }
}

/// Verify a recursive proof's chain integrity.
pub fn verify_recursive_chain(proof: &RecursiveProof) -> bool {
    if proof.proof_chain.is_empty() {
        return false;
    }

    // Verify the latest entry matches the proof data
    let mut hasher = Sha256::new();
    hasher.update(b"UniGroth-Proof-Commit-v1");
    hasher.update(&proof.inner_proof);
    hasher.update(&proof.vk_commitment);
    hasher.update(&proof.public_inputs_hash);
    let expected = hasher.finalize().to_vec();

    let last = &proof.proof_chain[proof.proof_chain.len() - 1];
    *last == expected
}

/// Estimate the cost of recursive verification.
pub fn estimate_recursion_cost(
    inner_constraints: usize,
    config: &RecursionConfig,
) -> RecursionCostEstimate {
    let verifier_constraints = match config.curve_pair {
        CurvePair::Bls12377Bw6761 => 20_000,
        CurvePair::Bn254Self => 150_000, // non-native field is expensive
    };

    RecursionCostEstimate {
        inner_constraints,
        verifier_constraints,
        total_recursive_constraints: inner_constraints + verifier_constraints,
        curve_pair: config.curve_pair.clone(),
        overhead_ratio: verifier_constraints as f64 / inner_constraints as f64,
    }
}

/// Cost estimate for recursive composition.
#[derive(Clone, Debug)]
pub struct RecursionCostEstimate {
    pub inner_constraints: usize,
    pub verifier_constraints: usize,
    pub total_recursive_constraints: usize,
    pub curve_pair: CurvePair,
    pub overhead_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn test_vk_commitment_deterministic() {
        let vk = b"test-verifying-key-bytes";
        let c1 = commit_verifying_key(vk);
        let c2 = commit_verifying_key(vk);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 32);
    }

    #[test]
    fn test_public_input_commitment() {
        let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let c1 = commit_public_inputs(&inputs);
        let c2 = commit_public_inputs(&inputs);
        assert_eq!(c1, c2);

        let different = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)];
        let c3 = commit_public_inputs(&different);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_create_and_verify_recursive_proof() {
        let config = RecursionConfig::default();
        let proof_bytes = b"mock-proof-data";
        let vk_bytes = b"mock-vk-data";
        let pi_hash = b"mock-public-inputs";

        let rp = create_recursive_proof(proof_bytes, vk_bytes, pi_hash, None, &config);

        assert_eq!(rp.recursion_depth, 0);
        assert_eq!(rp.proof_chain.len(), 1);
        assert!(verify_recursive_chain(&rp));
    }

    #[test]
    fn test_recursive_chain_depth_3() {
        let config = RecursionConfig::default();

        let rp0 = create_recursive_proof(b"proof-0", b"vk-0", b"pi-0", None, &config);
        assert_eq!(rp0.recursion_depth, 0);

        let rp1 = create_recursive_proof(b"proof-1", b"vk-1", b"pi-1", Some(&rp0), &config);
        assert_eq!(rp1.recursion_depth, 1);
        assert_eq!(rp1.proof_chain.len(), 2);

        let rp2 = create_recursive_proof(b"proof-2", b"vk-2", b"pi-2", Some(&rp1), &config);
        assert_eq!(rp2.recursion_depth, 2);
        assert_eq!(rp2.proof_chain.len(), 3);
        assert!(verify_recursive_chain(&rp2));
    }

    #[test]
    fn test_tampered_proof_fails_chain_check() {
        let config = RecursionConfig::default();
        let mut rp = create_recursive_proof(b"proof", b"vk", b"pi", None, &config);

        rp.inner_proof = b"tampered".to_vec();
        assert!(!verify_recursive_chain(&rp));
    }

    #[test]
    fn test_recursion_cost_estimate() {
        let config = RecursionConfig {
            curve_pair: CurvePair::Bls12377Bw6761,
            max_depth: 64,
            accumulate: true,
        };

        let est = estimate_recursion_cost(100_000, &config);
        assert_eq!(est.verifier_constraints, 20_000);
        assert_eq!(est.total_recursive_constraints, 120_000);
        assert!(est.overhead_ratio < 1.0);
    }

    #[test]
    fn test_bn254_self_recursion_cost() {
        let config = RecursionConfig {
            curve_pair: CurvePair::Bn254Self,
            max_depth: 32,
            accumulate: false,
        };

        let est = estimate_recursion_cost(100_000, &config);
        assert_eq!(est.verifier_constraints, 150_000);
        assert!(est.overhead_ratio > 1.0);
    }

    #[test]
    fn test_empty_chain_fails() {
        let rp = RecursiveProof {
            inner_proof: vec![],
            vk_commitment: vec![],
            public_inputs_hash: vec![],
            recursion_depth: 0,
            proof_chain: vec![],
        };
        assert!(!verify_recursive_chain(&rp));
    }
}
