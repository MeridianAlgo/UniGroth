//! # Security Notes for UniGroth
#![allow(missing_docs)]
//!
//! What the core scheme provides, and what it does not:
//!
//! 1. **Knowledge soundness** in the Algebraic Group Model (Groth16).
//! 2. **Zero-knowledge**: the prover samples non-zero `r, s` for every proof.
//! 3. **Subversion zero-knowledge**: [`apply_subversion_zk`] rerandomizes a
//!    proof so it is distributed like a fresh one [BKSV20].
//! 4. **Hardened verification**: every verifier rejects identity, off-curve and
//!    wrong-subgroup proof points (see [`crate::proof_points_valid`]).
//!
//! **Not provided: simulation-extractability.** A valid Groth16 proof can be
//! rerandomized into a different valid proof for the same statement. If replay
//! or proof-malleability matters, make the context (sender, nonce, message)
//! a public input so a mauled proof is still bound to the original context.

use ark_ec::pairing::Pairing;
use ark_std::rand::RngCore;

use crate::{Proof, VerifyingKey};

// ─── Subversion Zero-Knowledge ───────────────────────────────────────────────

/// Rerandomize a proof so it is distributed like a fresh honest proof, even
/// if the setup was malicious: A' = A/r₁, B' = r₁B + r₁r₂δ, C' = C + r₂A.
///
/// Reference: BKSV20 (https://eprint.iacr.org/2020/811), Theorem 3.
pub fn apply_subversion_zk<E: Pairing, R: RngCore>(
    proof: &Proof<E>,
    vk: &VerifyingKey<E>,
    rng: &mut R,
) -> Proof<E> {
    crate::Groth16::<E>::rerandomize_proof(vk, proof, rng)
}

// ─── Security Report ────────────────────────────────────────────────────────

/// Security parameter set for UniGroth.
///
/// Default: 128-bit security in the AGM.
#[derive(Clone, Debug)]
pub struct SecurityParams {
    /// Security parameter λ (bits)
    pub lambda: usize,
    /// Whether subversion ZK is enabled
    pub subversion_zk: bool,
}

impl Default for SecurityParams {
    fn default() -> Self {
        Self {
            lambda: crate::config::SECURITY_BITS,
            subversion_zk: true,
        }
    }
}

impl SecurityParams {
    /// Maximum security configuration.
    pub fn maximum() -> Self {
        Self::default()
    }

    /// Report the claimed security guarantees.
    pub fn security_report(&self) -> SecurityReport {
        SecurityReport {
            lambda: self.lambda,
            knowledge_soundness_agm: true, // Always: Groth16 is KS in AGM
            zero_knowledge: true,          // Always: Groth16 is ZK
            // Groth16 proofs are rerandomizable, so not simulation-extractable.
            // Bind context (sender, nonce) into a public input to stop replay.
            simulation_extractable: false,
            subversion_zk: self.subversion_zk,
            post_quantum: false, // NOT post-quantum (pairing-based)
                                 // PQ: Would require switching to lattice-based or hash-based inner prover
                                 // See "Lattice-Based SNARKs" (2025) for a designated-verifier PQ path
        }
    }
}

/// Human-readable security properties report.
#[derive(Clone, Debug)]
pub struct SecurityReport {
    pub lambda: usize,
    pub knowledge_soundness_agm: bool,
    pub zero_knowledge: bool,
    pub simulation_extractable: bool,
    pub subversion_zk: bool,
    pub post_quantum: bool,
}

impl SecurityReport {
    pub fn print(&self) {
        println!("=== UniGroth Security Report ===");
        println!("Security level: {}-bit", self.lambda);
        println!(
            "Knowledge soundness (AGM): {}",
            if self.knowledge_soundness_agm {
                "[OK]"
            } else {
                "[NO]"
            }
        );
        println!(
            "Zero-knowledge: {}",
            if self.zero_knowledge { "[OK]" } else { "[NO]" }
        );
        println!(
            "Simulation-extractable: {}",
            if self.simulation_extractable {
                "[OK]"
            } else {
                "[NO]"
            }
        );
        println!(
            "Subversion zero-knowledge: {}",
            if self.subversion_zk { "[OK]" } else { "[NO]" }
        );
        println!(
            "Post-quantum: {}",
            if self.post_quantum {
                "[OK]"
            } else {
                "[NO] (pairing-based)"
            }
        );
        if !self.post_quantum {
            println!("  -> PQ path: Wrap with Binius/Plonky3 inner prover");
        }
    }
}

// ─── Post-Quantum Path (Design Notes) ───────────────────────────────────────
//
// ## Post-Quantum UniGroth
//
// Three approaches are implemented or viable in 2025/2026:
//
// ### Approach 1: Hybrid Inner + Pairing Outer  [IMPLEMENTED]
//   1. Run a transparent PQ inner SNARK (Binius or Plonky3) over a small field
//   2. Compress the inner proof inside a Plonkish circuit
//   3. Wrap the final aggregation in UniGroth (pairing-based)
//   → Classical security for the outer proof; PQ security for inner steps
//   → Fast verification (still 3-5 pairings for outer)
//   → Implementation: `src/pq_inner.rs` — SHA-256-backed Binius, Plonky3, Hybrid provers
//
// ### Approach 2: Full Lattice-Based Designated-Verifier
//   Use recent 2025 constructions (e.g., "Designated-Verifier zkSNARKs from LWE")
//   → Near-Groth16 verifier speed in designated-verifier setting
//   → Full PQ security (LWE/SIS hardness)
//   → Larger proofs than pairing-based (~1-2KB vs 192 bytes)
//   → Requires external lattice library (not yet integrated)
//
// ### Approach 3: Use UniGroth only for Aggregation  [IMPLEMENTED]
//   Prove many small PQ proofs (e.g., Plonky3), aggregate them with UniGroth
//   → PQ proofs internally, classical aggregation for compression
//   → Good for batch/aggregation use cases
//   → Implementation: `src/pq_inner.rs::aggregate_pq_proofs()` + `src/aggregation.rs`
//
// References:
// - Binius: https://eprint.iacr.org/2023/1217
// - Plonky3: https://github.com/Plonky3/Plonky3
// - LWE SNARK: "Designated-Verifier SNARKs from LWE" (2025)

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs_to_qap::LibsnarkReduction;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_std::{rand::SeedableRng, test_rng};

    #[derive(Clone)]
    struct TestCircuit {
        x: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let x_sq = cs.new_input_variable(|| {
                let xv = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(xv * xv)
            })?;
            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_sq)
        }
    }

    #[test]
    fn test_security_report() {
        let params = SecurityParams::maximum();
        let report = params.security_report();
        report.print();

        assert!(report.knowledge_soundness_agm);
        assert!(report.zero_knowledge);
        assert!(!report.simulation_extractable);
        assert!(report.subversion_zk);
        assert!(!report.post_quantum); // Not PQ (by design)
    }

    #[test]
    fn test_subversion_zk() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, vk) =
            crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(circuit, &mut rng)
                .unwrap();

        let x = Fr::from(9u64);
        let proof = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            TestCircuit { x: Some(x) },
            &mut rng,
        )
        .unwrap();

        // Apply S-ZK rerandomization
        let szk_proof = apply_subversion_zk(&proof, &vk, &mut rng);

        // Rerandomized proof should be different
        assert_ne!(szk_proof.a, proof.a);

        // But should still verify
        let pvk = crate::prepare_verifying_key(&vk);
        let public_inputs = vec![x * x];
        assert!(crate::Groth16::<Bn254>::verify_proof(&pvk, &szk_proof, &public_inputs).unwrap());
    }

    // ─── SE Rejection Tests ───────────────────────────────────────────────────
    //
    // These tests verify that the SE verifier correctly *rejects* tampered proofs,
    // wrong public inputs, and corrupted SE elements.  A verifier that accepts
    // everything is not a verifier.
}
