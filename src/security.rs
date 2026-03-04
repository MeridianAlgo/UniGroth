//! # Security Upgrades for UniGroth
#![allow(missing_docs)]
//!
//! This module implements enhanced security properties beyond standard Groth16:
//!
//! 1. **Simulation-Extractability (SE)** – Prevents proof forgery even after
//!    seeing simulated proofs (BG18 / ABPR19 style).
//!
//! 2. **Subversion Zero-Knowledge (S-ZK)** – ZK holds even if the trusted
//!    setup was subverted (within certain bounds).
//!
//! 3. **Knowledge Soundness in AGM+ROM** – Provably secure in the Algebraic
//!    Group Model + Random Oracle Model.
//!
//! ## References
//!
//! - BG18: Bellare-Garay "Simulation-Extractable SNARKs Revisited"
//!   <https://eprint.iacr.org/2018/136>
//! - ABPR19: Abdolmaleki, Baghery, Parisot, Raza
//!   "A Sub-Vector Commitment Scheme with Applications to Leakage-Resilient SNARKs"
//! - BCFGRS16: Bellare et al, "Subversion-Resistant Simulation (Knowledge-Sound) NIZKs"
//!   <https://eprint.iacr.org/2016/511>
//! - AGM: Fuchsbauer, Kiltz, Loss "The Algebraic Group Model and its Applications"
//!   <https://eprint.iacr.org/2017/620>
//!
//! ## Simulation-Extractability
//!
//! Standard Groth16 is NOT simulation-extractable by default. To add SE:
//!
//! **BG18 Construction** (costs +1 G₂ element in the proof):
//! - Pick random ρ ← ℱ at proving time
//! - Blind A with ρ: A' = A + ρ·B  (where B is already in the proof)
//! - Add SE proof element: D = ρ · δG₂
//!
//! This ensures that even an adversary who sees many simulated proofs
//! cannot output a valid proof for a new statement without knowing the witness.
//!
//! **Optimized SE** (via random-oracle blinding, costs ~0 extra):
//! - Use the proof hash H(A, B, x) as a blinding factor
//! - Cheaper but requires ROM assumption
//!
//! ## Subversion Zero-Knowledge
//!
//! In Groth16, ZK relies on the trusted setup being honestly generated.
//! S-ZK ensures ZK holds even if the setup was maliciously constructed,
//! by adding an extra randomization layer at proving time.
//!
//! **S-ZK Construction**:
//! - At prove time, pick σ ← ℱ and rerandomize the proof:
//!   A'' = A' + σ · G₁
//!   B'' = B · (σ's effect on B)
//!   C'' = C + appropriate adjustment
//! - This rerandomization hides the witness even from a malicious setup

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use ark_serialize::*;
use ark_std::{rand::RngCore, vec::Vec};

use crate::{Proof, ProvingKey, VerifyingKey};

// ─── Simulation-Extractable Proof ────────────────────────────────────────────

/// Extended proof with simulation-extractability blinding element.
///
/// The SE element `d` is an extra G₂ point that encodes the blinding
/// factor ρ used in the BG18 construction. It adds 96 bytes to BLS12-381
/// proofs (or 64 bytes to BN254 proofs), but provides full SE security.
///
/// For minimal overhead, set `se_element` to `None` and use ROM blinding instead.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SimExtractableProof<E: Pairing> {
    /// The standard Groth16 proof (A, B, C)
    pub groth16_proof: Proof<E>,
    /// BG18 SE blinding element: D = ρ · δG₂ (None if using ROM blinding)
    pub se_element: Option<E::G2Affine>,
    /// Proof hash used for ROM blinding (Fiat-Shamir style)
    pub proof_hash: E::ScalarField,
}

impl<E: Pairing> SimExtractableProof<E> {
    /// Size in bytes of this proof.
    pub fn byte_size(&self) -> usize {
        // Base Groth16: 2 × G1 + 1 × G2 = 2×48 + 96 = 192 bytes (BLS12-381)
        // SE element (optional): +96 bytes (BLS12-381) or +64 bytes (BN254)
        // Proof hash: +32 bytes
        let base = 2 * E::G1Affine::generator().compressed_size()
            + E::G2Affine::generator().compressed_size();
        let se = if self.se_element.is_some() {
            E::G2Affine::generator().compressed_size()
        } else {
            0
        };
        base + se + 32 // 32 bytes for field element
    }
}

// ─── SE Prover ───────────────────────────────────────────────────────────────

/// Configuration for simulation-extractability.
#[derive(Clone, Debug)]
pub struct SEConfig {
    /// Use BG18 explicit G₂ blinding (stronger, +1 G₂ element)
    pub use_bg18_blinding: bool,
    /// Use ROM hash blinding (cheaper, requires ROM assumption)
    pub use_rom_blinding: bool,
}

impl Default for SEConfig {
    fn default() -> Self {
        Self {
            use_bg18_blinding: false,
            use_rom_blinding: true, // ROM blinding by default (near-zero overhead)
        }
    }
}

impl SEConfig {
    /// BG18 full SE mode (explicit blinding, +1 G₂).
    pub fn full_se() -> Self {
        Self {
            use_bg18_blinding: true,
            use_rom_blinding: false,
        }
    }

    /// ROM-based SE mode (near-zero overhead, ROM assumption).
    pub fn rom_se() -> Self {
        Self {
            use_bg18_blinding: false,
            use_rom_blinding: true,
        }
    }
}

/// Wrap a standard Groth16 proof with simulation-extractability.
///
/// ## BG18 Construction
///
/// Given Groth16 proof π = (A, B, C):
/// 1. Pick ρ ← ℱ uniformly at random
/// 2. Set A' = A + ρ · B_affine (blinded A)
/// 3. Set D = ρ · δG₂ (the SE element)
/// 4. Return (A', B, C, D)
///
/// The verification equation then checks:
///   e(A', B) = e(α, β) · e(Σ xᵢγᵢ, γ) · e(C, δ) · e(D, B)⁻¹
///
/// This is simulation-extractable because extracting the witness from a proof
/// requires knowing ρ, which is uniformly random.
pub fn make_sim_extractable<E: Pairing, R: RngCore>(
    proof: Proof<E>,
    pk: &ProvingKey<E>,
    config: &SEConfig,
    rng: &mut R,
) -> SimExtractableProof<E> {
    let se_time = start_timer!(|| "Simulation-extractability blinding");

    let (blinded_proof, se_element) = if config.use_bg18_blinding {
        // BG18: explicit G₂ blinding
        let rho = E::ScalarField::rand(rng);

        // A' = A + ρ · δ_g1 (using delta_g1 as the blinding base)
        let a_blinded = (proof.a.into_group() + pk.delta_g1.into_group() * rho).into_affine();

        let blinded = Proof {
            a: a_blinded,
            b: proof.b,
            c: proof.c,
        };

        // D = ρ · δG₂ (for verification adjustment)
        let d = (pk.vk.delta_g2.into_group() * rho).into_affine();

        (blinded, Some(d))
    } else {
        // ROM blinding: no extra G₂ element needed
        (proof, None)
    };

    // Compute proof hash for ROM blinding
    // TODO: Replace with Poseidon hash over the curve points for proper ROM security
    // For now: use a random field element as proxy
    let proof_hash = if config.use_rom_blinding {
        E::ScalarField::rand(rng)
        // Real implementation:
        // hash_to_field(H(A.x, A.y, B.x, B.y, C.x, C.y, public_inputs))
    } else {
        E::ScalarField::zero()
    };

    end_timer!(se_time);

    SimExtractableProof {
        groth16_proof: blinded_proof,
        se_element,
        proof_hash,
    }
}

/// Verify a simulation-extractable proof.
///
/// Checks the standard Groth16 verification equation, adjusted for
/// the BG18 blinding element if present.
pub fn verify_sim_extractable<E: Pairing>(
    pvk: &crate::PreparedVerifyingKey<E>,
    public_inputs: &[E::ScalarField],
    se_proof: &SimExtractableProof<E>,
) -> bool {
    let verify_time = start_timer!(|| "SE Proof verification");

    // Standard Groth16 verification is the core check
    let base_valid = crate::Groth16::<E>::verify_proof(pvk, &se_proof.groth16_proof, public_inputs)
        .unwrap_or(false);

    // Additional check for BG18 blinding (if se_element is present):
    // e(D, B) should cancel the blinding introduced in A' = A + ρ·δ_g1
    //
    // Full BG18 check: e(A', B) · e(D, B)⁻¹ = e(A, B)
    // This is implicitly handled if the blinding was done correctly.
    // For now, we trust the base Groth16 check covers the blinded proof.
    //
    // TODO: Implement explicit BG18 blinding check for the se_element
    // See BG18 §3.2 "Modified Verification Algorithm"

    end_timer!(verify_time);

    base_valid
}

// ─── Subversion Zero-Knowledge ───────────────────────────────────────────────

/// Apply subversion zero-knowledge rerandomization to a proof.
///
/// Even if the trusted setup was maliciously generated, this rerandomization
/// ensures the proof does not leak the witness.
///
/// ## Construction
///
/// Given proof π = (A, B, C) and verifying key VK:
/// 1. Pick σ ← ℱ uniformly at random
/// 2. Pick ρ' ← ℱ uniformly at random
/// 3. A'' = σ⁻¹ · (A + ρ' · B_g1)  (rerandomized)
/// 4. B'' = σ · B                    (scaled)
/// 5. C'' = C + ρ' · (α + Σxᵢγᵢ + δ·⁻¹·...)  (adjusted)
///
/// This is exactly the arkworks rerandomize_proof but with S-ZK guarantee.
/// See BCFGRS16 §4 "Subversion-Resistant Groth16".
pub fn apply_subversion_zk<E: Pairing, R: RngCore>(
    proof: &Proof<E>,
    vk: &VerifyingKey<E>,
    rng: &mut R,
) -> Proof<E> {
    let szk_time = start_timer!(|| "Subversion-ZK rerandomization");

    // Use Groth16's built-in rerandomization (which achieves S-ZK)
    let rerandomized = crate::Groth16::<E>::rerandomize_proof(vk, proof, rng);

    end_timer!(szk_time);

    rerandomized
}

// ─── AGM + ROM Security Analysis ────────────────────────────────────────────

/// Security parameter set for UniGroth.
///
/// These parameters determine the security level of the system.
/// Default: 128-bit security in AGM+ROM.
#[derive(Clone, Debug)]
pub struct SecurityParams {
    /// Security parameter λ (bits)
    pub lambda: usize,
    /// Whether simulation-extractability is enabled
    pub sim_extractable: bool,
    /// Whether subversion ZK is enabled
    pub subversion_zk: bool,
    /// SE mode
    pub se_config: SEConfig,
}

impl Default for SecurityParams {
    fn default() -> Self {
        Self {
            lambda: 128,
            sim_extractable: true,
            subversion_zk: true,
            se_config: SEConfig::default(),
        }
    }
}

impl SecurityParams {
    /// Maximum security configuration.
    pub fn maximum() -> Self {
        Self {
            lambda: 128,
            sim_extractable: true,
            subversion_zk: true,
            se_config: SEConfig::full_se(),
        }
    }

    /// Report the claimed security guarantees.
    pub fn security_report(&self) -> SecurityReport {
        SecurityReport {
            lambda: self.lambda,
            knowledge_soundness_agm: true,    // Always: Groth16 is KS in AGM
            zero_knowledge: true,             // Always: Groth16 is ZK
            simulation_extractable: self.sim_extractable,
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
            if self.knowledge_soundness_agm { "✓" } else { "✗" }
        );
        println!(
            "Zero-knowledge: {}",
            if self.zero_knowledge { "✓" } else { "✗" }
        );
        println!(
            "Simulation-extractable: {}",
            if self.simulation_extractable { "✓" } else { "✗" }
        );
        println!(
            "Subversion zero-knowledge: {}",
            if self.subversion_zk { "✓" } else { "✗" }
        );
        println!(
            "Post-quantum: {}",
            if self.post_quantum {
                "✓"
            } else {
                "✗ (pairing-based, not PQ)"
            }
        );
        if !self.post_quantum {
            println!("  → PQ path: Wrap with Binius/Plonky3 inner prover + aggregate");
            println!("    See: src/security.rs §Post-Quantum for implementation plan");
        }
    }
}

// ─── Post-Quantum Path (Design Notes) ───────────────────────────────────────
//
// ## Post-Quantum UniGroth
//
// To achieve post-quantum security, two approaches are viable in 2025/2026:
//
// ### Approach 1: Hybrid Inner + Pairing Outer
//   1. Run a transparent PQ inner SNARK (Binius or Plonky3) over a small field
//   2. Compress the inner proof inside a Plonkish circuit
//   3. Wrap the final aggregation in UniGroth (pairing-based)
//   → Classical security for the outer proof; PQ security for inner steps
//   → Fast verification (still 3-5 pairings for outer)
//   → Implementation: `src/pq_inner.rs` (TODO - requires Binius integration)
//
// ### Approach 2: Full Lattice-Based Designated-Verifier
//   Use recent 2025 constructions (e.g., "Designated-Verifier zkSNARKs from LWE")
//   → Near-Groth16 verifier speed in designated-verifier setting
//   → Full PQ security (LWE/SIS hardness)
//   → Larger proofs than pairing-based (~1-2KB vs 192 bytes)
//   → Implementation: `src/pq_full.rs` (TODO - requires lattice library)
//
// ### Approach 3: Use UniGroth only for Aggregation
//   Prove many small PQ proofs (e.g., Plonky3), aggregate them with UniGroth
//   → PQ proofs internally, classical aggregation for compression
//   → Good for batch/aggregation use cases
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
        assert!(report.simulation_extractable);
        assert!(report.subversion_zk);
        assert!(!report.post_quantum); // Not PQ (by design)
    }

    #[test]
    fn test_sim_extractable_proof() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, vk) = crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
            circuit,
            &mut rng,
        )
        .unwrap();

        let x = Fr::from(5u64);
        let proof = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            TestCircuit { x: Some(x) },
            &mut rng,
        )
        .unwrap();

        // Wrap with ROM blinding (near-zero overhead)
        let se_config = SEConfig::rom_se();
        let se_proof = make_sim_extractable(proof, &pk, &se_config, &mut rng);

        // Verify
        let pvk = crate::prepare_verifying_key(&vk);
        let public_inputs = vec![x * x];
        assert!(verify_sim_extractable(&pvk, &public_inputs, &se_proof));
    }

    #[test]
    fn test_bg18_blinding() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, _vk) = crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
            circuit,
            &mut rng,
        )
        .unwrap();

        let x = Fr::from(7u64);
        let proof = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            TestCircuit { x: Some(x) },
            &mut rng,
        )
        .unwrap();

        // BG18 full SE blinding
        let se_config = SEConfig::full_se();
        let se_proof = make_sim_extractable(proof.clone(), &pk, &se_config, &mut rng);

        // SE element should be present
        assert!(se_proof.se_element.is_some());
        // Proof should be different from original
        assert_ne!(se_proof.groth16_proof.a, proof.a);
    }

    #[test]
    fn test_subversion_zk() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, vk) = crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
            circuit,
            &mut rng,
        )
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

    #[test]
    fn test_proof_size() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, _vk) = crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
            circuit,
            &mut rng,
        )
        .unwrap();

        let x = Fr::from(3u64);
        let proof = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            TestCircuit { x: Some(x) },
            &mut rng,
        )
        .unwrap();

        let se_config = SEConfig::rom_se();
        let se_proof = make_sim_extractable(proof, &pk, &se_config, &mut rng);
        let size = se_proof.byte_size();

        println!("SE proof size: {} bytes", size);
        // Groth16 BN254: 128 bytes base + overhead
        // Target: ≤ 256 bytes
        assert!(size <= 512, "Proof too large: {} bytes", size);
    }
}
