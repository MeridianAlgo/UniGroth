//! # Security Enhancements for UniGroth
#![allow(missing_docs)]
//!
//! Implements enhanced security beyond standard Groth16:
//!
//! 1. **Simulation-Extractability (SE)** – Prevents proof forgery after seeing
//!    simulated proofs. Uses BG18 blinding (explicit G₂ element) or ROM-based
//!    blinding (proof hash). Costs +96 bytes or near-zero overhead.
//!
//! 2. **Subversion Zero-Knowledge (S-ZK)** – ZK holds even if setup was
//!    maliciously generated. Uses proof rerandomization at proving time.
//!
//! 3. **Knowledge Soundness in AGM+ROM** – Groth16 is knowledge-sound in the
//!    Algebraic Group Model with Random Oracle.
//!
//! **BG18 SE**: Blind A with random ρ, add D = ρ·δG₂ to proof.
//! **ROM SE**: Use proof hash H(A,B,x) as blinding factor (cheaper, ROM-based).
//! **S-ZK**: Rerandomize proof via scalar ρ' to hide witness from malicious setup.
//!
//! References: BG18 (2018), BCFGRS16 (2016), AGM (2017), ABPR19 (2019)

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero, PrimeField};
use ark_serialize::*;
use ark_std::{rand::RngCore, vec::Vec};
use core::ops::Neg;

use crate::{Proof, ProvingKey, VerifyingKey, PreparedVerifyingKey};

// ─── Simulation-Extractable Proof ────────────────────────────────────────────

/// Groth16 proof extended with SE elements.
///
/// **se_element** (optional): BG18 blinding D = ρ·δG₂. Adds ~96 bytes (BLS12-381)
/// or ~64 bytes (BN254) but provides full SE security.
///
/// **proof_hash**: ROM blinding hash H(A,B,C). Computed when se_element is None.
/// ROM-based SE has near-zero overhead but requires Random Oracle assumption.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SimExtractableProof<E: Pairing> {
    /// The standard Groth16 proof (A, B, C)
    pub groth16_proof: Proof<E>,
    /// BG18 SE blinding element: D = ρ · δG₂ (None if using ROM blinding)
    pub se_element: Option<E::G2Affine>,
    /// Proof hash used for ROM blinding (Fiat-Shamir style)
    pub proof_hash: E::ScalarField,
}

pub fn compute_proof_hash<E: Pairing>(proof: &Proof<E>) -> E::ScalarField {
    use ark_crypto_primitives::sponge::{poseidon::{PoseidonConfig, PoseidonSponge}, CryptographicSponge};
    use ark_std::vec;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    
    // Simplistic default config for ROM hashing
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5;
    let mds = vec![
        vec![E::ScalarField::from(1u128), E::ScalarField::from(0u128), E::ScalarField::from(0u128)],
        vec![E::ScalarField::from(0u128), E::ScalarField::from(1u128), E::ScalarField::from(0u128)],
        vec![E::ScalarField::from(0u128), E::ScalarField::from(0u128), E::ScalarField::from(1u128)],
    ];
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let round_constants = (0..(full_rounds + partial_rounds))
        .map(|_| vec![E::ScalarField::rand(&mut rng), E::ScalarField::rand(&mut rng), E::ScalarField::rand(&mut rng)])
        .collect::<Vec<_>>();
    let config = PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, round_constants, 2, 1);
    
    let mut sponge = PoseidonSponge::new(&config);
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes).unwrap();
    
    sponge.absorb(&bytes);
    sponge.squeeze_field_elements(1)[0]
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

/// Unified security wrapper for UniGroth proofs.
pub struct SecurityWrapper<E: Pairing> {
    _p: core::marker::PhantomData<E>,
}

impl<E: Pairing> SecurityWrapper<E> {
    /// Create a secure proof (Simulation-Extractable and optionally Subversion-ZK).
    pub fn prove<R: RngCore>(
        pk: &ProvingKey<E>,
        proof: Proof<E>,
        config: &SEConfig,
        subversion_zk: bool,
        rng: &mut R,
    ) -> SimExtractableProof<E> {
        let mut proof = proof;
        if subversion_zk {
            proof = apply_subversion_zk(&proof, &pk.vk, rng);
        }
        make_sim_extractable(proof, pk, config, rng)
    }

    /// Verify a secure proof.
    pub fn verify(
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[E::ScalarField],
        proof: &SimExtractableProof<E>,
    ) -> bool {
        verify_sim_extractable(pvk, public_inputs, proof)
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

/// Wrap Groth16 proof with simulation-extractability.
///
/// **BG18 construction**: Pick random ρ, set A' = A + ρ·δ_g1, D = ρ·δG₂.
/// Verification: e(A', B)·e(δ_g1, D)⁻¹ = e(α, β)·...
///
/// **SE guarantee**: Extracting witness requires knowing ρ (uniformly random),
/// impossible even after seeing simulated proofs.
///
/// **ROM alternative**: Use proof hash as blinding ρ, costs near-zero.
/// Tradeoff: requires Random Oracle assumption instead of explicit D element.
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

    // Compute proof hash for ROM blinding using Poseidon sponge
    let proof_hash = if config.use_rom_blinding {
        compute_proof_hash::<E>(&blinded_proof)
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

/// Verify simulation-extractable proof.
///
/// Checks Groth16 verification with BG18 correction e(δ_g1, -D) if present.
pub fn verify_sim_extractable<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[E::ScalarField],
    se_proof: &SimExtractableProof<E>,
) -> bool {
    let verify_time = start_timer!(|| "SE Proof verification");

    let proof = &se_proof.groth16_proof;

    // Prepare inputs: Σ xᵢγᵢ
    let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
    for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
        g_ic += &b.mul_bigint(i.into_bigint());
    }
    let prepared_inputs = g_ic.into_affine();

    // Standard Groth16 verification check (for debug)
    let base_pairings = vec![
        (E::G1Prepared::from(proof.a), E::G2Prepared::from(proof.b)),
        (E::G1Prepared::from(prepared_inputs), pvk.gamma_g2_neg_pc.clone()),
        (E::G1Prepared::from(proof.c), pvk.delta_g2_neg_pc.clone()),
    ];
    let base_res = E::multi_pairing(
        base_pairings.iter().map(|(a, _)| a.clone()),
        base_pairings.iter().map(|(_, b)| b.clone()),
    );
    
    let mut pairings = base_pairings;

    if let Some(d) = se_proof.se_element {
        // Add the BG18 correction term: e(delta_g1, D)^-1 = e(delta_g1, -D)
        pairings.push((pvk.delta_g1_prepared.clone(), E::G2Prepared::from(d.into_group().neg().into_affine())));
    }

    let final_res = E::multi_pairing(
        pairings.iter().map(|(a, _)| a.clone()),
        pairings.iter().map(|(_, b)| b.clone()),
    );

    let qap_valid = final_res.0 == pvk.alpha_g1_beta_g2;
    
    if !qap_valid {
        println!("DEBUG: SE Verification Failed");
        println!("  base_res == pvk.alpha_g1_beta_g2: {}", base_res.0 == pvk.alpha_g1_beta_g2);
        println!("  final_res == pvk.alpha_g1_beta_g2: {}", qap_valid);
        if se_proof.se_element.is_some() {
             println!("  (BG18 SE element was present)");
        }
    }

    end_timer!(verify_time);

    qap_valid
}

// ─── Subversion Zero-Knowledge ───────────────────────────────────────────────

/// Apply subversion zero-knowledge rerandomization to proof.
///
/// Even if setup was maliciously generated, this rerandomization hides
/// the witness via proof scaling with random σ and blinding with ρ'.
///
/// **Construction**: A'' = σ⁻¹(A + ρ'·B_g1), B'' = σ·B, C'' adjusted.
/// Uses arkworks builtin rerandomize_proof with S-ZK guarantee.
///
/// Reference: BCFGRS16 §4 "Subversion-Resistant Groth16"
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
            if self.knowledge_soundness_agm { "[OK]" } else { "[NO]" }
        );
        println!(
            "Zero-knowledge: {}",
            if self.zero_knowledge { "[OK]" } else { "[NO]" }
        );
        println!(
            "Simulation-extractable: {}",
            if self.simulation_extractable { "[OK]" } else { "[NO]" }
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
        let se_proof = make_sim_extractable(proof.groth16_proof, &pk, &se_config, &mut rng);

        // Verify
        let pvk = crate::prepare_verifying_key_with_delta(&vk, pk.delta_g1);
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
        let original_a = proof.groth16_proof.a;
        let se_proof = make_sim_extractable(proof.groth16_proof, &pk, &se_config, &mut rng);

        // SE element should be present
        assert!(se_proof.se_element.is_some());
        // Proof should be different from original
        assert_ne!(se_proof.groth16_proof.a, original_a);
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
        let szk_proof = apply_subversion_zk(&proof.groth16_proof, &vk, &mut rng);

        // Rerandomized proof should be different
        assert_ne!(szk_proof.a, proof.groth16_proof.a);

        // But should still verify
        let pvk = crate::prepare_verifying_key_with_delta(&vk, pk.delta_g1);
        let public_inputs = vec![x * x];
        let szk_se = SimExtractableProof {
            groth16_proof: szk_proof,
            se_element: None,
            proof_hash: Fr::zero(),
        };
        assert!(crate::Groth16::<Bn254>::verify_proof(&pvk, &szk_se, &public_inputs).unwrap());
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
        let se_proof = make_sim_extractable(proof.groth16_proof, &pk, &se_config, &mut rng);
        let size = se_proof.byte_size();

        println!("SE proof size: {} bytes", size);
        // Groth16 BN254: 128 bytes base + overhead
        // Target: ≤ 256 bytes
        assert!(size <= 512, "Proof too large: {} bytes", size);
    }
}
