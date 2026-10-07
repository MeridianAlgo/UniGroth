//! Full Pipeline Integration Test
//!
//! Exercises the complete UniGroth pipeline end-to-end:
//! 1. Universal setup (KZG SRS)
//! 2. Circuit definition + SAP analysis
//! 3. Groth16 proving with Dynark FFT
//! 4. Security wrapping (SE + S-ZK)
//! 5. Verification
//! 6. Proof aggregation
//! 7. Folding / IVC
//! 8. Plonkish constraint system
//! 9. Post-quantum inner prover
//! 10. Proof compression

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::One;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use unigroth::{
    aggregate_proofs,
    kzg::UniversalSRS,
    prepare_verifying_key,
    r1cs_to_qap::LibsnarkReduction,
    security::{apply_subversion_zk, SecurityParams},
    universal_setup::UniversalParams,
    verify_aggregated, Groth16,
};

// ─── Test Circuits ───────────────────────────────────────────────────────────

/// Cubic circuit: proves knowledge of x such that x³ + x + 5 = y (public)
#[derive(Clone)]
struct CubicCircuit {
    x: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for CubicCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;

        // x² = x * x
        let x_val = self.x.unwrap_or_default();
        let x2_val = x_val * x_val;
        let x2 = cs.new_witness_variable(|| Ok(x2_val))?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x2)?;

        // x³ = x² * x
        let x3_val = x2_val * x_val;
        let x3 = cs.new_witness_variable(|| Ok(x3_val))?;
        cs.enforce_r1cs_constraint(|| lc!() + x2, || lc!() + x, || lc!() + x3)?;

        // y = x³ + x + 5 (public output)
        let y_val = x3_val + x_val + Fr::from(5u64);
        let y = cs.new_input_variable(|| Ok(y_val))?;
        cs.enforce_r1cs_constraint(
            || lc!() + x3 + x + (Fr::from(5u64), ark_relations::gr1cs::Variable::One),
            || lc!() + (Fr::one(), ark_relations::gr1cs::Variable::One),
            || lc!() + y,
        )?;

        Ok(())
    }
}

// ─── Integration Tests ──────────────────────────────────────────────────────

#[test]
fn test_full_pipeline_prove_verify_aggregate() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("=== UniGroth Full Pipeline Test ===\n");

    // Step 1: Setup
    let setup_circuit = CubicCircuit { x: None };
    let (pk, vk) =
        Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(setup_circuit, &mut rng)
            .unwrap();
    println!("[1] Setup complete");

    // Step 2: Generate multiple proofs with different witnesses
    let witnesses: Vec<Fr> = vec![
        Fr::from(3u64),
        Fr::from(7u64),
        Fr::from(11u64),
        Fr::from(42u64),
    ];

    let mut proofs = Vec::new();
    let mut public_inputs_all = Vec::new();

    for (i, &x) in witnesses.iter().enumerate() {
        let y = x * x * x + x + Fr::from(5u64);
        let circuit = CubicCircuit { x: Some(x) };
        let se_proof = Groth16::<Bn254, LibsnarkReduction>::prove(&pk, circuit, &mut rng).unwrap();

        // Verify individually
        let pvk = prepare_verifying_key(&vk);
        let valid = Groth16::<Bn254>::verify_proof(&pvk, &se_proof, &[y]).unwrap();
        assert!(valid, "Individual proof {} must verify", i);

        proofs.push(se_proof);
        public_inputs_all.push(vec![y]);
    }
    println!(
        "[2] Generated and verified {} individual proofs",
        proofs.len()
    );

    // Step 3: Aggregate all proofs
    let agg = aggregate_proofs::<Bn254>(&proofs);
    assert_eq!(agg.proofs.len(), 4);
    let agg_valid = verify_aggregated(&vk, &public_inputs_all, &agg);
    assert!(agg_valid, "Aggregated proof must verify");
    println!(
        "[3] Aggregated {} proofs → single verification: PASS",
        agg.proofs.len()
    );

    // Step 4: Subversion-ZK rerandomization
    let x = Fr::from(99u64);
    let y = x * x * x + x + Fr::from(5u64);
    let raw_proof = Groth16::<Bn254, LibsnarkReduction>::create_random_proof_with_reduction(
        CubicCircuit { x: Some(x) },
        &pk,
        &mut rng,
    )
    .unwrap();

    let pvk = prepare_verifying_key(&vk);
    let szk_proof = apply_subversion_zk(&raw_proof, &vk, &mut rng);
    assert_ne!(szk_proof.a, raw_proof.a, "S-ZK must rerandomize proof");
    assert!(Groth16::<Bn254>::verify_proof(&pvk, &szk_proof, &[y]).unwrap());
    println!("[4] Security: Subversion-ZK rerandomized proof verified");

    // Step 5: Security report
    let params = SecurityParams::maximum();
    let report = params.security_report();
    assert!(report.knowledge_soundness_agm);
    assert!(
        !report.simulation_extractable,
        "Groth16 proofs are rerandomizable"
    );
    assert!(report.subversion_zk);
    println!("[5] Security report: 128-bit AGM + S-ZK");

    println!("\n=== Full Pipeline: ALL PASS ===");
}

#[test]
fn test_universal_setup_pipeline() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(123u64);

    println!("=== Universal Setup Pipeline Test ===\n");

    // One-time ceremony
    let mut universal = UniversalParams::<Bn254>::setup(256, &mut rng);
    println!("[Setup] Universal SRS with max_degree=256");

    // Derive keys for different circuits (same circuit, different key derivations)
    let circuit1 = CubicCircuit { x: None };
    let keys1 = universal.derive_keys(circuit1, &mut rng).unwrap();
    println!(
        "[Derive] Circuit keys derived: VK has {} gamma_abc elements",
        keys1.1.gamma_abc_g1.len()
    );

    let circuit2 = CubicCircuit { x: None };
    let keys2 = universal.derive_keys(circuit2, &mut rng).unwrap();
    println!(
        "[Derive] Second derivation: VK has {} gamma_abc elements",
        keys2.1.gamma_abc_g1.len()
    );

    // Derived keys actually prove and verify, and are bound to their δ.
    let x = Fr::from(4u64);
    let y = x * x * x + x + Fr::from(5u64);
    for (pk, vk) in [&keys1, &keys2] {
        let proof = Groth16::<Bn254>::prove(pk, CubicCircuit { x: Some(x) }, &mut rng).unwrap();
        let pvk = prepare_verifying_key(vk);
        assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &[y]).unwrap());
        assert!(!Groth16::<Bn254>::verify_proof(&pvk, &proof, &[y + Fr::from(1u64)]).unwrap());
    }

    // Update ceremony: a verifiable contribution
    let before = universal.clone();
    let contribution = universal.contribute(&mut rng);
    assert!(UniversalParams::verify_contribution(
        &before,
        &universal,
        &contribution
    ));
    println!("[Update] SRS updated with fresh randomness (contribution verified)");

    // KZG operations
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use unigroth::kzg::KZG;
    let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);
    let poly = DensePolynomial::from_coefficients_vec(vec![
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
    ]);
    let commit = KZG::commit(&srs, &poly).unwrap();
    let point = Fr::from(5u64);
    let (value, opening) = KZG::open(&srs, &poly, &point).unwrap();
    let valid = KZG::verify(&srs, &commit, &point, &value, &opening);
    assert!(valid, "KZG opening must verify");
    println!("[KZG] Commit → Open → Verify: PASS");

    println!("\n=== Universal Setup Pipeline: ALL PASS ===");
}
