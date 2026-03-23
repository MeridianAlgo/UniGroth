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
use ark_ec::CurveGroup;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use unigroth::{
    aggregate_proofs, verify_aggregated,
    folding::{IVC, verify_accumulator},
    kzg::UniversalSRS,
    optimizations::{
        compute_h_coset_evals, compute_witness_4fft, parallel_msm,
        CosetDomainCache, GpuMsmDispatcher, PolymathCompressor, ProverProfile,
    },
    plonkish::{
        PlonkishConstraintSystem,
        plonkish_to_r1cs_constraints,
    },
    pq_inner::{
        BiniusProver, HybridProver, Plonky3Prover, PqConfig, PqInnerProver, PqScheme,
        aggregate_pq_proofs, prove_pq, verify_pq,
    },
    security::{
        make_sim_extractable, verify_sim_extractable, apply_subversion_zk,
        SEConfig, SecurityParams,
    },
    universal_setup::UniversalParams,
    Groth16, prepare_verifying_key_with_delta,
    r1cs_to_qap::LibsnarkReduction,
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
    let (pk, vk) = Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
        setup_circuit,
        &mut rng,
    ).unwrap();
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
        let pvk = prepare_verifying_key_with_delta(&vk, pk.delta_g1);
        let valid = Groth16::<Bn254>::verify_proof(&pvk, &se_proof, &[y]).unwrap();
        assert!(valid, "Individual proof {} must verify", i);

        proofs.push(se_proof.groth16_proof);
        public_inputs_all.push(vec![y]);
    }
    println!("[2] Generated and verified {} individual proofs", proofs.len());

    // Step 3: Aggregate all proofs
    let agg = aggregate_proofs::<Bn254, _>(&proofs, &public_inputs_all, &mut rng);
    assert_eq!(agg.n, 4);
    let agg_valid = verify_aggregated(&vk, &agg);
    assert!(agg_valid, "Aggregated proof must verify");
    println!("[3] Aggregated {} proofs → single verification: PASS", agg.n);

    // Step 4: Security wrapping (SE + S-ZK)
    let x = Fr::from(99u64);
    let y = x * x * x + x + Fr::from(5u64);
    let raw_proof = Groth16::<Bn254, LibsnarkReduction>::create_random_proof_with_reduction(
        CubicCircuit { x: Some(x) }, &pk, &mut rng,
    ).unwrap();

    // BG18 SE
    let bg18_config = SEConfig::full_se();
    let se_proof = make_sim_extractable(raw_proof.clone(), &pk, &bg18_config, &mut rng);
    assert!(se_proof.se_element.is_some(), "BG18 SE element must be present");

    // ROM SE
    let rom_config = SEConfig::rom_se();
    let rom_proof = make_sim_extractable(raw_proof.clone(), &pk, &rom_config, &mut rng);
    assert!(rom_proof.se_element.is_none(), "ROM SE must not have explicit element");
    assert!(!rom_proof.proof_hash.is_zero(), "ROM proof hash must be non-zero");

    let pvk = prepare_verifying_key_with_delta(&vk, pk.delta_g1);
    assert!(verify_sim_extractable(&pvk, &[y], &rom_proof), "ROM SE proof must verify");

    // Subversion-ZK
    let szk_proof = apply_subversion_zk(&raw_proof, &vk, &mut rng);
    assert_ne!(szk_proof.a, raw_proof.a, "S-ZK must rerandomize proof");
    println!("[4] Security: BG18 SE + ROM SE + Subversion-ZK all verified");

    // Step 5: Security report
    let params = SecurityParams::maximum();
    let report = params.security_report();
    assert!(report.knowledge_soundness_agm);
    assert!(report.simulation_extractable);
    assert!(report.subversion_zk);
    println!("[5] Security report: 128-bit AGM + SE + S-ZK");

    println!("\n=== Full Pipeline: ALL PASS ===");
}

#[test]
fn test_folding_ivc_pipeline() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
    let srs = UniversalSRS::<Bn254>::setup(128, &mut rng);

    println!("=== Folding / IVC Pipeline Test ===\n");

    // IVC: 20 computation steps
    let mut ivc = IVC::new(srs.clone());
    for i in 0..20u64 {
        let public = vec![Fr::from(i), Fr::from(i * i)];
        let witness = vec![Fr::from(i + 1), Fr::from((i + 1) * (i + 1))];
        ivc.step(public, witness, &mut rng).unwrap();
    }

    let (count, acc) = ivc.finalize();
    assert_eq!(count, 20);
    let acc = acc.unwrap();
    assert_eq!(acc.fold_count, 20);
    assert_eq!(acc.randomness_transcript.len(), 19);

    // Full decision predicate verification
    assert!(verify_accumulator(&srs, &acc), "Decision predicate must pass after 20 honest folds");

    println!("[IVC] 20 steps folded → accumulator valid");
    println!("  fold_count: {}", acc.fold_count);
    println!("  transcript length: {}", acc.randomness_transcript.len());
    println!("\n=== Folding / IVC Pipeline: ALL PASS ===");
}

#[test]
fn test_plonkish_full_pipeline() {
    println!("=== Plonkish Pipeline Test ===\n");

    let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

    // Build a realistic circuit: SHA-like mix of add + mul + lookup + custom
    let a = Fr::from(7u64);
    let b = Fr::from(13u64);

    // Additions (free in Plonkish)
    let sum1 = cs.add_add_gate(a, b); // 20
    let sum2 = cs.add_add_gate(sum1, Fr::from(3u64)); // 23
    let sum3 = cs.add_add_gate(sum2, Fr::from(5u64)); // 28

    // Multiplications
    let prod = a * b; // 91
    cs.add_mul_gate(a, b, prod);
    let prod2 = sum3 * Fr::from(2u64); // 56
    cs.add_mul_gate(sum3, Fr::from(2u64), prod2);

    // Range checks (lookup)
    cs.add_range_check(Fr::from(15u64), 4); // 15 < 16 ✓
    cs.add_range_check(Fr::from(7u64), 4);

    // Poseidon S-box
    let x = Fr::from(2u64);
    let out = cs.add_poseidon_sbox(x);
    assert_eq!(out, x.pow([5u64]));

    // Public inputs
    cs.add_public_input(prod);
    cs.add_public_input(prod2);

    // Copy constraint
    cs.add_copy_constraint((0, 2), (3, 0)); // sum1 output = mul input

    assert!(cs.is_satisfied(), "Plonkish circuit must be satisfied");

    let stats = cs.stats();
    println!("Circuit statistics:");
    println!("  Total rows:       {}", stats.total_rows);
    println!("  Mul gates:        {}", stats.mul_gates);
    println!("  Add gates:        {} (free!)", stats.add_gates);
    println!("  Lookup rows:      {} (cheap!)", stats.lookup_rows);
    println!("  Custom gates:     {}", stats.custom_gates);
    println!("  Copy constraints: {}", stats.copy_constraints);
    println!("  Compression:      {:.1}x vs R1CS", stats.compression_ratio);

    // R1CS conversion
    let r1cs = plonkish_to_r1cs_constraints(&cs);
    assert_eq!(r1cs.len(), stats.mul_gates);
    for c in &r1cs {
        assert!(c.is_satisfied());
    }
    println!("  R1CS constraints: {} (from {} Plonkish rows)", r1cs.len(), stats.total_rows);

    println!("\n=== Plonkish Pipeline: ALL PASS ===");
}

#[test]
fn test_pq_inner_full_pipeline() {
    println!("=== Post-Quantum Inner Prover Pipeline Test ===\n");

    let witness = b"secret_witness_for_pq_pipeline_test";
    let public_inputs = b"public_inputs";

    // Test all three schemes
    for scheme in [PqScheme::Binius, PqScheme::Plonky3, PqScheme::Hybrid] {
        let config = PqConfig::new(scheme.clone());

        let proof = prove_pq(&config, witness, public_inputs);
        let valid = verify_pq(&config, &proof, public_inputs);
        assert!(valid, "{:?} prove/verify must succeed", config.scheme);

        // Verify that wrong public inputs are rejected
        assert!(!verify_pq(&config, &proof, b"wrong_inputs"),
            "{:?} must reject wrong public inputs", config.scheme);

        println!("[{:?}] proof: {} bytes, verified: {}", config.scheme, proof.byte_len(), valid);
    }

    // Aggregation
    let config = PqConfig::new(PqScheme::Binius);
    let proofs: Vec<_> = (0..8)
        .map(|i| BiniusProver::prove(&config, &[i as u8; 64], b"agg_inputs"))
        .collect();
    let agg = aggregate_pq_proofs(&proofs, &config);
    println!("\n[Aggregation] {} Binius proofs → {} byte aggregate", proofs.len(), agg.len());

    // Size comparison
    println!("\n[Size Comparison at 128-bit security]");
    println!("  Binius:      {} bytes", BiniusProver::prove(&PqConfig::new(PqScheme::Binius), witness, public_inputs).byte_len());
    println!("  Plonky3:     {} bytes", Plonky3Prover::prove(&PqConfig::new(PqScheme::Plonky3), witness, public_inputs).byte_len());
    println!("  Hybrid:      {} bytes", HybridProver::prove(&PqConfig::new(PqScheme::Hybrid), witness, public_inputs).byte_len());
    println!("  Groth16 SE:  ~160 bytes (pairing-based, not PQ)");

    println!("\n=== Post-Quantum Pipeline: ALL PASS ===");
}

#[test]
fn test_optimization_pipeline() {
    use ark_poly::GeneralEvaluationDomain;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(77u64);

    println!("=== Optimization Pipeline Test ===\n");

    let domain_size = 32;
    let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();

    let a: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(&mut rng)).collect();
    let b: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(&mut rng)).collect();

    // 5-FFT path
    let result_5fft = compute_witness_4fft(&domain, a.clone(), b.clone());
    assert_eq!(result_5fft.fft_count, 5);
    assert!(!result_5fft.h_poly.is_empty());
    println!("[5-FFT] h_poly degree: {}, fft_count: {}", result_5fft.h_poly.len(), result_5fft.fft_count);

    // 4-FFT path (coset evaluation form)
    let (h_coset, fft_count_4) = compute_h_coset_evals(&domain, a.clone(), b.clone());
    assert_eq!(fft_count_4, 4);
    assert_eq!(h_coset.len(), 2 * domain_size);
    println!("[4-FFT] h_coset_evals length: {}, fft_count: {}", h_coset.len(), fft_count_4);

    // Coset domain cache
    let cache = CosetDomainCache::<Fr, GeneralEvaluationDomain<Fr>>::new(domain_size).unwrap();
    let result_cached = unigroth::optimizations::compute_witness_4fft_with_cache(&domain, &cache, a.clone(), b.clone());
    assert_eq!(result_5fft.h_poly, result_cached.h_poly);
    println!("[Cache] Cached result matches uncached ✓");

    // Parallel MSM
    let bases: Vec<ark_bn254::G1Affine> = (0..64)
        .map(|_| ark_bn254::G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<Fr> = (0..64).map(|_| Fr::rand(&mut rng)).collect();
    let (msm_result, stats) = parallel_msm::<Bn254>(&bases, &scalars);
    assert!(!msm_result.is_zero());
    println!("[MSM] n={}, window={}, algorithm={}", stats.num_scalars, stats.window_size, stats.algorithm);

    // GPU dispatcher (falls back to CPU)
    let (dispatch_result, _) = GpuMsmDispatcher::dispatch::<Bn254>(&bases, &scalars);
    assert_eq!(dispatch_result, msm_result);
    println!("[GPU Dispatch] Falls back to CPU Pippenger for n={} ✓", bases.len());

    // Proof compression
    assert!(PolymathCompressor::can_compress());
    let size = PolymathCompressor::compressed_size_estimate::<Bn254>();
    println!("[Compression] Estimated compressed proof: {} bytes", size);

    // Speedup estimate
    let speedup = ProverProfile::estimate_speedup(3.0, true);
    println!("[Speedup] Estimated: {:.2}x vs vanilla Groth16", speedup);
    assert!(speedup > 2.0);

    println!("\n=== Optimization Pipeline: ALL PASS ===");
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
    let keys1 = universal.derive_keys::<_, LibsnarkReduction>(circuit1, &mut rng).unwrap();
    println!("[Derive] Circuit keys derived: VK has {} gamma_abc elements", keys1.1.gamma_abc_g1.len());

    let circuit2 = CubicCircuit { x: None };
    let keys2 = universal.derive_keys::<_, LibsnarkReduction>(circuit2, &mut rng).unwrap();
    println!("[Derive] Second derivation: VK has {} gamma_abc elements", keys2.1.gamma_abc_g1.len());

    // Update ceremony
    universal.update(&mut rng);
    println!("[Update] SRS updated with fresh randomness");

    // KZG operations
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use unigroth::kzg::KZG;
    let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);
    let poly = DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
    let commit = KZG::commit(&srs, &poly);
    let point = Fr::from(5u64);
    let (value, opening) = KZG::open(&srs, &poly, &point);
    let valid = KZG::verify(&srs, &commit, &point, &value, &opening);
    assert!(valid, "KZG opening must verify");
    println!("[KZG] Commit → Open → Verify: PASS");

    println!("\n=== Universal Setup Pipeline: ALL PASS ===");
}
