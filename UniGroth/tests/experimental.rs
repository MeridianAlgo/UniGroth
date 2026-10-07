//! Tests for modules behind the `experimental` feature. These modules are
//! research scaffolds with documented soundness gaps; see the crate docs.
//! Run with `cargo test --features experimental`.

#![cfg(feature = "experimental")]

use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_std::rand::SeedableRng;
use unigroth as ug;
use unigroth::{
    folding::{verify_accumulator, IVC},
    kzg::UniversalSRS,
    optimizations::{
        compute_h_coset_evals, compute_witness_4fft, parallel_msm, CosetDomainCache,
        GpuMsmDispatcher, PolymathCompressor, ProverProfile,
    },
    plonkish::{plonkish_to_r1cs_constraints, PlonkishConstraintSystem},
    pq_inner::{
        aggregate_pq_proofs, prove_pq, verify_pq, BiniusProver, HybridProver, Plonky3Prover,
        PqConfig, PqInnerProver, PqProof, PqScheme,
    },
};

// from groth16_comparison.rs
// ─── 5. Plonkish Arithmetization: Custom Gates + Lookups ─────────────────────

#[test]
fn compare_plonkish_unigroth_exclusive() {
    let mut cs = ug::plonkish::PlonkishConstraintSystem::<Fr>::new();

    // Build circuit with diverse gate types
    let a = Fr::from(7u64);
    let b = Fr::from(13u64);

    // Addition gates (FREE in Plonkish — each costs 1 R1CS constraint in ark-groth16)
    let _sum = cs.add_add_gate(a, b);

    // Multiplication gate
    cs.add_mul_gate(a, b, a * b);

    // Range check via lookup (1 Plonkish row — needs ~16 R1CS constraints for 4-bit)
    cs.add_range_check(Fr::from(15u64), 4);

    // Poseidon S-box custom gate (1 row — needs ~5 mul constraints in R1CS)
    let sbox_out = cs.add_poseidon_sbox(Fr::from(2u64));
    assert_eq!(sbox_out, Fr::from(2u64).pow([5u64]));

    // Copy constraint (permutation argument)
    cs.add_copy_constraint((0, 2), (2, 0));

    assert!(cs.is_satisfied(), "Plonkish circuit must be satisfied");

    let stats = cs.stats();
    assert!(
        stats.compression_ratio > 1.0,
        "Plonkish must compress vs R1CS (got {:.1}x)",
        stats.compression_ratio
    );

    // Convert to R1CS for final Groth16 proof
    let r1cs = ug::plonkish::plonkish_to_r1cs_constraints(&cs);
    for c in &r1cs {
        assert!(c.is_satisfied());
    }

    println!("[PLONKISH] UniGroth exclusive features:");
    println!("  Custom gates: Poseidon S-box, EC add, boolean, bit decomp");
    println!("  Lookup tables: range checks, XOR");
    println!("  Copy constraints (permutation argument)");
    println!("  {:.1}x compression vs pure R1CS", stats.compression_ratio);
    println!(
        "  {} Plonkish rows → {} R1CS constraints",
        stats.total_rows,
        r1cs.len()
    );
    println!("  ark-groth16: R1CS ONLY — no custom gates, no lookups");
}

// from groth16_comparison.rs
// ─── 7. Folding / IVC: ProtoStar Recursion ──────────────────────────────────

#[test]
fn compare_folding_ivc_unigroth_exclusive() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
    let srs = ug::kzg::UniversalSRS::<Bn254>::setup(128, &mut rng);

    // IVC: 10 computation steps folded into one accumulator
    let mut ivc = ug::folding::IVC::<Bn254>::new(srs.clone());
    for i in 0..10u64 {
        let public = vec![Fr::from(i), Fr::from(i * i)];
        let witness = vec![Fr::from(i + 1), Fr::from((i + 1) * (i + 1))];
        ivc.step(public, witness, &mut rng).unwrap();
    }

    let (steps, acc) = ivc.finalize();
    assert_eq!(steps, 10);
    let acc = acc.unwrap();
    assert_eq!(acc.fold_count, 10);
    assert_eq!(acc.randomness_transcript.len(), 9);

    // Full decision predicate verification
    assert!(
        ug::folding::verify_accumulator(&srs, &acc),
        "Accumulator must pass decision predicate after 10 honest folds"
    );

    // Verify the folding engine independently
    let instance = ug::folding::FoldingInstance {
        public_inputs: vec![Fr::from(42u64)],
        witness: vec![Fr::from(42u64)],
        slack: Fr::one(),
    };
    let mut engine = ug::folding::FoldingEngine::<Bn254>::new(srs.clone());
    engine.fold(instance, &mut rng).unwrap();
    let engine_acc = engine.finalize().unwrap();
    assert!(ug::folding::verify_accumulator(&srs, &engine_acc));

    println!("[FOLDING/IVC] UniGroth: ProtoStar folding with full decision predicate");
    println!(
        "  10 IVC steps → single accumulator (fold_count={})",
        acc.fold_count
    );
    println!("  Relaxed R1CS: A(z)*B(z) = mu*C(z) + e verified per-constraint");
    println!("  KZG witness commitment linearity check");
    println!("  ark-groth16: NO folding, NO IVC, NO recursion");
}

// from groth16_comparison.rs
// ─── 8. Post-Quantum Path: SHA-256-Backed Provers ───────────────────────────

#[test]
fn compare_pq_path_unigroth_exclusive() {
    let witness = b"secret_witness_data_for_comparison_test";
    let public_inputs = b"public_statement";

    for scheme in [
        ug::pq_inner::PqScheme::Binius,
        ug::pq_inner::PqScheme::Plonky3,
        ug::pq_inner::PqScheme::Hybrid,
    ] {
        let config = ug::pq_inner::PqConfig::new(scheme.clone());
        let proof = ug::pq_inner::prove_pq(&config, witness, public_inputs);

        // Must verify with correct inputs
        assert!(
            ug::pq_inner::verify_pq(&config, &proof, public_inputs),
            "{:?} proof must verify",
            scheme
        );

        // Must reject wrong inputs (public input binding)
        assert!(
            !ug::pq_inner::verify_pq(&config, &proof, b"wrong_inputs"),
            "{:?} must reject wrong public inputs",
            scheme
        );

        println!(
            "  [{:?}] {} bytes, verified, wrong inputs rejected",
            scheme,
            proof.byte_len()
        );
    }

    // PQ proof aggregation
    let config = ug::pq_inner::PqConfig::new(ug::pq_inner::PqScheme::Binius);
    let proofs: Vec<_> = (0..4)
        .map(|i| ug::pq_inner::BiniusProver::prove(&config, &[i as u8; 64], b"agg"))
        .collect();
    let agg = ug::pq_inner::aggregate_pq_proofs(&proofs, &config);
    assert!(!agg.is_empty());

    println!("[POST-QUANTUM] UniGroth: SHA-256-backed PQ inner provers");
    println!("  Binius (binary fields), Plonky3 (FRI), Hybrid (Plonky3+Groth16)");
    println!("  Public input binding via SHA-256 commitment");
    println!("  PQ proof aggregation via Merkle digest chains");
    println!("  ark-groth16: NO post-quantum support (pairing-based only)");
}

// from groth16_comparison.rs
// ─── 9. Optimizations: Faster Proving ────────────────────────────────────────

#[test]
fn compare_optimizations_unigroth_superior() {
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    // 1. Dynark 5-FFT (ark-groth16 uses ~6-7 FFTs)
    let domain_size = 64;
    let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();
    let a: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(&mut rng)).collect();
    let b: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(&mut rng)).collect();

    let result = ug::optimizations::compute_witness_4fft(&domain, a.clone(), b.clone());
    assert_eq!(result.fft_count, 5, "Must use 5 FFTs (not 6-7)");

    // 2. True 4-FFT coset evaluation
    let (h_coset, fft4) = ug::optimizations::compute_h_coset_evals(&domain, a.clone(), b.clone());
    assert_eq!(fft4, 4, "Coset path must use only 4 FFTs");
    assert_eq!(h_coset.len(), 2 * domain_size);

    // 3. Coset domain cache (eliminates repeated domain rebuild)
    let cache =
        ug::optimizations::CosetDomainCache::<Fr, GeneralEvaluationDomain<Fr>>::new(domain_size)
            .unwrap();
    let cached = ug::optimizations::compute_witness_4fft_with_cache(&domain, &cache, a, b);
    assert_eq!(result.h_poly, cached.h_poly, "Cached must match uncached");

    // 4. CSR sparse matrix (skip zero rows)
    let sparse_matrix = vec![
        vec![(Fr::from(3u64), 0), (Fr::from(5u64), 2)],
        vec![], // empty row — skipped by CSR
        vec![(Fr::from(1u64), 1)],
        vec![], // empty row — skipped by CSR
    ];
    let csr = ug::optimizations::CsrMatrix::from_ark_matrix(&sparse_matrix, 4, 4);
    assert_eq!(csr.nnz_rows.len(), 2, "CSR must skip {} zero rows", 4 - 2);

    // 5. Parallel MSM (rayon-accelerated Pippenger)
    let bases: Vec<ark_bn254::G1Affine> = (0..128)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<Fr> = (0..128).map(|_| Fr::rand(&mut rng)).collect();
    let (msm_result, stats) = ug::optimizations::parallel_msm::<Bn254>(&bases, &scalars);
    assert!(!msm_result.is_zero());

    // 6. Polymath proof compression
    assert!(ug::optimizations::PolymathCompressor::can_compress());
    let est_size = ug::optimizations::PolymathCompressor::compressed_size_estimate::<Bn254>();
    assert!(est_size <= 256, "Compressed proof ≤256 bytes");

    // 7. Speedup estimate
    let speedup = ug::optimizations::ProverProfile::estimate_speedup(3.0, true);
    assert!(
        speedup > 2.0,
        "UniGroth must be >2x faster than vanilla Groth16"
    );

    println!("[OPTIMIZATIONS] UniGroth vs ark-groth16:");
    println!(
        "  Dynark 5-FFT:          {} FFTs vs ~6-7 (17% fewer)",
        result.fft_count
    );
    println!("  True 4-FFT coset:      {} FFTs vs ~6-7 (33% fewer)", fft4);
    println!("  Coset domain cache:    eliminates repeated domain builds");
    println!(
        "  CSR sparse QAP:        skips {} zero rows (2.8-5.5x on sparse)",
        4 - csr.nnz_rows.len()
    );
    println!(
        "  Parallel MSM:          n={}, window={}, algo={}",
        stats.num_scalars, stats.window_size, stats.algorithm
    );
    println!(
        "  Polymath compression:  ~{} bytes (vs 192 uncompressed)",
        est_size
    );
    println!(
        "  Estimated speedup:     {:.1}x vs vanilla Groth16",
        speedup
    );
    println!("  ark-groth16: standard 6-7 FFTs, no CSR, no cache, no compression");
}

// from full_pipeline_test.rs
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
    assert!(
        verify_accumulator(&srs, &acc),
        "Decision predicate must pass after 20 honest folds"
    );

    println!("[IVC] 20 steps folded → accumulator valid");
    println!("  fold_count: {}", acc.fold_count);
    println!("  transcript length: {}", acc.randomness_transcript.len());
    println!("\n=== Folding / IVC Pipeline: ALL PASS ===");
}

// from full_pipeline_test.rs
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
    println!(
        "  Compression:      {:.1}x vs R1CS",
        stats.compression_ratio
    );

    // R1CS conversion
    let r1cs = plonkish_to_r1cs_constraints(&cs);
    assert_eq!(r1cs.len(), stats.mul_gates);
    for c in &r1cs {
        assert!(c.is_satisfied());
    }
    println!(
        "  R1CS constraints: {} (from {} Plonkish rows)",
        r1cs.len(),
        stats.total_rows
    );

    println!("\n=== Plonkish Pipeline: ALL PASS ===");
}

// from full_pipeline_test.rs
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
        assert!(
            !verify_pq(&config, &proof, b"wrong_inputs"),
            "{:?} must reject wrong public inputs",
            config.scheme
        );

        println!(
            "[{:?}] proof: {} bytes, verified: {}",
            config.scheme,
            proof.byte_len(),
            valid
        );
    }

    // Aggregation
    let config = PqConfig::new(PqScheme::Binius);
    let proofs: Vec<_> = (0..8)
        .map(|i| BiniusProver::prove(&config, &[i as u8; 64], b"agg_inputs"))
        .collect();
    let agg = aggregate_pq_proofs(&proofs, &config);
    println!(
        "\n[Aggregation] {} Binius proofs → {} byte aggregate",
        proofs.len(),
        agg.len()
    );

    // Size comparison
    println!("\n[Size Comparison at 128-bit security]");
    println!(
        "  Binius:      {} bytes",
        BiniusProver::prove(&PqConfig::new(PqScheme::Binius), witness, public_inputs).byte_len()
    );
    println!(
        "  Plonky3:     {} bytes",
        Plonky3Prover::prove(&PqConfig::new(PqScheme::Plonky3), witness, public_inputs).byte_len()
    );
    println!(
        "  Hybrid:      {} bytes",
        HybridProver::prove(&PqConfig::new(PqScheme::Hybrid), witness, public_inputs).byte_len()
    );
    println!("  Groth16 SE:  ~160 bytes (pairing-based, not PQ)");

    println!("\n=== Post-Quantum Pipeline: ALL PASS ===");
}

// from full_pipeline_test.rs
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
    println!(
        "[5-FFT] h_poly degree: {}, fft_count: {}",
        result_5fft.h_poly.len(),
        result_5fft.fft_count
    );

    // 4-FFT path (coset evaluation form)
    let (h_coset, fft_count_4) = compute_h_coset_evals(&domain, a.clone(), b.clone());
    assert_eq!(fft_count_4, 4);
    assert_eq!(h_coset.len(), 2 * domain_size);
    println!(
        "[4-FFT] h_coset_evals length: {}, fft_count: {}",
        h_coset.len(),
        fft_count_4
    );

    // Coset domain cache
    let cache = CosetDomainCache::<Fr, GeneralEvaluationDomain<Fr>>::new(domain_size).unwrap();
    let result_cached = unigroth::optimizations::compute_witness_4fft_with_cache(
        &domain,
        &cache,
        a.clone(),
        b.clone(),
    );
    assert_eq!(result_5fft.h_poly, result_cached.h_poly);
    println!("[Cache] Cached result matches uncached ✓");

    // Parallel MSM
    let bases: Vec<ark_bn254::G1Affine> = (0..64)
        .map(|_| ark_bn254::G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<Fr> = (0..64).map(|_| Fr::rand(&mut rng)).collect();
    let (msm_result, stats) = parallel_msm::<Bn254>(&bases, &scalars);
    assert!(!msm_result.is_zero());
    println!(
        "[MSM] n={}, window={}, algorithm={}",
        stats.num_scalars, stats.window_size, stats.algorithm
    );

    // GPU dispatcher (falls back to CPU)
    let (dispatch_result, _) = GpuMsmDispatcher::dispatch::<Bn254>(&bases, &scalars);
    assert_eq!(dispatch_result, msm_result);
    println!(
        "[GPU Dispatch] Falls back to CPU Pippenger for n={} ✓",
        bases.len()
    );

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

// from red_team.rs
/// Documents a known limitation: the hash-based "PQ" inner proofs prove nothing.
/// Anyone can fabricate an accepted proof for arbitrary public inputs without a witness.
#[test]
fn pq_inner_proofs_are_forgeable_by_design() {
    use sha2::{Digest, Sha256};
    let cfg = PqConfig::new(PqScheme::Binius);
    let public = b"any statement the attacker likes";

    let commitment = [0xAAu8; 32]; // arbitrary, no witness behind it
    let mut h = Sha256::new();
    h.update(b"pub_bind");
    h.update([0x01]);
    h.update(commitment);
    h.update((public.len() as u64).to_le_bytes());
    h.update(public);
    let pub_bind = h.finalize();

    let mut body = Vec::new();
    for counter in 0u32..6 {
        body.extend_from_slice(
            &Sha256::new()
                .chain_update(commitment)
                .chain_update(counter.to_le_bytes())
                .finalize(),
        );
    }
    let mut bytes = commitment.to_vec();
    bytes.extend_from_slice(&pub_bind);
    bytes.extend_from_slice(&body[..192]);

    let forged = PqProof {
        bytes,
        scheme: PqScheme::Binius,
    };
    assert!(
        verify_pq(&cfg, &forged, public),
        "forgery accepted: verify_pq is tamper-evidence only"
    );
}
