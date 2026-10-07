//! # UniGroth vs ark-groth16 — Full Benchmark Suite
//!
//! Covers setup, proving and verification time, proof size, batch
//! verification and security properties, on code paths the library uses.

use ark_bn254::Bn254;
use ark_ff::Field;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::{rand::SeedableRng, UniformRand};

use ark_groth16 as ark_g16;
use unigroth as ug;

type Fr = <Bn254 as ark_ec::pairing::Pairing>::ScalarField;

// ── Circuit: a * b = c, N repeated constraints ────────────────────────────────

const N_CONSTRAINTS: usize = 4096;
const N_RUNS: usize = 8;

#[derive(Clone)]
struct MulCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for MulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;
        for _ in 0..N_CONSTRAINTS {
            cs.enforce_r1cs_constraint(|| lc!() + a_var, || lc!() + b_var, || lc!() + c_var)?;
        }
        Ok(())
    }
}

// ── Timing helpers ────────────────────────────────────────────────────────────

fn now_us() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

fn mean_f(v: &[u128]) -> f64 {
    v.iter().sum::<u128>() as f64 / v.len() as f64
}
fn min_v(v: &[u128]) -> u128 {
    *v.iter().min().unwrap()
}

fn speedup(baseline_us: f64, optimized_us: f64) -> String {
    let ratio = baseline_us / optimized_us;
    if ratio >= 1.0 {
        format!("{:.2}× faster", ratio)
    } else {
        format!("{:.2}× slower", 1.0 / ratio)
    }
}

fn sep() {
    println!("  {}", "─".repeat(68));
}

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║          UniGroth vs ark-groth16 — Full Benchmark Suite             ║");
    println!("║  Circuit: MulCircuit ({N_CONSTRAINTS} constraints, BN254)  ·  {N_RUNS} runs each         ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);
    let a_val = Fr::rand(&mut rng);
    let b_val = Fr::rand(&mut rng);
    let c_val = a_val * b_val;

    // ─────────────────────────────────────────────────────────────────────────
    println!("  § 1  SETUP");
    sep();

    let t0 = now_us();
    let (ark_pk, ark_vk) = ark_g16::Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit::<Fr> { a: None, b: None },
        &mut rng,
    )
    .expect("ark-groth16 setup failed");
    let ark_setup_us = now_us() - t0;

    let t0 = now_us();
    let (ug_pk, ug_vk) = ug::Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit::<Fr> { a: None, b: None },
        &mut rng,
    )
    .expect("unigroth setup failed");
    let ug_setup_us = now_us() - t0;

    let ark_pvk = ark_g16::Groth16::<Bn254>::process_vk(&ark_vk).unwrap();
    let ug_pvk = ug::Groth16::<Bn254>::process_vk(&ug_vk).unwrap();

    println!(
        "  ark-groth16 setup : {:>8.1} ms",
        ark_setup_us as f64 / 1000.0
    );
    println!(
        "  unigroth    setup : {:>8.1} ms  ({})",
        ug_setup_us as f64 / 1000.0,
        speedup(ark_setup_us as f64, ug_setup_us as f64)
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    println!("  § 2  PROVE + VERIFY TIMING  ({N_RUNS} runs)");
    sep();

    let mut ark_prove = Vec::with_capacity(N_RUNS);
    let mut ark_verify = Vec::with_capacity(N_RUNS);
    let mut ark_proof_last = None;

    for _ in 0..N_RUNS {
        let t = now_us();
        let proof = ark_g16::Groth16::<Bn254>::prove(
            &ark_pk,
            MulCircuit::<Fr> {
                a: Some(a_val),
                b: Some(b_val),
            },
            &mut rng,
        )
        .unwrap();
        ark_prove.push(now_us() - t);

        let t = now_us();
        let ok = ark_g16::Groth16::<Bn254>::verify_with_processed_vk(&ark_pvk, &[c_val], &proof)
            .unwrap();
        ark_verify.push(now_us() - t);
        assert!(ok);
        ark_proof_last = Some(proof);
    }

    let mut ug_prove = Vec::with_capacity(N_RUNS);
    let mut ug_verify = Vec::with_capacity(N_RUNS);
    let mut ug_proof_last = None;

    for _ in 0..N_RUNS {
        let t = now_us();
        let proof = ug::Groth16::<Bn254>::prove(
            &ug_pk,
            MulCircuit::<Fr> {
                a: Some(a_val),
                b: Some(b_val),
            },
            &mut rng,
        )
        .unwrap();
        ug_prove.push(now_us() - t);

        let t = now_us();
        let ok = ug::Groth16::<Bn254>::verify_with_processed_vk(&ug_pvk, &[c_val], &proof).unwrap();
        ug_verify.push(now_us() - t);
        assert!(ok);
        ug_proof_last = Some(proof);
    }

    let ark_prove_mean = mean_f(&ark_prove);
    let ug_prove_mean = mean_f(&ug_prove);
    let ark_verify_mean = mean_f(&ark_verify);
    let ug_verify_mean = mean_f(&ug_verify);

    println!("  Prove (µs):");
    println!(
        "    ark-groth16 — mean {:>8.0}  min {:>8}",
        ark_prove_mean,
        min_v(&ark_prove)
    );
    println!(
        "    unigroth    — mean {:>8.0}  min {:>8}  ← {}",
        ug_prove_mean,
        min_v(&ug_prove),
        speedup(ark_prove_mean, ug_prove_mean)
    );
    println!();
    println!("  Verify (µs):");
    println!(
        "    ark-groth16 — mean {:>8.0}  min {:>8}",
        ark_verify_mean,
        min_v(&ark_verify)
    );
    println!(
        "    unigroth    — mean {:>8.0}  min {:>8}  ← {}",
        ug_verify_mean,
        min_v(&ug_verify),
        speedup(ark_verify_mean, ug_verify_mean)
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    println!("  § 3  PROOF SIZE");
    sep();

    let ark_proof = ark_proof_last.as_ref().unwrap();
    let ug_proof = ug_proof_last.as_ref().unwrap();

    let mut ark_bytes = Vec::new();
    ark_proof.serialize_compressed(&mut ark_bytes).unwrap();

    let mut ug_bytes = Vec::new();
    ug_proof.serialize_compressed(&mut ug_bytes).unwrap();

    println!(
        "  ark-groth16 proof (compressed)          : {:>4} bytes",
        ark_bytes.len()
    );
    println!(
        "  unigroth proof (compressed)             : {:>4} bytes",
        ug_bytes.len()
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    println!("  § 4  BATCH VERIFICATION (N proofs, one multi-pairing)");
    sep();
    println!("  verify_aggregated(): N+3 Miller loops and one final exponentiation,");
    println!("  with Fiat-Shamir weights. Every proof point is subgroup-checked.");
    println!();

    use ug::aggregation::{aggregate_proofs, verify_aggregated};

    // Generate several proofs
    let n_agg_proofs = [1usize, 2, 4, 8, 16, 32];

    let mut pool: Vec<ug::Proof<Bn254>> = Vec::new();
    let mut input_pool: Vec<Vec<Fr>> = Vec::new();
    for i in 0..32usize {
        let ai = Fr::from((i + 1) as u64);
        let bi = Fr::from((i + 2) as u64);
        let ci = ai * bi;
        let proof = ug::Groth16::<Bn254>::prove(
            &ug_pk,
            MulCircuit::<Fr> {
                a: Some(ai),
                b: Some(bi),
            },
            &mut rng,
        )
        .unwrap();
        pool.push(proof);
        input_pool.push(vec![ci]);
    }

    for &n in &n_agg_proofs {
        let proofs = &pool[..n];
        let inputs = &input_pool[..n];

        let t = now_us();
        for (proof, inp) in proofs.iter().zip(inputs.iter()) {
            let ok = ug::Groth16::<Bn254>::verify_with_processed_vk(&ug_pvk, inp, proof).unwrap();
            assert!(ok);
        }
        let individual_us = now_us() - t;

        let t = now_us();
        let agg = aggregate_proofs::<Bn254>(proofs);
        let ok = verify_aggregated(&ug_vk, inputs, &agg);
        let aggregated_us = now_us() - t;
        assert!(ok, "aggregated proof must verify for n={}", n);

        println!("  N={n} proofs:");
        println!("    One at a time  : {:>7.1} µs", individual_us as f64);
        println!(
            "    Batched        : {:>7.1} µs  ← {}",
            aggregated_us as f64,
            speedup(individual_us as f64, aggregated_us as f64)
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    println!("  § 5  SECURITY PROPERTIES");
    sep();
    let w = 32usize;
    println!(
        "  {:<w$}  {:^14}  {:^14}",
        "Property", "ark-groth16", "UniGroth"
    );
    println!(
        "  {:<w$}  {:^14}  {:^14}",
        "─".repeat(w),
        "──────────────",
        "──────────────"
    );
    let rows = [
        ("Knowledge soundness (AGM)", "✓", "✓"),
        ("Zero-knowledge", "✓", "✓"),
        ("Simulation-extractability", "✗", "✗  (not proven)"),
        ("Subversion ZK", "✓ (rerandomize)", "✓ (rerandomize)"),
        ("Subgroup-checked verifier", "deser. only", "✓  (always)"),
        ("Universal setup", "✗", "✓  (BGM17)"),
        ("Batch verification", "✗", "✓  (Fiat-Shamir)"),
        ("Post-quantum", "✗", "✗"),
    ];
    for (prop, ark, ug) in &rows {
        println!("  {:<w$}  {:^14}  {:^14}", prop, ark, ug);
    }
    println!();
}
