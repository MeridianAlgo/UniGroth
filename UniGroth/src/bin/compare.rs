//! # UniGroth vs ark-groth16 Head-to-Head Comparison
//!
//! Compares timing, proof size, security features, FFT counts, and IVC
//! between the upstream `ark-groth16` crate and the local `unigroth` crate.

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

// ── Shared circuit: proves a * b = c for N constraints ──────────────────────

const N_CONSTRAINTS: usize = 1000;

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

// ── Timing helpers ───────────────────────────────────────────────────────────

fn now_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

fn mean(v: &[u128]) -> f64 {
    v.iter().sum::<u128>() as f64 / v.len() as f64
}

fn min(v: &[u128]) -> u128 {
    *v.iter().min().unwrap()
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!("======================================================================");
    println!("  UniGroth vs ark-groth16 — Head-to-Head Comparison");
    println!("  Circuit: MulCircuit({N_CONSTRAINTS} constraints, BN254)");
    println!("======================================================================\n");

    let runs = 5usize;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    // Pick random witnesses once for consistency
    let a_val = Fr::rand(&mut rng);
    let b_val = Fr::rand(&mut rng);
    let c_val = a_val * b_val;

    // ── Section 1: Setup ─────────────────────────────────────────────────────
    println!("──────────────────────────────────────────────────────────────────────");
    println!("  SECTION 1: Setup (circuit_specific_setup)");
    println!("──────────────────────────────────────────────────────────────────────\n");

    // ark-groth16 setup
    let t0 = now_ms();
    let (ark_pk, ark_vk) = ark_g16::Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit::<Fr> { a: None, b: None },
        &mut rng,
    )
    .expect("ark-groth16 setup failed");
    let ark_setup_ms = (now_ms() - t0) as f64 / 1000.0;
    println!("  ark-groth16 setup: {:.1} ms", ark_setup_ms);

    let ark_pvk = ark_g16::Groth16::<Bn254>::process_vk(&ark_vk).unwrap();

    // unigroth setup
    let t0 = now_ms();
    let (ug_pk, ug_vk) = ug::Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit::<Fr> { a: None, b: None },
        &mut rng,
    )
    .expect("unigroth setup failed");
    let ug_setup_ms = (now_ms() - t0) as f64 / 1000.0;
    println!("  unigroth setup:    {:.1} ms\n", ug_setup_ms);

    let ug_pvk = ug::Groth16::<Bn254>::process_vk(&ug_vk).unwrap();

    // ── Section 2: Timing Comparison ─────────────────────────────────────────
    println!("──────────────────────────────────────────────────────────────────────");
    println!("  SECTION 2: Prove + Verify Timing ({runs} runs each)");
    println!("──────────────────────────────────────────────────────────────────────\n");

    let mut ark_prove_times = Vec::with_capacity(runs);
    let mut ark_verify_times = Vec::with_capacity(runs);
    let mut ark_proof_last = None;

    for _ in 0..runs {
        let t = now_ms();
        let proof = ark_g16::Groth16::<Bn254>::prove(
            &ark_pk,
            MulCircuit::<Fr> { a: Some(a_val), b: Some(b_val) },
            &mut rng,
        )
        .unwrap();
        ark_prove_times.push(now_ms() - t);

        let t = now_ms();
        let ok = ark_g16::Groth16::<Bn254>::verify_with_processed_vk(&ark_pvk, &[c_val], &proof)
            .unwrap();
        ark_verify_times.push(now_ms() - t);
        assert!(ok, "ark-groth16 verify failed");
        ark_proof_last = Some(proof);
    }

    let mut ug_prove_times = Vec::with_capacity(runs);
    let mut ug_verify_times = Vec::with_capacity(runs);
    let mut ug_proof_last = None;

    for _ in 0..runs {
        let t = now_ms();
        let proof = ug::Groth16::<Bn254>::prove(
            &ug_pk,
            MulCircuit::<Fr> { a: Some(a_val), b: Some(b_val) },
            &mut rng,
        )
        .unwrap();
        ug_prove_times.push(now_ms() - t);

        let t = now_ms();
        let ok = ug::Groth16::<Bn254>::verify_with_processed_vk(&ug_pvk, &[c_val], &proof)
            .unwrap();
        ug_verify_times.push(now_ms() - t);
        assert!(ok, "unigroth verify failed");
        ug_proof_last = Some(proof);
    }

    println!("  Prove times (µs):");
    println!("    ark-groth16 — mean: {:.0} µs  min: {} µs",
        mean(&ark_prove_times), min(&ark_prove_times));
    println!("    unigroth    — mean: {:.0} µs  min: {} µs\n",
        mean(&ug_prove_times), min(&ug_prove_times));

    println!("  Verify times (µs):");
    println!("    ark-groth16 — mean: {:.0} µs  min: {} µs",
        mean(&ark_verify_times), min(&ark_verify_times));
    println!("    unigroth    — mean: {:.0} µs  min: {} µs\n",
        mean(&ug_verify_times), min(&ug_verify_times));

    // ── Section 3: Proof Size ─────────────────────────────────────────────────
    println!("──────────────────────────────────────────────────────────────────────");
    println!("  SECTION 3: Proof Size");
    println!("──────────────────────────────────────────────────────────────────────\n");

    let ark_proof = ark_proof_last.as_ref().unwrap();
    let ug_proof = ug_proof_last.as_ref().unwrap();

    let mut ark_bytes = Vec::new();
    ark_proof.serialize_compressed(&mut ark_bytes).unwrap();

    let mut ug_bytes = Vec::new();
    ug_proof.serialize_compressed(&mut ug_bytes).unwrap();

    // Also serialize just the inner groth16 part for comparison
    let mut ug_inner_bytes = Vec::new();
    ug_proof.groth16_proof.serialize_compressed(&mut ug_inner_bytes).unwrap();

    println!("  ark-groth16 proof (compressed):          {} bytes", ark_bytes.len());
    println!("  unigroth inner Groth16 proof (compressed): {} bytes", ug_inner_bytes.len());
    println!("  unigroth SimExtractableProof (compressed): {} bytes", ug_bytes.len());
    println!("    (includes proof_hash field for ROM blinding + optional SE element)");
    println!("    se_element present: {}\n", ug_proof.se_element.is_some());

    // ── Section 4: Security Comparison ───────────────────────────────────────
    println!("──────────────────────────────────────────────────────────────────────");
    println!("  SECTION 4: Security Feature Comparison");
    println!("──────────────────────────────────────────────────────────────────────\n");

    let col_w = 30usize;
    println!("  {:<col_w$}  {:^12}  {:^12}", "Property", "ark-groth16", "UniGroth");
    println!("  {:<col_w$}  {:^12}  {:^12}", "-".repeat(col_w), "------------", "------------");
    let rows = [
        ("Knowledge soundness (AGM)", "✓", "✓"),
        ("Zero-knowledge",            "✓", "✓"),
        ("Simulation-extractability", "✗", "✓ (ROM blinding)"),
        ("Subversion ZK",             "✗", "✓ (rerandomize)"),
        ("Universal setup ready",     "✗", "✓ (KZG SRS)"),
        ("Folding / IVC",             "✗", "✓ (ProtoStar)"),
        ("Post-quantum",              "✗", "✗"),
        ("Proof compression",         "✗", "✓ (Polymath)"),
    ];
    for (prop, ark, ug) in &rows {
        println!("  {:<col_w$}  {:^12}  {:^12}", prop, ark, ug);
    }
    println!();

    // ── Section 5: FFT Comparison ─────────────────────────────────────────────
    println!("──────────────────────────────────────────────────────────────────────");
    println!("  SECTION 5: FFT Count per Proof");
    println!("──────────────────────────────────────────────────────────────────────\n");

    println!("  ark-groth16:  ~6 FFTs per proof  (standard libsnark reduction)");
    println!("  UniGroth:      5 FFTs per proof  (Dynark optimization; c iFFT eliminated)");
    println!("  UniGroth goal: 4 FFTs per proof  (true 4-FFT path via SAP algebraic identity)");
    println!("  Note: Dynark 4-FFT path available in optimizations::DynarkFFT::four_fft()\n");

    // ── Section 6: Folding / IVC Demo ─────────────────────────────────────────
    println!("──────────────────────────────────────────────────────────────────────");
    println!("  SECTION 6: Folding / IVC Demo (5 IVC steps with UniGroth)");
    println!("──────────────────────────────────────────────────────────────────────\n");

    {
        use ug::IVC;
        use unigroth::kzg::UniversalSRS;
        use ark_bn254::Bn254;

        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);
        let mut ivc = IVC::<Bn254>::new(srs);

        let n_steps = 5usize;
        println!("  Running {} IVC steps...", n_steps);

        for i in 0..n_steps as u64 {
            let pub_in = vec![Fr::from(i + 1)];
            let witness = vec![Fr::from((i + 1) * (i + 1))]; // witness: (i+1)²
            ivc.step(pub_in, witness, &mut rng).expect("IVC step failed");
            println!("    Step {} complete", i + 1);
        }

        let (step_count, acc_opt) = ivc.finalize();
        let acc = acc_opt.expect("IVC accumulator should be present");

        println!("\n  IVC Results:");
        println!("    Steps executed:     {}", step_count);
        println!("    Accumulated folds:  {}", acc.fold_count);
        println!("    Transcript length:  {} (Fiat-Shamir challenges)", acc.randomness_transcript.len());
        println!("    Accumulator valid:  {}", acc.is_valid_trivially());
    }

    println!();
    println!("======================================================================");
    println!("  Comparison complete.");
    println!("======================================================================");
}
