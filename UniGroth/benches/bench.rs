// UniGroth Comprehensive Benchmark Suite
//
// Benchmarks all key optimizations with real crypto operations:
//   1. 4-FFT vs 6-FFT witness computation
//   2. h_query_scalars O(n) vs O(n log n) (iterative acc vs pow)
//   3. Parallel MSM scaling across thread counts
//   4. End-to-end proving: UniGroth vs arkworks Groth16
//
// Run:
//   cargo bench --no-default-features --features "std parallel" -- --nocapture
//   RAYON_NUM_THREADS=1 cargo bench --no-default-features --features "std parallel" -- --nocapture

use ark_bls12_381::{Bls12_381, Fr as BlsFr, G1Affine as BlsG1Affine, G1Projective as BlsG1};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, UniformRand};
use ark_groth16::{r1cs_to_qap::evaluate_constraint, Groth16 as ArkGroth16};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_std::{
    rand::{Rng, SeedableRng},
    time::Instant,
};
use std::hint::black_box;

use unigroth as ug;

// ─── Circuits ────────────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;
        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        }
        cs.enforce_r1cs_constraint(|| lc!(), || lc!(), || lc!())?;
        Ok(())
    }
}

// ─── Timing ──────────────────────────────────────────────────────────────────

fn sep() {
    println!("  {}", "─".repeat(72));
}

fn speedup_str(baseline_us: f64, optimized_us: f64) -> String {
    let ratio = baseline_us / optimized_us;
    if ratio >= 1.0 {
        format!("{:.2}× faster", ratio)
    } else {
        format!("{:.2}× slower (regression)", 1.0 / ratio)
    }
}

// ─── Benchmark 1: 4-FFT vs 6-FFT ────────────────────────────────────────────

fn bench_fft_comparison() {
    println!("\n  § 1  QUOTIENT FFTs: 2n coset (old) vs n coset (new)");
    sep();
    println!("  Both compute the same h(X) coefficients. The quotient has degree");
    println!("  n-2, so n coset points determine it: the 2n expansion is unneeded.");
    println!("  Old: 3 iFFT(n) + 3 cosetFFT(2n) + 1 icosetFFT(2n).");
    println!("  New: 3 iFFT(n) + 3 cosetFFT(n) + 1 icosetFFT(n).");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    for log_n in [12, 14, 16, 18] {
        let domain_size = 1usize << log_n;
        let domain = GeneralEvaluationDomain::<BlsFr>::new(domain_size).unwrap();
        let iters = match log_n {
            18 => 3,
            16 => 10,
            14 => 30,
            _ => 50,
        };

        let a_evals: Vec<BlsFr> = (0..domain_size).map(|_| BlsFr::rand(&mut rng)).collect();
        let b_evals: Vec<BlsFr> = (0..domain_size).map(|_| BlsFr::rand(&mut rng)).collect();
        let c_evals: Vec<BlsFr> = (0..domain_size).map(|_| BlsFr::rand(&mut rng)).collect();

        let zero = BlsFr::from(0u64);
        let one = BlsFr::from(1u64);

        // Old path: product FFTs on a 2n coset, full h coefficients out.
        let start = Instant::now();
        for _ in 0..iters {
            let mut a = a_evals.clone();
            let mut b = b_evals.clone();
            let mut c = c_evals.clone();
            domain.ifft_in_place(&mut a);
            domain.ifft_in_place(&mut b);
            domain.ifft_in_place(&mut c);
            let double = 2 * domain_size;
            let coset2n = GeneralEvaluationDomain::<BlsFr>::new(double)
                .unwrap()
                .get_coset(BlsFr::GENERATOR)
                .unwrap();
            a.resize(double, zero);
            b.resize(double, zero);
            c.resize(double, zero);
            coset2n.fft_in_place(&mut a);
            coset2n.fft_in_place(&mut b);
            coset2n.fft_in_place(&mut c);
            let g_n = BlsFr::GENERATOR.pow([domain_size as u64]);
            let z_even = (g_n - one).inverse().unwrap();
            let z_odd = (-g_n - one).inverse().unwrap();
            let mut h: Vec<BlsFr> = a
                .iter()
                .zip(b.iter())
                .zip(c.iter())
                .enumerate()
                .map(|(i, ((ai, bi), ci))| {
                    (*ai * *bi - *ci) * if i % 2 == 0 { z_even } else { z_odd }
                })
                .collect();
            coset2n.ifft_in_place(&mut h);
            h.truncate(domain_size - 1);
            black_box(h);
        }
        let old_us = start.elapsed().as_micros() as f64 / iters as f64;

        // New path: product FFTs on the n coset, identical h coefficients out.
        let start = Instant::now();
        for _ in 0..iters {
            let mut a = a_evals.clone();
            let mut b = b_evals.clone();
            let mut c = c_evals.clone();
            domain.ifft_in_place(&mut a);
            domain.ifft_in_place(&mut b);
            domain.ifft_in_place(&mut c);
            let coset = domain.get_coset(BlsFr::GENERATOR).unwrap();
            coset.fft_in_place(&mut a);
            coset.fft_in_place(&mut b);
            coset.fft_in_place(&mut c);
            let g_n = BlsFr::GENERATOR.pow([domain_size as u64]);
            let z_inv = (g_n - one).inverse().unwrap();
            let mut h: Vec<BlsFr> = a
                .iter()
                .zip(b.iter())
                .zip(c.iter())
                .map(|((ai, bi), ci)| (*ai * *bi - *ci) * z_inv)
                .collect();
            coset.ifft_in_place(&mut h);
            h.truncate(domain_size - 1);
            black_box(h);
        }
        let new_us = start.elapsed().as_micros() as f64 / iters as f64;

        println!("  n=2^{log_n} ({domain_size} constraints, {iters} iterations):");
        println!("    2n coset (old) : {:>10.0} µs", old_us);
        println!(
            "    n coset  (new) : {:>10.0} µs  ← {}",
            new_us,
            speedup_str(old_us, new_us)
        );
    }
    println!();
}

// ─── Benchmark 2: h_query_scalars O(n) vs O(n log n) ────────────────────────

fn bench_h_query_scalars() {
    println!("  § 2  h_query_scalars: ITERATIVE (O(n)) vs POW LOOP (O(n log n))");
    sep();
    println!("  UniGroth: acc *= t (iterative multiplication)");
    println!("  Original: .pow([i as u64]) (exponentiation per element)");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    for log_n in [12, 14, 16, 18, 20] {
        let n = 1usize << log_n;
        let t = BlsFr::rand(&mut rng);
        let zt = BlsFr::rand(&mut rng);
        let delta_inv = BlsFr::rand(&mut rng);
        let base = zt * delta_inv;

        let iters = match log_n {
            20 => 3,
            18 => 5,
            16 => 20,
            14 => 50,
            _ => 100,
        };

        // O(n log n): .pow([i as u64]) loop (original Groth16 approach)
        let start = Instant::now();
        for _ in 0..iters {
            let mut scalars = Vec::with_capacity(n);
            for i in 0..n {
                scalars.push(base * t.pow([i as u64]));
            }
            black_box(scalars);
        }
        let pow_us = start.elapsed().as_micros() as f64 / iters as f64;

        // O(n): iterative acc *= t (UniGroth approach)
        let start = Instant::now();
        for _ in 0..iters {
            let mut scalars = Vec::with_capacity(n);
            let mut acc = base;
            for _ in 0..n {
                scalars.push(acc);
                acc *= t;
            }
            black_box(scalars);
        }
        let iter_us = start.elapsed().as_micros() as f64 / iters as f64;

        println!("  n=2^{log_n} ({n} scalars, {iters} iterations):");
        println!("    .pow([i]) loop (O(n log n)) : {:>10.0} µs", pow_us);
        println!(
            "    acc *= t       (O(n))       : {:>10.0} µs  ← {}",
            iter_us,
            speedup_str(pow_us, iter_us)
        );
    }
    println!();
}

// ─── Benchmark 3: Parallel MSM Scaling ──────────────────────────────────────

fn bench_parallel_msm() {
    println!("  § 3  PARALLEL MSM SCALING");
    sep();
    println!("  Measures MSM performance using arkworks Pippenger.");
    println!("  Set RAYON_NUM_THREADS=1 and rerun to see single-thread baseline.");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    for log_n in [10, 12, 14, 16] {
        let n = 1usize << log_n;
        let iters = match log_n {
            16 => 3,
            14 => 10,
            _ => 30,
        };

        let scalars: Vec<BlsFr> = (0..n).map(|_| BlsFr::rand(&mut rng)).collect();
        let bases: Vec<BlsG1Affine> = (0..n)
            .map(|_| BlsG1::rand(&mut rng).into_affine())
            .collect();

        let start = Instant::now();
        for _ in 0..iters {
            let result = BlsG1::msm(&bases, &scalars).unwrap();
            black_box(result);
        }
        let total_us = start.elapsed().as_micros() as f64 / iters as f64;

        let threads = rayon::current_num_threads();
        println!("  n=2^{log_n} ({n} scalars, {threads} threads, {iters} iters):");
        println!(
            "    MSM time : {:>10.0} µs  ({:.1} ns/scalar)",
            total_us,
            total_us * 1000.0 / n as f64
        );
    }
    println!();
}

// ─── Benchmark 4: End-to-End Prove+Verify ────────────────────────────────────

fn bench_end_to_end() {
    println!("  § 4  END-TO-END: UniGroth vs ark-groth16");
    sep();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    for (label, num_constraints, num_variables) in [
        ("small  (2^12)", (1 << 12) - 100, (1 << 12) - 100),
        ("medium (2^16)", (1 << 16) - 100, (1 << 16) - 100),
    ] {
        let a_val = BlsFr::rand(&mut rng);
        let b_val = BlsFr::rand(&mut rng);
        let c_val = a_val * b_val;

        let circuit = DummyCircuit::<BlsFr> {
            a: Some(a_val),
            b: Some(b_val),
            num_variables,
            num_constraints,
        };
        let setup_circuit = DummyCircuit::<BlsFr> {
            a: None,
            b: None,
            num_variables,
            num_constraints,
        };

        let iters = if num_constraints > (1 << 14) { 2 } else { 5 };

        // ark-groth16 setup + prove + verify
        let (ark_pk, ark_vk) =
            ArkGroth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

        let start = Instant::now();
        let mut ark_proof = None;
        for _ in 0..iters {
            ark_proof = Some(ArkGroth16::<Bls12_381>::prove(&ark_pk, circuit, &mut rng).unwrap());
        }
        let ark_prove_us = start.elapsed().as_micros() as f64 / iters as f64;

        let ark_pvk = ArkGroth16::<Bls12_381>::process_vk(&ark_vk).unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let ok = ArkGroth16::<Bls12_381>::verify_with_processed_vk(
                &ark_pvk,
                &[c_val],
                ark_proof.as_ref().unwrap(),
            )
            .unwrap();
            assert!(ok);
        }
        let ark_verify_us = start.elapsed().as_micros() as f64 / iters as f64;

        // UniGroth setup + prove + verify
        let (ug_pk, ug_vk) =
            ug::Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

        let start = Instant::now();
        let mut ug_proof = None;
        for _ in 0..iters {
            ug_proof = Some(ug::Groth16::<Bls12_381>::prove(&ug_pk, circuit, &mut rng).unwrap());
        }
        let ug_prove_us = start.elapsed().as_micros() as f64 / iters as f64;

        let ug_pvk = ug::Groth16::<Bls12_381>::process_vk(&ug_vk).unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let ok = ug::Groth16::<Bls12_381>::verify_with_processed_vk(
                &ug_pvk,
                &[c_val],
                ug_proof.as_ref().unwrap(),
            )
            .unwrap();
            assert!(ok);
        }
        let ug_verify_us = start.elapsed().as_micros() as f64 / iters as f64;

        println!("  Circuit: {label} ({num_constraints} constraints, {iters} iterations):");
        println!("    Prove:");
        println!("      ark-groth16 : {:>12.0} µs", ark_prove_us);
        println!(
            "      UniGroth    : {:>12.0} µs  ← {}",
            ug_prove_us,
            speedup_str(ark_prove_us, ug_prove_us)
        );
        println!("    Verify:");
        println!("      ark-groth16 : {:>12.0} µs", ark_verify_us);
        println!(
            "      UniGroth    : {:>12.0} µs  ← {}",
            ug_verify_us,
            speedup_str(ark_verify_us, ug_verify_us)
        );
        println!();
    }
}

// ─── Benchmark 5: evaluate_constraint scaling ────────────────────────────────

fn bench_evaluate_constraint() {
    println!("  § 5  evaluate_constraint SCALING");
    sep();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    for size in [100, 1000, 10000, 100000] {
        let terms: Vec<(BlsFr, usize)> = (0..10)
            .map(|_| (BlsFr::rand(&mut rng), rng.gen_range(0..size)))
            .collect();
        let assignment: Vec<BlsFr> = (0..size).map(|_| BlsFr::rand(&mut rng)).collect();

        let iters = 1000;
        let start = Instant::now();
        for _ in 0..iters {
            let result = evaluate_constraint(&terms, &assignment);
            black_box(result);
        }
        let time_ns = start.elapsed().as_nanos() as f64 / iters as f64;

        println!("  Assignment size {:>6}: {:>8.0} ns/eval", size, time_ns);
    }
    println!();
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("╔════════════════════════════════════════════════════════════════════════╗");
    println!("║        UniGroth Comprehensive Benchmark Suite                          ║");
    println!(
        "║  Threads: {}  ·  BLS12-381 + BN254                                    ║",
        rayon::current_num_threads()
    );
    println!("╚════════════════════════════════════════════════════════════════════════╝");

    bench_fft_comparison();
    bench_h_query_scalars();
    bench_parallel_msm();
    bench_end_to_end();
    bench_evaluate_constraint();

    println!("╔════════════════════════════════════════════════════════════════════════╗");
    println!("║                          BENCHMARK COMPLETE                            ║");
    println!("╚════════════════════════════════════════════════════════════════════════╝");
    println!();
}
