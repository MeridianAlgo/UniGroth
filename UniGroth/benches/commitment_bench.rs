// UniGroth Commitment Scheme Benchmark Suite
//
// Benchmarks FRI and IPA polynomial commitment schemes versus each other.
// Measures commit, prove, and verify times across polynomial degrees.
//
// Run:
//   cargo bench --no-default-features --features "std parallel" --bench commitment-benches

use ark_bn254::{Fr, G1Projective as G};
use ark_ff::UniformRand;
use ark_std::{rand::SeedableRng, time::Instant};
use std::hint::black_box;

use unigroth::commitment::{
    fri_commit, fri_prove, fri_verify, ipa_commit, ipa_prove, ipa_verify, FriConfig, IpaConfig,
};

fn sep() {
    println!("  {}", "-".repeat(72));
}

fn bench_fri() {
    println!("\n  S 1  FRI COMMITMENT — COMMIT / PROVE / VERIFY");
    sep();
    println!("  FRI: transparent, hash-based, O(log^2 n) proof size");
    println!();

    let sizes = [16usize, 64, 256, 1024];
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

    for &n in &sizes {
        let cfg = FriConfig::new(128, 4);
        let evals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Commit
        let t_commit = Instant::now();
        let comm = black_box(fri_commit(&evals, &cfg));
        let commit_us = t_commit.elapsed().as_micros();

        // Prove
        let t_prove = Instant::now();
        let proof = black_box(fri_prove(&evals, &cfg, &mut rng));
        let prove_us = t_prove.elapsed().as_micros();

        // Verify
        let t_verify = Instant::now();
        let ok = black_box(fri_verify(&comm, &proof, &cfg));
        let verify_us = t_verify.elapsed().as_micros();

        let est_bytes = cfg.proof_size_estimate(n);
        println!(
            "  n={:<5} | commit={:>6}μs | prove={:>6}μs | verify={:>5}μs | proof_est={:>6}B | ok={}",
            n, commit_us, prove_us, verify_us, est_bytes, ok
        );
    }
}

fn bench_ipa() {
    println!("\n  S 2  IPA COMMITMENT — COMMIT / PROVE / VERIFY");
    sep();
    println!("  IPA: transparent, discrete-log-based, O(log n) proof size");
    println!();

    let sizes = [4usize, 8, 16, 32];
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(99);

    for &n in &sizes {
        if !n.is_power_of_two() {
            continue;
        }
        let cfg = IpaConfig::<G>::setup(n, &mut rng);
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let blinding = Fr::rand(&mut rng);

        // Commit
        let t_commit = Instant::now();
        let comm = black_box(ipa_commit::<G>(&coeffs, blinding, &cfg));
        let commit_us = t_commit.elapsed().as_micros();

        // Derive eval
        let z = Fr::rand(&mut rng);
        let eval = coeffs
            .iter()
            .enumerate()
            .map(|(i, c)| *c * z.pow([i as u64]))
            .sum::<Fr>();

        // Prove
        let t_prove = Instant::now();
        let proof = black_box(ipa_prove::<G>(&coeffs, z, blinding, &cfg, &mut rng));
        let prove_us = t_prove.elapsed().as_micros();

        // Verify
        let t_verify = Instant::now();
        let ok = black_box(ipa_verify::<G>(&comm, &proof, z, eval, &cfg));
        let verify_us = t_verify.elapsed().as_micros();

        let est_bytes = cfg.proof_size_bytes();
        println!(
            "  n={:<5} | commit={:>6}μs | prove={:>6}μs | verify={:>5}μs | proof_est={:>6}B | ok={}",
            n, commit_us, prove_us, verify_us, est_bytes, ok
        );
    }
}

fn bench_scheme_comparison() {
    println!("\n  S 3  PROOF SIZE COMPARISON AT DEGREE 256");
    sep();
    use unigroth::transparent::TransparentProofSize;
    let sizes = TransparentProofSize::compare_schemes(256, 128);
    println!("  KZG:                                    48 B (single G1 point)");
    for (name, bytes) in &sizes {
        println!("  {:<40} {:>6} B", name, bytes);
    }
}

fn main() {
    println!("\n============================================================");
    println!("  UniGroth Commitment Scheme Benchmarks");
    println!("============================================================");
    bench_fri();
    bench_ipa();
    bench_scheme_comparison();
    println!("\n============================================================");
    println!("  Done.");
    println!("============================================================\n");
}
