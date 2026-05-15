// UniGroth Recursive Proof Benchmarks
//
// Measures the cost of building and describing a recursive verifier circuit
// at various recursion depths. Tracks constraint counts and theoretical
// prover time estimates.
//
// Run:
//   cargo bench --no-default-features --features "std parallel" --bench recursion-benches

use ark_std::time::Instant;
use std::hint::black_box;
use unigroth::gadgets::{GadgetInfo, RecursiveVerifierGadget};

fn sep() {
    println!("  {}", "-".repeat(72));
}

fn bench_recursive_verifier_depth() {
    println!("\n  S 1  RECURSIVE VERIFIER — CONSTRAINT COUNT vs DEPTH");
    sep();
    println!("  Nested Groth16 proof: each level verifies the previous one.");
    println!("  Constraint count grows linearly with recursion depth.");
    println!();

    // Each recursion level is one RecursiveVerifierGadget invocation.
    // We model depths 1..=16.
    for depth in [1, 2, 4, 8, 16] {
        let gadget = RecursiveVerifierGadget::standard();
        let total_constraints = gadget.constraint_count() * depth;
        // Rough prover estimate: 1ms per 1000 constraints (single-threaded)
        let estimated_prove_ms = total_constraints as f64 / 1000.0;
        println!(
            "  depth={:<3} | constraints={:<10} | est_prove={:.1}ms",
            depth, total_constraints, estimated_prove_ms
        );
    }
}

fn bench_public_input_scaling() {
    println!("\n  S 2  RECURSIVE VERIFIER — COST vs PUBLIC INPUT COUNT");
    sep();
    println!("  Inner proof public input count affects prepare_inputs cost.");
    println!();

    for num_inputs in [1, 4, 8, 16, 32] {
        let t = Instant::now();
        let gadget = black_box(RecursiveVerifierGadget::new(num_inputs));
        let constraints = black_box(gadget.constraint_count());
        let elapsed_us = t.elapsed().as_micros();
        println!(
            "  public_inputs={:<3} | constraints={:<10} | query_time={}μs",
            num_inputs, constraints, elapsed_us
        );
    }
}

fn bench_folding_depth_estimate() {
    println!("\n  S 3  FOLDING / IVC — ACCUMULATION COST ESTIMATE");
    sep();
    println!("  IVC: each fold step adds one RecursiveVerifier + Poseidon transcript.");
    println!();

    use unigroth::gadgets::PoseidonHashGadget;
    let verifier = RecursiveVerifierGadget::standard();
    let poseidon = PoseidonHashGadget::new();
    let per_step = verifier.constraint_count() + poseidon.constraint_count();

    for steps in [1, 10, 100, 1000] {
        let total = per_step * steps;
        let est_prove_s = total as f64 / 1_000_000.0; // 1M constraints/s estimate
        println!(
            "  steps={:<5} | total_constraints={:<12} | est_prove={:.3}s",
            steps, total, est_prove_s
        );
    }
    println!();
    println!("  Note: parallel proving (rayon) reduces wall time proportionally.");
}

fn main() {
    println!("\n============================================================");
    println!("  UniGroth Recursive Proof Benchmarks");
    println!("============================================================");
    bench_recursive_verifier_depth();
    bench_public_input_scaling();
    bench_folding_depth_estimate();
    println!("\n============================================================");
    println!("  Done.");
    println!("============================================================\n");
}
