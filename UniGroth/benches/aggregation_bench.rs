// UniGroth Aggregation Benchmark Suite
//
// Benchmarks SnarkPack-style proof aggregation vs N individual verifications.
//
// Run:
//   cargo bench --no-default-features --features "std parallel" --bench aggregation-benches

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{rand::SeedableRng, time::Instant};
use std::hint::black_box;

use unigroth::{aggregate_proofs, verify_aggregated, Groth16, SimExtractableProof};

fn sep() {
    println!("  {}", "-".repeat(72));
}

#[derive(Copy, Clone)]
struct MiniCircuit {
    pub a: Option<Fr>,
    pub b: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MiniCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            Ok(self.a.ok_or(SynthesisError::AssignmentMissing)?
                * self.b.ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        for _ in 0..63 {
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        }
        cs.enforce_r1cs_constraint(|| lc!(), || lc!(), || lc!())?;
        Ok(())
    }
}

fn bench_aggregation_vs_individual() {
    println!("\n  S 1  AGGREGATED vs INDIVIDUAL VERIFICATION");
    sep();
    println!("  aggregate_proofs: SnarkPack-style N->1 proof aggregation");
    println!("  Individual: N separate Groth16 verify calls");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42u64);

    let a_val = Fr::rand(&mut rng);
    let b_val = Fr::rand(&mut rng);
    let c_val = a_val * b_val;

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        MiniCircuit {
            a: Some(a_val),
            b: Some(b_val),
        },
        &mut rng,
    )
    .unwrap();
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();

    for n_proofs in [2usize, 4, 8, 16] {
        let iters = match n_proofs {
            16 => 5,
            8 => 10,
            _ => 20,
        };

        // Generate N SE proofs via the standard prove path
        let se_proofs: Vec<SimExtractableProof<Bls12_381>> = (0..n_proofs)
            .map(|_| {
                Groth16::<Bls12_381>::prove(
                    &pk,
                    MiniCircuit {
                        a: Some(a_val),
                        b: Some(b_val),
                    },
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let public_inputs: Vec<Vec<Fr>> = (0..n_proofs).map(|_| vec![c_val]).collect();

        // Individual verification: N separate verify_proof calls
        let start = Instant::now();
        for _ in 0..iters {
            for (proof, inputs) in se_proofs.iter().zip(public_inputs.iter()) {
                let ok =
                    Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, inputs, proof).unwrap();
                assert!(ok);
                black_box(ok);
            }
        }
        let individual_us = start.elapsed().as_micros() as f64 / iters as f64;

        // Extract inner Proof<E> for aggregation
        let inner_proofs: Vec<_> = se_proofs
            .iter()
            .map(|se| se.groth16_proof.clone())
            .collect();

        // Aggregated: aggregate + verify_aggregated
        let start = Instant::now();
        let mut agg = None;
        for _ in 0..iters {
            agg = Some(aggregate_proofs(&inner_proofs, &public_inputs, &mut rng));
        }
        let aggregate_us = start.elapsed().as_micros() as f64 / iters as f64;

        let agg_proof = agg.unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let ok = verify_aggregated(&vk, &agg_proof);
            assert!(ok, "aggregated proof must verify");
            black_box(ok);
        }
        let agg_verify_us = start.elapsed().as_micros() as f64 / iters as f64;

        let verify_speedup = individual_us / agg_verify_us;
        let total_is_faster = (aggregate_us + agg_verify_us) < individual_us;
        let overhead_ratio = if total_is_faster {
            individual_us / (aggregate_us + agg_verify_us)
        } else {
            (aggregate_us + agg_verify_us) / individual_us
        };

        println!("  N={n_proofs} proofs, {iters} iterations:");
        println!(
            "    Individual verify ({n_proofs} calls): {:>10.0} us",
            individual_us
        );
        println!(
            "    Aggregate prove               : {:>10.0} us",
            aggregate_us
        );
        println!(
            "    Aggregated verify (1 call)    : {:>10.0} us  <- {:.2}x vs individual",
            agg_verify_us, verify_speedup
        );
        println!(
            "    Total agg+verify vs individual: {:.2}x {}",
            overhead_ratio,
            if total_is_faster {
                "faster"
            } else {
                "slower (aggregation overhead; amortizes at larger N)"
            }
        );
        println!();
    }
}

fn bench_aggregation_throughput() {
    println!("  S 2  AGGREGATION THROUGHPUT (proofs/second)");
    sep();
    println!("  How many proofs can be verified per second in aggregated mode?");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7777u64);

    let a_val = Fr::rand(&mut rng);
    let b_val = Fr::rand(&mut rng);
    let c_val = a_val * b_val;

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        MiniCircuit {
            a: Some(a_val),
            b: Some(b_val),
        },
        &mut rng,
    )
    .unwrap();

    for n_proofs in [4usize, 8, 16] {
        let se_proofs: Vec<SimExtractableProof<Bls12_381>> = (0..n_proofs)
            .map(|_| {
                Groth16::<Bls12_381>::prove(
                    &pk,
                    MiniCircuit {
                        a: Some(a_val),
                        b: Some(b_val),
                    },
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let inner_proofs: Vec<_> = se_proofs
            .iter()
            .map(|se| se.groth16_proof.clone())
            .collect();
        let public_inputs: Vec<Vec<Fr>> = (0..n_proofs).map(|_| vec![c_val]).collect();
        let iters = 10;

        let start = Instant::now();
        for _ in 0..iters {
            let agg = aggregate_proofs(&inner_proofs, &public_inputs, &mut rng);
            let ok = verify_aggregated(&vk, &agg);
            assert!(ok);
            black_box(ok);
        }
        let total_us = start.elapsed().as_micros() as f64 / iters as f64;
        let throughput = n_proofs as f64 / (total_us / 1_000_000.0);

        println!(
            "  N={n_proofs}: {:.0} us/batch  |  {:.0} proofs/sec (aggregated)",
            total_us, throughput
        );
    }
    println!();
}

fn main() {
    println!();
    println!("+=======================================================================+");
    println!("|        UniGroth Aggregation Benchmark Suite                           |");
    println!("|  SnarkPack N->1 Aggregation vs Individual Verification                |");
    println!("+=======================================================================+");

    bench_aggregation_vs_individual();
    bench_aggregation_throughput();

    println!("+=======================================================================+");
    println!("|                          BENCHMARK COMPLETE                            |");
    println!("+=======================================================================+");
    println!();
}
