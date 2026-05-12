// UniGroth Lookup Argument Benchmark Suite
//
// Benchmarks Plookup (grand-product) and LogUp (log-derivative) lookup arguments.
// Compares against naive O(n log n) sort-based membership checks.
//
// Run:
//   cargo bench --no-default-features --features "std parallel" --bench lookup-benches

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::{rand::SeedableRng, time::Instant};
use std::hint::black_box;

use unigroth::{
    lookup::LookupTable, prove_logup, prove_multi_table_logup, prove_plookup, range_table,
    verify_logup, verify_multi_table_logup, verify_plookup, MultiTableLookup,
};

fn sep() {
    println!("  {}", "-".repeat(72));
}

fn speedup_str(baseline_us: f64, optimized_us: f64) -> String {
    let ratio = baseline_us / optimized_us;
    if ratio >= 1.0 {
        format!("{:.2}x faster", ratio)
    } else {
        format!("{:.2}x slower", 1.0 / ratio)
    }
}

fn naive_membership_check(table: &[Fr], queries: &[Fr]) -> bool {
    let mut sorted_table = table.to_vec();
    sorted_table.sort_by(|a, b| a.0.cmp(&b.0));
    for q in queries {
        if sorted_table.binary_search_by(|x| x.0.cmp(&q.0)).is_err() {
            return false;
        }
    }
    true
}

fn bench_plookup_vs_logup() {
    println!("\n  S 1  PLOOKUP vs LOGUP vs NAIVE MEMBERSHIP");
    sep();
    println!("  Plookup: grand-product argument, O(n log n) prover (sort + product)");
    println!("  LogUp:   log-derivative argument, O(n) prover (multiplicity sums)");
    println!("  Naive:   sort + binary search, no ZK, O(n log n)");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(1337u64);

    for log_table in [6u32, 8, 10, 12] {
        let table_size = 1usize << log_table;
        let query_count = table_size / 4;
        let t: LookupTable<Fr> = range_table(table_size as u64 - 1);
        let iters = match log_table {
            12 => 10,
            10 => 50,
            _ => 100,
        };

        let queries: Vec<Fr> = (0..query_count)
            .map(|i| Fr::from((i % table_size) as u64))
            .collect();

        let beta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);

        // Plookup prove
        let start = Instant::now();
        let mut plookup_proof = None;
        for _ in 0..iters {
            plookup_proof = Some(prove_plookup(&t, &queries, beta, gamma).expect("prove"));
        }
        let plookup_prove_us = start.elapsed().as_micros() as f64 / iters as f64;

        let proof = plookup_proof.unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let ok = verify_plookup(&t, &queries, &proof, beta, gamma);
            assert!(ok);
            black_box(ok);
        }
        let plookup_verify_us = start.elapsed().as_micros() as f64 / iters as f64;

        // LogUp prove
        let start = Instant::now();
        let mut logup_witness = None;
        for _ in 0..iters {
            logup_witness = Some(prove_logup(&t, &queries).expect("prove"));
        }
        let logup_prove_us = start.elapsed().as_micros() as f64 / iters as f64;

        let witness = logup_witness.unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let ok = verify_logup(&t, &queries, &witness, gamma);
            assert!(ok);
            black_box(ok);
        }
        let logup_verify_us = start.elapsed().as_micros() as f64 / iters as f64;

        // Naive check (no ZK)
        let start = Instant::now();
        for _ in 0..iters {
            let ok = naive_membership_check(&t.entries, &queries);
            black_box(ok);
        }
        let naive_us = start.elapsed().as_micros() as f64 / iters as f64;

        println!("  Table=2^{log_table} ({table_size}), Queries={query_count}, {iters} iters:");
        println!("    Plookup  prove  : {:>8.1} us", plookup_prove_us);
        println!("    Plookup  verify : {:>8.1} us", plookup_verify_us);
        println!(
            "    LogUp    prove  : {:>8.1} us  <- {} vs Plookup",
            logup_prove_us,
            speedup_str(plookup_prove_us, logup_prove_us)
        );
        println!(
            "    LogUp    verify : {:>8.1} us  <- {} vs Plookup",
            logup_verify_us,
            speedup_str(plookup_verify_us, logup_verify_us)
        );
        println!("    Naive (no ZK)   : {:>8.1} us", naive_us);
        println!();
    }
}

fn bench_multi_table_logup() {
    println!("  S 2  MULTI-TABLE LOGUP SCALING");
    sep();
    println!("  LogUp with multiple independent lookup tables.");
    println!();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(9999u64);

    for num_tables in [2usize, 4, 8] {
        let table_size = 256usize;
        let queries_per_table = 64usize;
        let iters = 50;

        let tables: Vec<LookupTable<Fr>> = (0..num_tables)
            .map(|_| range_table(table_size as u64 - 1))
            .collect();

        let multi = MultiTableLookup::new(tables);

        let queries: Vec<(usize, Fr)> = (0..num_tables * queries_per_table)
            .map(|i| {
                let tbl_idx = i % num_tables;
                let val = Fr::from((i % table_size) as u64);
                (tbl_idx, val)
            })
            .collect();

        let gamma = Fr::rand(&mut rng);

        let start = Instant::now();
        let mut witnesses = None;
        for _ in 0..iters {
            witnesses = Some(prove_multi_table_logup(&multi, &queries).expect("prove"));
        }
        let prove_us = start.elapsed().as_micros() as f64 / iters as f64;

        let w = witnesses.unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let ok = verify_multi_table_logup(&multi, &queries, &w, gamma);
            assert!(ok);
            black_box(ok);
        }
        let verify_us = start.elapsed().as_micros() as f64 / iters as f64;

        let total_queries = num_tables * queries_per_table;
        println!(
            "  {num_tables} tables x {table_size} entries, {total_queries} queries, {iters} iters:"
        );
        println!("    prove  : {:>8.1} us", prove_us);
        println!("    verify : {:>8.1} us", verify_us);
        println!(
            "    throughput: {:.0} queries/ms",
            total_queries as f64 / ((prove_us + verify_us) / 1000.0)
        );
        println!();
    }
}

fn main() {
    println!();
    println!("+=======================================================================+");
    println!("|        UniGroth Lookup Argument Benchmark Suite                       |");
    println!("|  Plookup (grand-product) vs LogUp (log-derivative) vs Naive           |");
    println!("+=======================================================================+");

    bench_plookup_vs_logup();
    bench_multi_table_logup();

    println!("+=======================================================================+");
    println!("|                          BENCHMARK COMPLETE                            |");
    println!("+=======================================================================+");
    println!();
}
