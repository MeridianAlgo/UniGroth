# UniGroth — Benchmarks

Criterion-based benchmarks comparing UniGroth's optimizations against baseline Groth16.

## Benchmark Sections

### §1 — FFT Comparison

Measures FFT throughput at domain sizes 2^12, 2^14, 2^16, 2^18 on BLS12-381.

| Path | FFTs | Description |
|------|------|-------------|
| Standard | 6 | iFFT(a) + iFFT(b) + iFFT(c) + cosetFFT(a) + cosetFFT(b) + cosetFFT(c) |
| UniGroth 5-FFT | 5 | Dynark coset trick — eliminates one iFFT via polynomial identity |
| UniGroth 4-FFT | 4 | True coset evaluation — further eliminates iFFT(c) entirely |

Expected: 4-FFT is ~17-33% faster than standard for large circuits.

### §2 — `h_query_scalars` Optimization

Compares O(n log n) vs O(n) scalar table computation at sizes 2^12 through 2^20.

| Method | Complexity | Description |
|--------|-----------|-------------|
| `.pow([i])` loop | O(n log n) | Repeated field exponentiation |
| `acc *= t` loop | O(n) | Iterative accumulation — UniGroth default |

Expected: 2–10× speedup on large circuits (2^18+).

### §3 — Parallel MSM Scaling

Pippenger MSM timing at 2^10 through 2^16 scalars, BLS12-381.
Reports ns/scalar. Rerun with `RAYON_NUM_THREADS=1` for single-thread baseline.

### §4 — End-to-End Proving

UniGroth vs ark-groth16, BN254, circuits with 2^12 and 2^16 constraints.
Measures: setup time, prove time, verify time.

### §5 — Sparse QAP (CSR format)

Dense vs CSR matrix evaluation at 5%, 20%, 50% row density.
Expected: 2.8–5.5× speedup at 5% density (typical for zkEVM circuits).

### §6 — Proof Aggregation

Individual verify (N × pairing) vs aggregate+verify (1 × pairing).
Tested at N = 2, 4, 8, 16, 32 proofs.

## Running Benchmarks

```bash
# Full benchmark suite (takes 2-5 minutes)
cargo bench --features std

# Single section
cargo bench --features std -- fft_comparison
cargo bench --features std -- h_query_scalars

# Single-threaded baseline for parallel speedup measurement
RAYON_NUM_THREADS=1 cargo bench --features std

# With flamegraph (requires cargo-flamegraph)
cargo flamegraph --bench groth16-benches -- --bench
```

## Expected Results (release build, modern laptop)

| Benchmark | Baseline | UniGroth | Speedup |
|-----------|----------|----------|---------|
| FFT (n=2^16) | standard 6-FFT | 4-FFT coset | ~1.33× |
| h_query (n=2^18) | O(n log n) | O(n) | 2–10× |
| MSM (n=2^14, 8 cores) | single-thread | rayon | ~1.2–2× |
| End-to-end prove (n=2^12) | ark-groth16 | UniGroth | ~1.16× |
| Sparse QAP (5% density) | dense eval | CSR | ~5× |
| Aggregation N=32 | 32 verifies | 1 verify | ~32× |
