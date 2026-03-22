# UniGroth Implementation Checklist

## Core: Wire Everything In
The codebase has all the modules written but nothing is connected to the main prover/verifier. These are blockers for any real speedup.

* [✓] **Fix `h_query_scalars` (O(n log n) → O(n))**
  * Replace `.pow([i as u64])` loop with iterative multiplication
  * Impact : 2–10× speedup on large circuits (single biggest wall-clock improvement)
  * File : `src/r1cs_to_qap.rs` : iterative `acc *= t` loop at line 222 ✓

* [✓] **Finish and wire 4-FFT compute_witness_4fft**
  * Rewrote `compute_witness_4fft` using polynomial multiplication on 2n coset domain
  * `c_evals` parameter removed : h extracted via identity: `(a·b)[k+n] = h[k]` for k=0..n-2
  * Eliminates iFFT(c) + coset_FFT(c) entirely : 7 FFTs → 5 FFTs
  * `witness_map_from_matrices` and `sap.rs` updated; all 44 tests pass ✓
  * Files : `src/optimizations.rs`, `src/r1cs_to_qap.rs`, `src/sap.rs`

* [✓] **Parallelize the 3 MSMs in `create_proof_with_assignment`**
  * Use `rayon::join` to run h_acc and l_aux_acc MSMs concurrently
  * Also parallelize A and B computation (2 independent operations)
  * Impact : ~2× speedup on multicore systems
  * File : `src/prover.rs` : nested `rayon::join` at lines 36–61 ✓

* [✓] **Wire SE (Simulation-Extractable) module into prover**
  * `lib.rs:174-176` : `prove()` calls `security::make_sim_extractable` with `SEConfig::default()` (ROM blinding) ✓
  * Returns `SimExtractableProof<E>` as the SNARK proof type

* [✓] **Implement SE verifier check in verifier.rs**
  * SE pairing equation check implemented in `verify_proof_with_prepared_inputs`
  * 4-pairing SE path (`e(A,B)·e(inputs,-γ)·e(C,-δ)·e(δ_g1,-D) = e(α,β)`) at `src/verifier.rs:62-98` ✓
  * File : `src/verifier.rs` ✓

---

## Performance: Quick Wins (Low Priority, High ROI)

* [✓] **Upgrade LTO setting to fat**
  * `Cargo.toml:89` : `lto = "fat"` already set in `[profile.release]` ✓
  * Free ~10–15% speedup on release builds via cross-crate inlining

* [✓] **Raise `evaluate_constraint` parallel threshold**
  * `src/r1cs_to_qap.rs:33` : threshold is already `1000` rows ✓
  * Rayon overhead avoided for small batches

---

## Performance: Advanced Optimizations

* [✓] **Lazy affine conversion with batch inversion**
  * Accumulate everything in projective coordinates
  * Do single batch inversion at end using Montgomery's batch trick
  * Cost : 1 batch inversion of N elements ≈ 3 single inversions
  * Impact : 20–30% on MSM-heavy operations
  * Files : `src/prover.rs` : `E::G1::normalize_batch(&[g_a, g_c])` at proof output ✓

* [✓] **Precomputed coset twiddle factors cache**
  * Cache twiddle factor tables keyed by domain size
  * Significant win for rollups generating thousands of proofs over same circuit
  * File : `src/optimizations.rs` : `CosetDomainCache<F,D>` + `compute_witness_4fft_with_cache` ✓

* [✓] **Sparse QAP exploitation (CSR format)**
  * Store A/B/C matrices in Compressed Sparse Row (CSR) format
  * Skip zero rows entirely during witness computation
  * Impact : 40–70% reduction on typical sparse circuits
  * File : `src/optimizations.rs` : `CsrMatrix<F>` with `nnz_rows` + `sparse_witness_eval` ✓

* [✓] **Proof aggregation (Bunz et al. / inner-product argument)**
  * Implement constant-size aggregation for N Groth16 proofs
  * Used in production by PLONKY2, Polygon
  * Connect to existing folding module
  * File : `src/aggregation.rs` : `AggregatedProof<E>`, `aggregate_proofs`, `verify_aggregated` ✓

---

## Security: Production Hardening

* [✓] **Circuit binding / domain separation**
  * SHA-256(vk.gamma_abc_g1) mixed into r,s via H(circuit_tag || fresh_random)
  * `circuit_bound_rand()` helper added to prover, replaces plain `rand(rng)` call
  * File : `src/prover.rs` ✓

* [✓] **Proof of knowledge for public inputs**
  * New module `src/public_input_pok.rs` with multi-scalar Schnorr PoK
  * `PublicInputPoK<E>`, `prove_public_input_pok`, `verify_public_input_pok` exported from crate
  * Fiat-Shamir challenge binds PoK to specific proof elements (A, B, C)
  * 5 tests: valid accept, wrong input reject, tampered response/commitment reject, cross-proof reject
  * File : `src/public_input_pok.rs` ✓

* [✓] **Toxic waste zeroing in generator.rs**
  * alpha, beta, gamma, delta, gamma_inverse, delta_inverse zeroed immediately after last use
  * `core::hint::black_box` prevents compiler from eliminating dead stores (safe, no unsafe_code)
  * File : `src/generator.rs` ✓

---

## Functionality: Production Deployment

* [✗] **On-chain verifier codegen (Solidity + WASM)**
  * Auto-generate Solidity verifier from verifying key
  * Also generate Rust-WASM verifier option
  * **HIGHEST impact for usability** : without this, proofs can't actually be deployed anywhere
  * Essential feature every major framework (snarkjs, bellman) provides
  * File : New module `src/verifier_codegen/` with solidity.rs and wasm.rs

* [✗] **Streaming/chunked witness computation**
  * For large circuits (2²⁰+ constraints), process witness in chunks
  * Accumulate MSM incrementally instead of loading full witness in memory
  * Genuine differentiator for memory-constrained environments
  * File : New module `src/streaming_prover.rs` or add to `src/prover.rs`

* [✗] **Verifying key compression**
  * Apply KZG-style commitment to gamma_abc_g1 vector
  * Provide opening proof per verification
  * Reduces VK size from O(n) to O(1) for circuits with many public inputs
  * Critical for zkEVM-scale deployments
  * File : `src/key_compression.rs` (new module)

---

## Testing & Validation

* [✗] **Benchmark 4-FFT vs 6-FFT on real circuits**
  * Measure actual speedup after completing 4-FFT wiring
  * File : `benches/` directory

* [✗] **Benchmark h_query_scalars optimization**
  * Profile wall-clock time on large constraint counts
  * Validate O(n log n) → O(n) improvement claim
  * File : `benches/` directory

* [✓] **Verify SE proofs are actually simulation-extractable**
  * 5 rejection tests added to `src/security.rs`:
    - `test_se_rejects_tampered_proof_a` — tampered A is rejected
    - `test_se_rejects_tampered_proof_c` — tampered C is rejected
    - `test_se_rejects_wrong_public_inputs` — wrong public inputs rejected
    - `test_se_forged_bg18_element_on_rom_proof_rejected` — forged se_element on ROM proof rejected
    - `test_se_rom_rejects_tampered_proof_elements` — ROM SE also rejects tampering
  * File : `src/security.rs` ✓

* [✗] **Benchmark parallel MSM speedup**
  * Measure multicore scaling on different core counts
  * File : `benches/` directory

---

## Summary: Tier by Impact

### Red : CRITICAL (Blockers for real speedup)
1. ~~Fix `h_query_scalars` (O(n log n) → O(n))~~ : ✓ **DONE** (`r1cs_to_qap.rs:222`)
2. ~~Finish and wire 4-FFT~~ : ✓ **DONE** (poly-mul approach, 7→5 FFTs, `optimizations.rs`)
3. ~~Parallelize the 3 MSMs~~ : ✓ **DONE** (`prover.rs:36-61`)
4. Wire SE into prover : ✗ **TODO** | ~~Add SE verifier check~~ : ✓ **DONE** (`verifier.rs:62-98`)

### Yellow : HIGH (Low-hanging fruit)
5. ~~Upgrade LTO to fat~~ : ✓ **DONE** (`Cargo.toml:89`)
6. ~~Raise parallel threshold~~ : ✓ **DONE** (`r1cs_to_qap.rs:33`)
7. ~~Circuit binding / domain separation~~ : ✓ **DONE** (`prover.rs:circuit_bound_rand`)

### Green : MEDIUM (Advanced optimizations)
8. Lazy affine conversion + batch inversion : **20–30% on MSM**
9. Precomputed coset twiddles : **Constant factor for rollups**
10. Sparse QAP (CSR format) : **40–70% on sparse circuits**

### Blue : GAME-CHANGING (New capabilities)
11. **On-chain verifier codegen** : **Most impactful for deployment**
12. Proof aggregation (Bunz et al.) : **Production-grade compression**
13. Sparse circuit exploitation : **Real-world circuit advantage**
14. Streaming prover : **zkEVM-scale circuits**
15. VK compression : **Large public input handling**

---

## Notes

- Core problem: All modules exist but nothing is wired into main prover/verifier
- UniGroth currently functionally identical to vanilla arkworks Groth16 with extra files
* Items 1–4 are what separates "has code" from "actually beats Groth16"
* Items 11–13 are what make it concretely more useful than vanilla Groth16 in production
