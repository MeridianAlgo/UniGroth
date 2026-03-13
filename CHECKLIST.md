# UniGroth Implementation Checklist

## Core: Wire Everything In
The codebase has all the modules written but nothing is connected to the main prover/verifier. These are blockers for any real speedup.

- [x] **Fix `h_query_scalars` (O(n log n) → O(n))**
  - Replace `.pow([i as u64])` loop with iterative multiplication
  - Impact: 2–10× speedup on large circuits (single biggest wall-clock improvement)
  - File: `src/r1cs_to_qap.rs` — iterative `acc *= t` loop at line 222 ✓

- [x] **Finish and wire 4-FFT compute_witness_4fft**
  - Rewrote `compute_witness_4fft` using polynomial multiplication on 2n coset domain
  - `c_evals` parameter removed — h extracted via identity: `(a·b)[k+n] = h[k]` for k=0..n-2
  - Eliminates iFFT(c) + coset_FFT(c) entirely: 7 FFTs → 5 FFTs
  - `witness_map_from_matrices` and `sap.rs` updated; all 44 tests pass ✓
  - Files: `src/optimizations.rs`, `src/r1cs_to_qap.rs`, `src/sap.rs`

- [x] **Parallelize the 3 MSMs in `create_proof_with_assignment`**
  - Use `rayon::join` to run h_acc and l_aux_acc MSMs concurrently
  - Also parallelize A and B computation (2 independent operations)
  - Impact: ~2× speedup on multicore systems
  - File: `src/prover.rs` — nested `rayon::join` at lines 36–61 ✓

- [x] **Wire SE (Simulation-Extractable) module into prover**
  - `lib.rs:174-176` — `prove()` calls `security::make_sim_extractable` with `SEConfig::default()` (ROM blinding) ✓
  - Returns `SimExtractableProof<E>` as the SNARK proof type

- [x] **Implement SE verifier check in verifier.rs**
  - SE pairing equation check implemented in `verify_proof_with_prepared_inputs`
  - 4-pairing SE path (`e(A,B)·e(inputs,-γ)·e(C,-δ)·e(δ_g1,-D) = e(α,β)`) at `src/verifier.rs:62-98` ✓
  - File: `src/verifier.rs` ✓

---

## Performance: Quick Wins (Low Priority, High ROI)

- [x] **Upgrade LTO setting to fat**
  - `Cargo.toml:89` — `lto = "fat"` already set in `[profile.release]` ✓
  - Free ~10–15% speedup on release builds via cross-crate inlining

- [x] **Raise `evaluate_constraint` parallel threshold**
  - `src/r1cs_to_qap.rs:33` — threshold is already `1000` rows ✓
  - Rayon overhead avoided for small batches

---

## Performance: Advanced Optimizations

- [ ] **Lazy affine conversion with batch inversion**
  - Accumulate everything in projective coordinates
  - Do single batch inversion at end using Montgomery's batch trick
  - Cost: 1 batch inversion of N elements ≈ 3 single inversions
  - Impact: 20–30% on MSM-heavy operations
  - Files: `src/prover.rs` (MSM accumulation sites)

- [ ] **Precomputed coset twiddle factors cache**
  - Cache twiddle factor tables keyed by domain size
  - Significant win for rollups generating thousands of proofs over same circuit
  - File: `src/optimizations.rs` (FFT domain setup)

- [ ] **Sparse QAP exploitation (CSR format)**
  - Store A/B/C matrices in Compressed Sparse Row (CSR) format
  - Skip zero rows entirely during witness computation
  - Impact: 40–70% reduction on typical sparse circuits
  - File: `src/prover.rs` (witness_map_from_matrices), matrix data structures

- [ ] **Proof aggregation (Bunz et al. / inner-product argument)**
  - Implement constant-size aggregation for N Groth16 proofs
  - Used in production by PLONKY2, Polygon
  - Connect to existing folding module
  - File: New module `src/aggregation.rs` or extend `src/folding.rs`

---

## Security: Production Hardening

- [ ] **Circuit binding / domain separation**
  - Hash verifying key's gamma_abc vector into proving randomness
  - Prevents proof replay across different circuits with colliding VKs
  - Security: One-line change, genuine security argument
  - File: `src/prover.rs` (proof generation randomness)

- [ ] **Proof of knowledge for public inputs**
  - Add Schnorr-style commitment to public inputs as part of proof
  - Prevents adversarial public input choice after proof generation
  - File: `src/prover.rs`, `src/verifier.rs`

- [ ] **Toxic waste zeroing in generator.rs**
  - Explicitly zero alpha/beta/gamma/delta scalars after use
  - Prevent sensitive values sitting in stack memory
  - Standard HSM/MPC practice
  - File: `src/generator.rs`

---

## Functionality: Production Deployment

- [ ] **On-chain verifier codegen (Solidity + WASM)**
  - Auto-generate Solidity verifier from verifying key
  - Also generate Rust-WASM verifier option
  - **HIGHEST impact for usability** — without this, proofs can't actually be deployed anywhere
  - Essential feature every major framework (snarkjs, gnark, bellman) provides
  - File: New module `src/verifier_codegen/` with solidity.rs and wasm.rs

- [ ] **Streaming/chunked witness computation**
  - For large circuits (2²⁰+ constraints), process witness in chunks
  - Accumulate MSM incrementally instead of loading full witness in memory
  - Genuine differentiator for memory-constrained environments
  - File: New module `src/streaming_prover.rs` or add to `src/prover.rs`

- [ ] **Verifying key compression**
  - Apply KZG-style commitment to gamma_abc_g1 vector
  - Provide opening proof per verification
  - Reduces VK size from O(n) to O(1) for circuits with many public inputs
  - Critical for zkEVM-scale deployments
  - File: `src/key_compression.rs` (new module)

---

## Testing & Validation

- [ ] **Benchmark 4-FFT vs 6-FFT on real circuits**
  - Measure actual speedup after completing 4-FFT wiring
  - File: `benches/` directory

- [ ] **Benchmark h_query_scalars optimization**
  - Profile wall-clock time on large constraint counts
  - Validate O(n log n) → O(n) improvement claim
  - File: `benches/` directory

- [ ] **Verify SE proofs are actually simulation-extractable**
  - Test verifier correctly rejects tampered SE proofs
  - Validate security reduction holds
  - File: Test suite in `tests/`

- [ ] **Benchmark parallel MSM speedup**
  - Measure multicore scaling on different core counts
  - File: `benches/` directory

---

## Summary: Tier by Impact

### 🔴 CRITICAL (Blockers for real speedup)
1. ~~Fix `h_query_scalars` (O(n log n) → O(n))~~ — ✅ **DONE** (`r1cs_to_qap.rs:222`)
2. ~~Finish and wire 4-FFT~~ — ✅ **DONE** (poly-mul approach, 7→5 FFTs, `optimizations.rs`)
3. ~~Parallelize the 3 MSMs~~ — ✅ **DONE** (`prover.rs:36-61`)
4. Wire SE into prover — ⬜ **TODO** | ~~Add SE verifier check~~ — ✅ **DONE** (`verifier.rs:62-98`)

### 🟡 HIGH (Low-hanging fruit)
5. ~~Upgrade LTO to fat~~ — ✅ **DONE** (`Cargo.toml:89`)
6. ~~Raise parallel threshold~~ — ✅ **DONE** (`r1cs_to_qap.rs:33`)
7. Circuit binding / domain separation — **One-line security fix**

### 🟢 MEDIUM (Advanced optimizations)
8. Lazy affine conversion + batch inversion — **20–30% on MSM**
9. Precomputed coset twiddles — **Constant factor for rollups**
10. Sparse QAP (CSR format) — **40–70% on sparse circuits**

### 🔵 GAME-CHANGING (New capabilities)
11. **On-chain verifier codegen** — **Most impactful for deployment**
12. Proof aggregation (Bunz et al.) — **Production-grade compression**
13. Sparse circuit exploitation — **Real-world circuit advantage**
14. Streaming prover — **zkEVM-scale circuits**
15. VK compression — **Large public input handling**

---

## Notes

- Core problem: All modules exist but nothing is wired into main prover/verifier
- UniGroth currently functionally identical to vanilla arkworks Groth16 with extra files
- Items 1–4 are what separates "has code" from "actually beats Groth16"
- Items 11–13 are what make it concretely more useful than vanilla Groth16 in production
