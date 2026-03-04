# CHANGELOG

## UniGroth v0.1.0 (March 2026)

### New Modules

#### Universal & Updatable SRS (`src/kzg.rs`, `src/universal_setup.rs`)
- `UniversalSRS` — Powers-of-Tau structured reference string supporting degrees up to 2²⁸
- `KZG::commit`, `KZG::open`, `KZG::verify`, `KZG::batch_verify` — full KZG polynomial commitment scheme over any pairing-friendly curve
- `UniversalSRS::update` — updatable SRS: anyone can contribute entropy post-ceremony
- `UniversalSRS::from_powers_of_tau` — load from existing Perpetual Powers of Tau transcripts
- `UniversalParams` — wraps KZG SRS with Groth16-specific scalars; exposes `derive_keys` and `derive_keys_with_sap` for circuit-agnostic key generation without a new ceremony
- Tests: commit/open/verify roundtrip, batch verify, SRS update, universal setup for multiple circuits, updatable setup

#### Square Arithmetic Programs (`src/sap.rs`)
- `R1CSToSAP` — reduction from R1CS to SAP form; detects addition-only gates and reports optimization gains
- `SAPStats` — analyzes a constraint system and reports addition/multiplication gate split and estimated circuit size reduction (typically 2-3×)
- Integrated as an alternative QAP reduction into `UniversalParams::derive_keys_with_sap`
- Tests: SAP statistics on mixed addition/multiplication circuits

#### ProtoStar Folding / IVC (`src/folding.rs`)
- `FoldingInstance` — holds public inputs, witness, and slack variable for a single step
- `FoldingAccumulator` — running accumulator state (acc_x, acc_w, acc_e, acc_μ) with randomness transcript
- `FoldingEngine` — folds instances one-by-one: initializes on first call, applies randomized combination with cross-term commitments on subsequent calls
- `IVC` — high-level Incrementally Verifiable Computation wrapper with `step()` / `finalize()` API
- `verify_accumulator` — decision predicate stub; full relaxed R1CS check is stubbed with detailed implementation notes (ProtoStar §4.2)
- Cross-term computation, Fiat-Shamir challenge generation (currently random; Poseidon hash TODO), witness polynomial interpolation via IFFT
- Tests: single fold, 5-instance fold, 10-step IVC, decision check, scalar fold correctness, witness polynomial recovery

#### Simulation-Extractability & Subversion ZK (`src/security.rs`)
- `SimExtractableProof<E>` — extended proof with optional BG18 G₂ blinding element and ROM proof hash
- `SEConfig` — choose between BG18 full SE (+1 G₂, explicit blinding) or ROM-based SE (near-zero overhead)
- `make_sim_extractable` — wraps any Groth16 proof with SE blinding
- `verify_sim_extractable` — verifies SE-wrapped proofs (delegates to Groth16 verifier; BG18 pairing check TODO)
- `apply_subversion_zk` — S-ZK rerandomization wrapper using Groth16's built-in rerandomize
- `SecurityParams` / `SecurityReport` — declare and print security properties (KS in AGM, ZK, SE, S-ZK, PQ flag)
- Post-quantum design notes: Binius/Plonky3 hybrid inner prover path; LWE designated-verifier full PQ path
- Tests: security report, ROM SE proof + verify, BG18 blinding, S-ZK rerandomization, proof size check

#### Prover Optimizations (`src/optimizations.rs`)
- `compute_witness_4fft` — Dynark-style witness computation reducing FFT count (iFFT(a), iFFT(b), coset-FFT(a), coset-FFT(b) run in parallel via rayon; c iFFT elimination TODO pending full SAP algebraic identity)
- `parallel_msm` / `parallel_msm_g2` — Pippenger MSM with stats reporting, backed by arkworks' parallel implementation
- `MSMGPUHint` — signals when n > 2¹² scalars warrant GPU dispatch; documents icicle/bellman-cuda integration path
- `PolymathCompressor` — size estimation for Polymath G₂-free proof compression (128 bytes target); compression itself is TODO pending Polymath §5 integration
- `ProverProfile::estimate_speedup` — models expected speedup: SAP reduction × Dynark FFT factor × parallel MSM factor
- Tests: 4-FFT on random and zero witnesses, MSM correctness (single scalar), GPU hint thresholds, size estimates, speedup estimates

#### Plonkish Arithmetization (`src/plonkish.rs`)
- `PlonkSelectors<F>` — q_L, q_R, q_O, q_M, q_C, q_lookup selectors with named constructors (`mul_gate`, `add_gate`, `public_input_gate`, `constant_gate`) and `evaluate(a, b, c)`
- `CustomGateRegistry<F>` — pluggable custom gate registry; built-ins: Poseidon S-Box (x^5), boolean check (a(a-1)=0), partial EC add, 2-bit decomposition
- `LookupTable<F>` — range-check tables (2^k entries), XOR tables, LogUp sum for polynomial identity argument
- `PlonkishConstraintSystem<F>` — full execution trace with `add_mul_gate`, `add_add_gate`, `add_public_input`, `add_range_check`, `add_poseidon_sbox`, `add_copy_constraint`; `is_satisfied()` skips public-input and lookup rows; `stats()` reports compression ratio
- `PlonkishStats` — reports total rows, gate breakdown, effective R1CS size, and compression ratio
- `plonkish_to_r1cs_stats` — returns the number of multiplication constraints (only muls need R1CS constraints; addition/lookup rows are free)
- Tests: gate selectors, custom gates, range and XOR tables, full circuit construction and satisfaction, range check, Poseidon S-Box, compression ratio (10:1 on addition-heavy circuits), LogUp sum, copy constraints, R1CS size mapping

### Bug Fixes
- Fixed `tests/mimc.rs` using `ark_groth16::Groth16` (unresolved import) — updated to `unigroth::Groth16`

### Test Results
- **42/42** unit tests pass across all modules (folding, security, optimizations, plonkish, kzg, sap, universal_setup, core Groth16)
- **1/1** integration test passes (`tests/mimc.rs` — MiMC hash circuit, 50 prove/verify iterations on BLS12-377)

---

## UniGroth v0.0.0 (March 2026)

### Project Fork & Rebranding

- **Forked from arkworks-rs/groth16** - UniGroth is built on the excellent Groth16 implementation from the arkworks ecosystem
- **Renamed to UniGroth** - Reflecting the vision of a universal, next-generation zkSNARK framework
- **New project identity** - Updated package name to `unigroth`, new repository structure, comprehensive documentation

### Documentation

- [\#INIT] Complete README overhaul with UniGroth vision, architecture, and roadmap
- [\#INIT] Added comprehensive comparison with related work (Polymath, Pari, Dynark, Plonk, STARKs)
- [\#INIT] Created ROADMAP.md with detailed 24-month development plan
- [\#INIT] Enhanced library documentation with UniGroth context and future features
- [\#INIT] Added research paper references and implementation resources

### Project Structure

- [\#INIT] Updated Cargo.toml with UniGroth metadata and authorship
- [\#INIT] Maintained compatibility with arkworks ecosystem
- [\#INIT] Preserved dual MIT/Apache-2.0 licensing
- [\#INIT] Set minimum Rust version to 1.70

### Current Status

⚠️ **RESEARCH PROTOTYPE** - This release contains the baseline Groth16 implementation. Universal setup, SAP arithmetization, folding, and other UniGroth features are under active development.

### Acknowledgements

Built on the framework from [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16). Extended by MeridianAlgo (2026).

---

## Upstream Changes (from arkworks-rs/groth16)

The following changes are from the original arkworks Groth16 implementation that UniGroth is based on:

## Pending

### Breaking changes

- [\#44](https://github.com/arkworks-rs/groth16/pull/44) Move free functions in `generator.rs`, `prover.rs`, `verifier.rs` to methods on `Groth16` struct.

### Features

- [\#34](https://github.com/arkworks-rs/groth16/pull/34) Allow specifying custom R1CS to QAP reductions.
- [\#44](https://github.com/arkworks-rs/groth16/pull/44) Extend \#34 by adding support for custom QAP reductions to the `Groth16` struct directly.

### Improvements

- [\#36](https://github.com/arkworks-rs/groth16/pull/36) Documentation updates and minor optimization in setup.

### Bug fixes

## v0.3.0

### Breaking changes

- [\#21](https://github.com/arkworks-rs/groth16/pull/21) Change the `generate_parameters` interface to take generators as input.

### Features

- [\#30](https://github.com/arkworks-rs/groth16/pull/30) Add proof input preprocessing.

### Improvements

### Bug fixes

## v0.2.0

### Breaking changes

- [\#4](https://github.com/arkworks-rs/groth16/pull/4) Change `groth16`'s logic to implement the `SNARK` trait.
- Minimum version on crates from `arkworks-rs/algebra` and `arkworks-rs/curves` is now `v0.2.0`
- [\#24](https://github.com/arkworks-rs/groth16/pull/24) Switch from `bench-utils` to `ark_std::perf_trace`

### Features

- [\#5](https://github.com/arkworks-rs/groth16/pull/5) Add R1CS constraints for the groth16 verifier.
- [\#8](https://github.com/arkworks-rs/groth16/pull/8) Add benchmarks for the prover
- [\#16](https://github.com/arkworks-rs/groth16/pull/16) Add proof re-randomization

### Improvements

- [\#9](https://github.com/arkworks-rs/groth16/pull/9) Improve memory consumption by manually dropping large vectors once they're no longer needed

### Bug fixes

- [c9bc5519](https://github.com/arkworks-rs/groth16/commit/885b9b569522f59a7eb428d1095f442ec9bc5519) Fix parallel feature flag
- [\#22](https://github.com/arkworks-rs/groth16/pull/22) Compile with `panic='abort'` in release mode, for safety of the library across FFI boundaries.

## v0.1.0

_Initial release_
