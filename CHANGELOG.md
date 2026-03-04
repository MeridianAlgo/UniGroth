# CHANGELOG

## UniGroth v0.1.0 (March 2026)

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
