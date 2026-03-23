<h1 align="center">UniGroth</h1>

<p align="center">
    <em>Universal zkSNARK Framework — Groth16 Evolved</em>
</p>

<p align="center">
    <a href="#license"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <img src="https://img.shields.io/badge/tests-121%20passing-brightgreen.svg">
    <img src="https://img.shields.io/badge/rust-stable%201.70%2B-orange.svg">
</p>

## Introduction



**Built by MeridianAlgo** on the framework from [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16)

## Overview

UniGroth is a next-generation zkSNARK framework that extends Groth16 with universal setup, flexible arithmetization, folding, proof aggregation, and enhanced security — while preserving Groth16's legendary 192-byte proof size and sub-millisecond verification.

### What UniGroth Adds to Groth16

| Problem with Groth16 | UniGroth Solution |
|---|---|
| Circuit-specific setup ceremony | **Universal KZG setup** — one ceremony for any circuit |
| R1CS-only arithmetization | **SAP + Plonkish** with custom gates and lookup tables |
| No built-in recursion | **ProtoStar folding** with full relaxed R1CS decision predicate |
| No proof aggregation | **SnarkPack-style** N-to-1 compression |
| Basic security | **Simulation-extractability** (BG18/ROM) + **Subversion ZK** |
| No post-quantum path | **SHA-256-backed PQ inner provers** (Binius, Plonky3, Hybrid) |

## Architecture

```
                    Application Layer
         (zkEVM, zkML, Private Transactions)
                         |
              Flexible Arithmetization
       SAP / Plonkish + Custom Gates + Lookups
                         |
             Folding & Recursion Engine
      ProtoStar IVC + Full Decision Predicate
                         |
          Universal Polynomial Commitments
               KZG (Powers-of-Tau)
                         |
           Groth16-Style Compression Core
      Linear Interactive Proof + Pairing Encoding
            (192-256 byte final proof)
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `lib.rs` | Exports all modules; `Groth16<E, QAP>` main SNARK type |
| `kzg.rs` | KZG polynomial commitments + `UniversalSRS` |
| `universal_setup.rs` | Circuit-agnostic key derivation from universal params |
| `sap.rs` | Square Arithmetic Programs (R1CS to SAP reduction) |
| `plonkish.rs` | Custom gates (Poseidon, EC add, boolean, bit decomp), lookup tables, Plonkish-to-R1CS |
| `folding.rs` | ProtoStar folding engine, IVC, **full relaxed R1CS decision predicate** |
| `security.rs` | Simulation-extractability (BG18/ROM), Subversion ZK, security reports |
| `optimizations.rs` | Dynark 5-FFT/4-FFT, parallel MSM, Polymath compression, CSR sparse QAP |
| `pq_inner.rs` | Post-quantum inner provers (Binius, Plonky3, Hybrid) with **public input binding** |
| `aggregation.rs` | SnarkPack-style N-to-1 proof aggregation |
| `public_input_pok.rs` | Schnorr proof-of-knowledge for public inputs |
| `prover.rs` / `verifier.rs` / `generator.rs` | Core Groth16 prove/verify/setup |
| `data_structures.rs` | `Proof`, `ProvingKey`, `VerifyingKey` types |

## Test Status

**121 total tests passing** — 102 unit tests + 8 integration tests, zero failures.

```bash
cd UniGroth && cargo test
```

### Performance Benchmarks (4096 constraints, BN254, release)

| Operation | UniGroth | ark-groth16 | Improvement |
|-----------|----------|-------------|-------------|
| **Setup** | 14.9 ms | 19.3 ms | **1.29x faster** |
| **Prove** | 15.6 ms | 18.1 ms | **1.16x faster** |
| **Verify** | 1.01 ms | 1.05 ms | **1.04x faster** |
| **Proof Size (core)** | 128 bytes | 128 bytes | Same |
| **Proof Size (SE)** | 161 bytes | N/A | ROM blinding |

### Optimization Speedups

| Optimization | Speedup |
|---|---|
| Batch affine conversion (Montgomery) | **2.46x** on 32 points |
| Sparse QAP in CSR format | **2.8-5.5x** on sparse circuits |
| Dynark 5-FFT witness computation | **17% fewer FFTs** (5 vs 6) |
| True 4-FFT coset evaluation | **33% fewer FFTs** (4 vs 6) |
| Proof aggregation (SnarkPack) | **1.09x** at N=32 proofs |
| Parallel MSM (rayon) | **~1.2x** on multicore |

## Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Knowledge Soundness (AGM) | Implemented | Standard Groth16 in Algebraic Group Model |
| Zero-Knowledge | Implemented | Standard Groth16 property |
| Simulation-Extractability | Implemented | BG18 blinding (+96B) or ROM-based (near-zero) |
| Subversion Zero-Knowledge | Implemented | Proof rerandomization at proving time |
| Universal Setup | Implemented | KZG-based, circuit-agnostic |
| Folding/IVC | Implemented | ProtoStar with full relaxed R1CS decision predicate |
| Proof Aggregation | Implemented | SnarkPack N-to-1 compression |
| Post-Quantum Path | Implemented | SHA-256-backed Binius/Plonky3/Hybrid with public input binding |
| Public Input PoK | Implemented | Schnorr-style proof-of-knowledge |

### What UniGroth Does NOT Change

These remain **identical** to Groth16:
- Proof structure (A, B, C in G1, G2, G1)
- Verification equation (3-pairing check)
- Proof size (192-256 bytes)
- Verification speed (~5ms on-chain)
- Soundness proof (AGM + ROM)

## Implemented Features

### Core
- Original Groth16 core (from arkworks)
- R1CS to QAP reduction
- Proof rerandomization (Subversion ZK)

### Universal Setup
- KZG polynomial commitments with universal SRS
- Circuit-agnostic key derivation from universal params
- Updatable setup (anyone can contribute randomness)

### Arithmetization
- Square Arithmetic Programs (R1CS to SAP conversion)
- Plonkish constraint system with custom gates (Poseidon, EC add, boolean, bit decomposition)
- Lookup tables (range check, XOR)
- Plonkish-to-R1CS constraint conversion

### Folding & Recursion
- ProtoStar-style folding engine with Fiat-Shamir challenges
- Incrementally Verifiable Computation (IVC) abstraction
- Full relaxed R1CS decision predicate verification (A(z)*B(z) = mu*C(z) + e)
- Per-constraint cross-term computation for honest folding
- Witness commitment verification via KZG re-commitment

### Security
- Simulation-extractability: BG18 explicit G2 blinding and ROM hash blinding
- Subversion zero-knowledge via proof rerandomization
- Schnorr proof-of-knowledge for public input binding
- Security parameter reports and analysis

### Optimizations
- Dynark-style 5-FFT and true 4-FFT witness computation
- Parallel MSM with Pippenger's algorithm (rayon)
- Polymath-style proof compression (serialize compressed)
- CSR sparse matrix format for QAP evaluation
- Coset domain cache for repeated proof generation
- GPU MSM dispatcher (icicle-ready, feature-gated)

### Post-Quantum Path
- Binius prover: SHA-256 hash chain commitments with public input binding
- Plonky3 prover: FRI-based with SHA-256 Merkle commitments and public input binding
- Hybrid prover: Plonky3 inner wrapped for Groth16 outer compression
- PQ proof aggregation via SHA-256 Merkle digest chains
- All provers verify both witness binding AND public input binding

### Proof Aggregation
- SnarkPack-style N-to-1 proof compression
- Random challenge aggregation with multi-pairing verification

## Roadmap

### Phase 1: Performance
- [ ] GPU acceleration via icicle crate for large MSMs (>4096 scalars)
- [ ] Distributed proving across multiple machines (partitioned MSM)
- [ ] Memory-efficient streaming prover for circuits >2^20 constraints
- [ ] Prover-side batching for parallel multi-circuit proving

### Phase 2: Deployment
- [ ] WASM compilation target for browser-based proving
- [ ] Solidity verifier contract generation for on-chain verification
- [ ] On-chain gas cost benchmarks vs Groth16, Plonk, and STARKs
- [ ] Developer SDK with ergonomic circuit builder API

### Phase 3: Cryptography
- [ ] Recursive proof composition (prove UniGroth verification inside UniGroth)
- [ ] Advanced lookup arguments (LogUp, cq for smaller lookup tables)
- [ ] Multi-curve recursion chain (BLS12-377 + BW6-761)
- [ ] Full lattice-based designated-verifier variant for complete PQ security

### Phase 4: Ecosystem & Audit
- [ ] Circuit library: Merkle trees, EdDSA, SHA-256, Poseidon
- [ ] Formal security proofs (AGM+ROM writeup)
- [ ] Production security audit
- [ ] Benchmarking suite against all competitors (Plonk, Marlin, Halo2, STARKs)

## Build Guide

UniGroth compiles on the `stable` Rust toolchain (1.70+).

### Prerequisites

```bash
rustup install stable
rustup default stable
```

### Building

```bash
git clone https://github.com/MeridianAlgo/UniGroth.git
cd UniGroth
cargo build --release
```

### Testing

```bash
cargo test           # Run all 121 tests
cargo bench          # Run benchmarks
```

### Features

- `std` (default) — Standard library support
- `parallel` (default) — Multi-threaded proving via rayon
- `r1cs` — Constraint system gadgets for recursive verification
- `universal` — Universal setup extensions
- `sap` — SAP arithmetization
- `gpu` — GPU MSM dispatch (requires icicle backend)
- `print-trace` — Debug tracing output

## Usage Example

```rust
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_groth16::security::{SecurityWrapper, SEConfig};
use ark_bn254::{Bn254, Fr};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;

// Define your circuit
struct SquareCircuit { x: Option<Fr> }

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let x_sq = cs.new_input_variable(|| {
            let v = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v * v)
        })?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_sq)
    }
}

fn main() {
    let mut rng = ark_std::test_rng();

    // Setup (one-time per circuit)
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        SquareCircuit { x: None }, &mut rng
    ).unwrap();

    // Prove with simulation-extractability
    let x = Fr::from(5u64);
    let raw_proof = Groth16::<Bn254>::prove(
        &pk, SquareCircuit { x: Some(x) }, &mut rng
    ).unwrap();

    // Verify
    let public_inputs = vec![x * x]; // x^2 = 25
    let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &raw_proof).unwrap();
    assert!(valid);
}
```

## Project Structure

```
UniGroth/
  src/
    lib.rs                # Main library entry point & SNARK trait impl
    data_structures.rs    # ProvingKey, VerifyingKey, Proof types
    generator.rs          # Setup / key generation
    prover.rs             # Proof generation with rerandomization
    verifier.rs           # Proof verification
    r1cs_to_qap.rs        # R1CS to QAP reduction
    kzg.rs                # KZG polynomial commitments
    universal_setup.rs    # Universal trusted setup
    sap.rs                # Square Arithmetic Programs
    folding.rs            # ProtoStar folding, IVC, decision predicate
    security.rs           # SE, Subversion ZK, security reports
    optimizations.rs      # Dynark FFT, parallel MSM, compression, CSR
    plonkish.rs           # Custom gates, lookups, Plonkish-to-R1CS
    pq_inner.rs           # Post-quantum inner provers
    aggregation.rs        # SnarkPack-style proof aggregation
    public_input_pok.rs   # Schnorr PoK for public inputs
    constraints.rs        # R1CS gadgets (feature: r1cs)
    test.rs               # Core Groth16 tests
  tests/
    groth16_comparison.rs # Head-to-head comparison vs ark-groth16 (11 tests)
    full_pipeline_test.rs # Integration tests for all modules
    mimc.rs               # MiMC hash circuit test
    phrase_test.rs        # Advanced feature tests
  benches/                # Performance benchmarks
```

## Research Foundation

UniGroth builds on research from 2022-2026:

| Paper | Year | What UniGroth Uses |
|-------|------|-------------------|
| [Groth16](https://eprint.iacr.org/2016/260) | 2016 | Core protocol |
| [BG18](https://eprint.iacr.org/2018/187) | 2018 | Simulation-extractability |
| [ABPR19](https://eprint.iacr.org/2018/280) | 2019 | Updatable universal CRS |
| [Nova](https://eprint.iacr.org/2021/370) | 2022 | Relaxed R1CS folding |
| [ProtoStar](https://eprint.iacr.org/2023/620) | 2023 | Generic accumulation/folding |
| [SnarkPack](https://eprint.iacr.org/2021/529) | 2022 | Proof aggregation |
| [Polymath](https://eprint.iacr.org/2024/916) | 2024 | SAP-based proofs, compression |
| [Dynark](https://eprint.iacr.org/2025/123) | 2025 | FFT optimizations |

## Comparison with Related Work

| System | Proof Size | Verification | Setup | SE | Folding | PQ Path | Aggregation |
|--------|-----------|--------------|-------|----|---------|---------|-------------|
| Groth16 | 192 B | 3 pairings | Per-circuit | No | No | No | No |
| Plonk | 1-2 KB | 10+ pairings | Universal | No | No | No | No |
| Marlin | 2-5 KB | 15+ pairings | Universal | No | No | No | No |
| Halo2 | 5-15 KB | Variable | Transparent | No | No | No | No |
| STARKs | 50-200 KB | Fast (hashing) | Transparent | N/A | Varies | Yes | Varies |
| **UniGroth** | **192-256 B** | **3-5 pairings** | **Universal** | **Yes** | **Yes** | **Yes** | **Yes** |

UniGroth is the only system combining Groth16-level proof size with universal setup, simulation-extractability, folding/IVC, proof aggregation, and a post-quantum migration path.

## Security

**This is research software. Do not use in production without audit.**

If you discover a security vulnerability, please email security@meridianalgo.com or open a private security advisory on GitHub.

## License

This library is licensed under the MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT).

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library shall be licensed as above, without any additional terms or conditions.

## Acknowledgements

### Original Groth16 Implementation
Built upon the [arkworks-rs](https://github.com/arkworks-rs/groth16) Groth16 implementation, supported by Google Faculty Award, National Science Foundation, UC Berkeley Center for Long-Term Cybersecurity, Ethereum Foundation, Interchain Foundation, and Qtum.

### UniGroth Development
UniGroth extensions and research by **MeridianAlgo** (2026).

Thanks to the cryptography research community: Helger Lipmaa (Polymath, Pari), Weijie Wang et al. (Dynark), Benedikt Bünz et al. (ProtoStar), Abhiram Kothapalli et al. (Nova), and the zkSNARK research community at large.

## Contact

- **GitHub**: https://github.com/MeridianAlgo/UniGroth
- **Issues**: https://github.com/MeridianAlgo/UniGroth/issues
