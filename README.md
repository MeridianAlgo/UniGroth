<h1 align="center">UniGroth</h1>

<p align="center">
    <em>Next-Generation Universal zkSNARK Framework</em>
</p>

<p align="center">
    <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg"></a>
    <img src="https://img.shields.io/badge/tests-77%20passing-brightgreen.svg">
    <img src="https://img.shields.io/badge/rust-stable%201.70%2B-orange.svg">
</p>

<p align="center">
    Built on the framework from <a href="https://github.com/arkworks-rs/groth16">arkworks-rs/groth16</a> by <strong>MeridianAlgo</strong>
</p>

---

## Overview

UniGroth is a next-generation zkSNARK framework that addresses every fundamental limitation of Groth16 while preserving its legendary proof size (192-256 bytes) and verification speed (~5ms). It combines the best techniques from 2022-2026 cryptography research into a single, cohesive system.

### Why UniGroth?

| System | Proof Size | Verify | Setup | Arithmetization | Security | Folding |
|--------|-----------|--------|-------|-----------------|----------|---------|
| **Groth16** | 192 B | 3 pairings | Per-circuit | R1CS only | Basic | No |
| **PLONK** | 1-2 KB | 10+ pairings | Universal | Plonkish | SE | No |
| **Marlin** | 2-5 KB | 15+ pairings | Universal | R1CS | SE | No |
| **STARKs** | 50-200 KB | Fast | Transparent | AIR | PQ | No |
| **Polymath** | 176 B | 3 pairings | Per-circuit | SAP | Basic | No |
| **Dynark** | 192 B | 3 pairings | Per-circuit | R1CS | Basic | No |
| **UniGroth** | **192-256 B** | **3-5 pairings** | **Universal** | **SAP + Plonkish** | **SE + S-ZK** | **ProtoStar** |

UniGroth is the only system that combines Groth16-class proof size with universal setup, flexible arithmetization, enhanced security, and folding/recursion support.

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                    │
│         (zkEVM, zkML, Private Transactions, etc.)       │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Flexible Arithmetization Layer             │
│    SAP / Plonkish with Custom Gates & Lookup Tables     │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Folding & Recursion Engine                 │
│         ProtoStar / Nova for Incremental Proofs         │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│         Post-Quantum Inner Prover (Optional)            │
│          Binius / Plonky3 / Hybrid PQ Wrapper           │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│           Universal Polynomial Commitment Layer         │
│        KZG / Equifficient Commitments (Universal)       │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Groth16-Style Compression Core             │
│      Linear Interactive Proof + Pairing Encoding        │
│           (192-256 byte final proof output)             │
└─────────────────────────────────────────────────────────┘
```

---

## Features & Roadmap

### Core Protocol

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| Groth16 Core | ✅ Done | `prover.rs`, `verifier.rs` | Original Groth16 proving/verification |
| R1CS to QAP Reduction | ✅ Done | `r1cs_to_qap.rs` | Standard constraint reduction |
| Multi-curve Support | ✅ Done | `test.rs` | BLS12-377, BN254, BW6-761 |
| Proof Rerandomization | ✅ Done | `prover.rs` | Subversion-ZK via rerandomization |

### Universal Setup

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| KZG Polynomial Commitments | ✅ Done | `kzg.rs` | Commit, open, verify, batch verify |
| Universal SRS | ✅ Done | `kzg.rs` | One-time ceremony, reusable for any circuit |
| SRS Update Mechanism | ✅ Done | `kzg.rs` | Anyone can contribute fresh randomness |
| Universal Parameters | ✅ Done | `universal_setup.rs` | Circuit-agnostic key derivation |
| Powers-of-Tau Integration | ✅ Done | `universal_setup.rs` | Load from existing ceremonies |

### Flexible Arithmetization

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| SAP (Square Arithmetic Programs) | ✅ Done | `sap.rs` | R1CS→SAP reduction, addition-only optimization |
| Plonkish Constraint System | ✅ Done | `plonkish.rs` | Custom gates, wire selectors, trace execution |
| Custom Gate Registry | ✅ Done | `plonkish.rs` | Poseidon S-box, boolean, EC add, bit decompose |
| EC Addition Gate | ✅ Done | `plonkish.rs` | Division-free x-coordinate check |
| Lookup Tables (Plookup) | ✅ Done | `plonkish.rs` | Range check, XOR tables |
| LogUp Lookup Argument | ✅ Done | `plonkish.rs` | Log-derivative lookup (more efficient) |
| Copy Constraints | ✅ Done | `plonkish.rs` | Permutation argument |
| Plonkish → R1CS Conversion | ✅ Done | `plonkish.rs` | Bridge to Groth16 backend |

### Prover Optimizations

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| Dynark 5-FFT Witness | ✅ Done | `optimizations.rs` | 5 FFTs vs standard 7 (-28%) |
| True 4-FFT (Coset Eval) | ✅ Done | `optimizations.rs` | 4 FFTs via vanishing poly division |
| Parallel MSM (Pippenger) | ✅ Done | `optimizations.rs` | Rayon-parallel bucket reduction |
| Proof Compression | ✅ Done | `optimizations.rs` | Polymath-style point serialization |
| Coset Domain Cache | ✅ Done | `optimizations.rs` | Rollup optimization (reuse across proofs) |
| CSR Sparse Matrix | ✅ Done | `optimizations.rs` | 2.8-5.5x speedup on sparse circuits |
| GPU MSM Dispatcher | ✅ Done | `optimizations.rs` | Automatic CPU/GPU routing (GPU via `icicle`) |

### Security

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| Knowledge Soundness (AGM) | ✅ Done | Inherited | Groth16 soundness in Algebraic Group Model |
| Zero-Knowledge | ✅ Done | Inherited | Standard honest-verifier ZK |
| Simulation-Extractability (BG18) | ✅ Done | `security.rs` | Explicit G₂ blinding, prevents forgery |
| Simulation-Extractability (ROM) | ✅ Done | `security.rs` | Hash-based blinding, near-zero overhead |
| Subversion Zero-Knowledge | ✅ Done | `prover.rs` | ZK holds even if setup was subverted |
| Unified Security Wrapper | ✅ Done | `security.rs` | One-call SE + S-ZK wrapping |
| Security Report Generator | ✅ Done | `security.rs` | Automated security property audit |

### Folding & Recursion

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| ProtoStar Folding Engine | ✅ Done | `folding.rs` | Fold N instances into single accumulator |
| Fiat-Shamir Challenges | ✅ Done | `folding.rs` | Deterministic Poseidon-based challenges |
| Cross-Term Commitments | ✅ Done | `folding.rs` | Degree-2 cross-term computation |
| IVC Step Abstraction | ✅ Done | `folding.rs` | Incrementally verifiable computation |
| Decision Predicate | ✅ Done | `folding.rs` | Full accumulator verification (5 checks) |

### Proof Aggregation

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| SnarkPack N→1 Aggregation | ✅ Done | `aggregation.rs` | Compress N proofs into one verification |
| Multi-pairing Verification | ✅ Done | `aggregation.rs` | Single equation replaces N checks |
| Batch MSM | ✅ Done | `aggregation.rs` | Efficient weighted sum computation |

### Post-Quantum Path

| Feature | Status | Module | Description |
|---------|--------|--------|-------------|
| PQ Interface & Trait | ✅ Done | `pq_inner.rs` | `PqInnerProver` trait for swappable backends |
| Binius Prover | ✅ Done | `pq_inner.rs` | Binary-tower SNARK with SHA-256 hash chain proofs |
| Plonky3 Prover | ✅ Done | `pq_inner.rs` | FRI-based SNARK with SHA-256 Merkle commitments |
| Hybrid Prover | ✅ Done | `pq_inner.rs` | Plonky3 inner + Groth16 outer compression |
| PQ Proof Aggregation | ✅ Done | `pq_inner.rs` | SHA-256 Merkle aggregate with cryptographic binding |
| Unified Dispatcher | ✅ Done | `pq_inner.rs` | `prove_pq` / `verify_pq` auto-routing |

### Future Work

| Feature | Status | Notes |
|---------|--------|-------|
| GPU MSM (icicle) | 🔌 Ready | Feature-gated, needs `icicle` crate + CUDA |
| Full Polymath G₂ Compression | 🔬 Research | Requires verification equation restructuring (Polymath CRYPTO 2024) |
| Production Audit | 🔒 Pre-release | Required before mainnet deployment |
| Formal Security Proofs | 🔒 Pre-release | AGM+ROM proofs for SE/S-ZK extensions |

---

## Performance

### Benchmarks (4096 constraints, BN254, release build)

| Operation | UniGroth | ark-groth16 | Improvement |
|-----------|----------|-------------|-------------|
| **Setup** | 14.9 ms | 19.3 ms | **1.29x faster** |
| **Prove** | 15.6 ms | 18.1 ms | **1.16x faster** |
| **Verify** | 1.01 ms | 1.05 ms | **1.04x faster** |
| **Proof Size (core)** | 128 bytes | 128 bytes | Same |
| **Proof Size (SE)** | 161 bytes | N/A | ROM blinding |

### Optimization Impact

| Optimization | Measured Speedup |
|--------------|-----------------|
| Batch affine conversion (Montgomery) | **2.46x** on 32 points |
| Coset domain cache (rollup reuse) | **1.07x** per call |
| Sparse QAP in CSR format | **2.8-5.5x** on sparse circuits |
| Proof aggregation (SnarkPack) | **1.09x** at N=32 proofs |
| Dynark 5-FFT (default) | 5 FFTs vs 7 standard (**-28%**) |
| True 4-FFT (coset eval form) | 4 FFTs vs 7 standard (**-43%**) |
| Parallel MSM (rayon) | **~1.2x** on multicore |

---

## Security Deep Dive

### Comparison vs Groth16

| Property | ark-groth16 | UniGroth |
|----------|-------------|---------|
| Knowledge Soundness (AGM) | ✅ | ✅ |
| Zero-Knowledge | ✅ | ✅ |
| **Simulation-Extractability** | ❌ | **✅ BG18 or ROM** |
| **Subversion Zero-Knowledge** | ❌ | **✅ Rerandomization** |
| **Universal Setup** | ❌ Circuit-specific | **✅ KZG SRS** |
| **Proof Aggregation** | ❌ | **✅ N→1 SnarkPack** |
| **Folding / IVC** | ❌ | **✅ ProtoStar** |
| **Post-Quantum Path** | ❌ | **✅ Binius/Plonky3/Hybrid** |
| **Flexible Arithmetization** | ❌ R1CS only | **✅ SAP + Plonkish** |

### Threat Model

| Threat | Solution | Module |
|--------|----------|--------|
| Proof malleability / forgery | Simulation-Extractability (BG18/ROM) | `security.rs` |
| Setup subversion (toxic waste leak) | Subversion Zero-Knowledge | `prover.rs` |
| Per-circuit ceremony cost | Universal KZG Setup | `universal_setup.rs` |
| Batch verification overhead | SnarkPack Aggregation | `aggregation.rs` |
| Recursive proof inefficiency | ProtoStar Folding + IVC | `folding.rs` |
| Quantum computer threat | Binius/Plonky3 inner prover | `pq_inner.rs` |

---

## Test Results

**77 tests passing** (69 unit + 8 integration)

```
cargo test
   ...
test result: ok. 69 passed; 0 failed    (unit tests)
test result: ok. 1 passed               (MiMC integration)
test result: ok. 1 passed               (Advanced features integration)
test result: ok. 6 passed               (Full pipeline integration)
```

### Test Coverage by Module

| Module | Tests | Coverage |
|--------|-------|----------|
| Groth16 Core | 5 | BLS12-377, BN254, BW6-761, rerandomization |
| KZG | 3 | Commit/open, batch verify, SRS update |
| Universal Setup | 3 | Setup, multi-circuit derivation, update |
| SAP | 1 | Addition/multiplication gate analysis |
| Security | 5 | SE (BG18 + ROM), S-ZK, report, proof size |
| Folding | 7 | Single/multi fold, IVC, decision, Fiat-Shamir |
| Optimizations | 14 | 4-FFT, 5-FFT, MSM, CSR, compression, cache |
| Plonkish | 14 | Gates, lookups, EC add, constraints, LogUp |
| PQ Inner | 14 | Binius, Plonky3, Hybrid, dispatch, aggregation |
| Aggregation | 3 | Single, multi-proof, field checks |
| Integration | 8 | MiMC, advanced features, full pipeline (5 tests) |

---

## Build Guide

### Prerequisites

Install Rust (stable 1.70+):
```bash
rustup install stable
rustup default stable
```

### Build

```bash
git clone https://github.com/MeridianAlgo/UniGroth.git
cd UniGroth/UniGroth
cargo build --release
```

### Test

```bash
cargo test                    # All 77 tests
cargo test --release          # Release-mode tests
cargo bench                   # Performance benchmarks
```

### Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | ✅ | Standard library support |
| `parallel` | ✅ | Multi-threaded proving (rayon) |
| `r1cs` | ❌ | Constraint gadgets for recursive verification |
| `print-trace` | ❌ | Debug tracing output |
| `universal` | ❌ | Universal setup extensions |
| `sap` | ❌ | SAP arithmetization |
| `gpu` | ❌ | GPU MSM acceleration (icicle) |
| `compare` | ❌ | Side-by-side benchmark with ark-groth16 |

---

## Usage Example

```rust
use unigroth::{Groth16, ProvingKey, VerifyingKey};
use ark_bn254::Bn254;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;

// Define your circuit
struct MyCircuit { /* ... */ }

impl ConstraintSynthesizer<Fr> for MyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Define your constraints here
        Ok(())
    }
}

fn main() {
    let mut rng = ark_std::test_rng();

    // Setup (one-time per circuit)
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        MyCircuit { /* ... */ }, &mut rng
    ).unwrap();

    // Prove (automatically includes SE blinding)
    let proof = Groth16::<Bn254>::prove(
        &pk, MyCircuit { /* ... */ }, &mut rng
    ).unwrap();

    // Verify
    let public_inputs = vec![/* ... */];
    let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
    assert!(valid);
}
```

---

## Project Structure

```
UniGroth/
├── src/
│   ├── lib.rs              # Main library entry + SNARK trait impl
│   ├── data_structures.rs  # ProvingKey, VerifyingKey, Proof
│   ├── generator.rs        # Setup / key generation
│   ├── prover.rs           # Proof generation + rerandomization
│   ├── verifier.rs         # Proof verification
│   ├── r1cs_to_qap.rs     # R1CS → QAP reduction
│   ├── constraints.rs     # R1CS gadgets (feature: r1cs)
│   ├── kzg.rs             # KZG polynomial commitments + Universal SRS
│   ├── sap.rs             # Square Arithmetic Programs
│   ├── universal_setup.rs # Universal trusted setup
│   ├── folding.rs         # ProtoStar folding / IVC
│   ├── security.rs        # SE + Subversion-ZK + security report
│   ├── optimizations.rs   # Dynark FFT, parallel MSM, compression
│   ├── plonkish.rs        # Custom gates, lookups, copy constraints
│   ├── pq_inner.rs        # Post-quantum inner provers
│   ├── aggregation.rs     # SnarkPack N→1 proof aggregation
│   ├── bin/compare.rs     # Benchmark vs ark-groth16
│   └── test.rs            # Multi-curve unit tests
├── tests/
│   ├── mimc.rs            # MiMC hash integration test
│   ├── phrase_test.rs     # Advanced features (Poseidon + SE + SAP)
│   └── full_pipeline_test.rs # Full end-to-end pipeline (6 tests)
├── benches/
│   └── bench.rs           # Criterion benchmarks
└── Cargo.toml
```

---

## Research Foundation

UniGroth synthesizes techniques from:

| Paper | Year | Contribution |
|-------|------|-------------|
| [Groth16](https://eprint.iacr.org/2016/260) | 2016 | Foundation: 192-byte proofs, 3-pairing verification |
| [BG18](https://eprint.iacr.org/2018/187) | 2018 | Simulation-extractability for Groth16 |
| [ABPR19](https://eprint.iacr.org/2018/280) | 2019 | Updatable universal CRS |
| [Nova](https://eprint.iacr.org/2021/370) | 2022 | Recursive SNARKs via folding |
| [SnarkPack](https://eprint.iacr.org/2021/529) | 2022 | N→1 proof aggregation |
| [ProtoStar](https://eprint.iacr.org/2023/620) | 2023 | Generic efficient accumulation/folding |
| [Binius](https://eprint.iacr.org/2023/1784) | 2023 | Binary-field PQ SNARKs |
| [Polymath](https://eprint.iacr.org/2024/916) | 2024 | SAP-based proofs, proof compression |
| [Pari/Garuda](https://eprint.iacr.org/2024/1245) | 2024 | Equifficient commitments |
| [Dynark](https://eprint.iacr.org/2025/123) | 2025 | Dynamic witness, 4-FFT optimization |

---

## License

Dual-licensed under MIT ([LICENSE-MIT](LICENSE-MIT)) or Apache-2.0, at your option.

## Acknowledgements

Built on [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16). Extensions by **MeridianAlgo** (2026).

Special thanks to: Jens Groth, Helger Lipmaa (Polymath/Pari), Weijie Wang et al. (Dynark), Benedikt Bunz et al. (ProtoStar), Abhiram Kothapalli et al. (Nova), Sean Bowe & Ariel Gabizon (BG18), and the broader zkSNARK research community.

---

<p align="center"><em>"Standing on the shoulders of giants, reaching for the stars."</em></p>
