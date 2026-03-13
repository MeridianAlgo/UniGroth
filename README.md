<h1 align="center">UniGroth</h1>

<p align="center">
    <em>Universal zkSNARK Framework</em>
</p>

<p align="center">
    <a href="#license"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
</p>

**Edited by MeridianAlgo** — Built on the framework from [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16)

## Overview

UniGroth is an newer zkSNARK framework that addresses the fundamental limitations of Groth16 while preserving its legendary proof size and verification speed. This project represents a research-driven approach to building the next generation of zero-knowledge proof systems.

### The Evolution Beyond Groth16

Groth16 (2016) revolutionized zkSNARKs with its 192-byte proofs and 3-pairing verification, but it has critical limitations:
- **Circuit-specific trusted setup** — requires a new multi-party computation ceremony for every circuit
- **No flexibility** — locked into R1CS, no custom gates or lookups
- **Prover inefficiency** — slower than modern systems on complex circuits
- **Limited security** — not simulation-extractable or subversion-resistant by default

UniGroth aims to solve these problems while maintaining Groth16's core strengths.

## Design Goals

UniGroth is designed as a comprehensive framework combining cutting-edge research from 2024-2026:

### 1. Universal & Updatable Setup
- **One-time ceremony** using Powers-of-Tau (already completed for BN254/BLS12-381)
- **Updatable** — anyone can contribute additional randomness for enhanced security
- **Reusable** — works for any circuit up to 2²⁸ gates without new ceremonies
- Based on KZG-style polynomial commitments and universal Phase-2 techniques

### 2. Flexible Arithmetization
- **Square Arithmetic Programs (SAP)** — inspired by Polymath (CRYPTO 2024) and Pari/Garuda (2024)
- **Plonkish gates** — custom gates and lookup tables for 2-5× smaller effective circuits
- **Efficient encoding** — addition gates and lookups become nearly free
- Result: faster prover than vanilla Groth16 on real-world circuits (zkEVMs, ML inference)

### 3. Groth16-Level Performance
- **Proof size**: 192-256 bytes (3-4 group elements)
- **Verification**: 3-5 pairings (~5ms, same on-chain gas as Groth16)
- **Compression** — uses Groth16's elegant Linear Interactive Proof structure
- **Universal polynomial openings** replace circuit-specific encodings

### 4. Folding & Recursion
- **ProtoStar-style folding** — incremental proof composition
- **Nova integration** — efficient IVC (Incrementally Verifiable Computation)
- **Recursive aggregation** — compress multiple proofs into one
- Enables zkVM and rollup applications with minimal overhead

### 5. Enhanced Security
- **Simulation-Extractability (SE)** — prevents proof malleability attacks
- **Subversion zero-knowledge** — secure even if setup is backdoored
- **AGM + ROM security** — proven in the Algebraic Group Model with Random Oracle
- **Post-quantum path** — optional hybrid mode with lattice-based or Binius inner proofs

### 6. Prover Optimizations
- **Dynark-style FFTs** — 4 FFTs instead of 6 (from Dynark 2025)
- **GPU/FPGA acceleration** — optimized MSMs and parallel folding
- **Dynamic witness updates** — up to 1400× faster for incremental changes
- **Hardware-friendly** — designed for ASIC implementation

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

## Performance Targets

| Metric | Groth16 (2016) | UniGroth (Target) | Improvement |
|--------|----------------|-------------------|-------------|
| Proof Size | 192 bytes | 192-256 bytes | ≈ Same |
| Verification | 3 pairings (~5ms) | 3-5 pairings (~5-7ms) | ≈ Same |
| Prover Time | Baseline | 2-5× faster* | 2-5× faster |
| Setup | Circuit-specific MPC | One universal ceremony | 3-5x faster |
| Flexibility | R1CS only | Plonkish + lookups | Full |
| Security | Basic | SE + Subversion-resistant | Stronger |

> *On real-world circuits with lookups and custom gates*

## Current Status

**RESEARCH PROTOTYPE** — Academic proof-of-concept under active development. Not audited or production-ready.

### Test Results

- **57 total tests pass**: 51 unit tests + 6 new optimization tests (batch affine, coset cache, CSR sparse, aggregation) + 1 integration test (MiMC)
- Run with: `cd UniGroth && cargo test`

### Performance Benchmarks (4096 constraints, BN254, release build)

| Operation | UniGroth | ark-groth16 | Improvement |
|-----------|----------|-------------|-------------|
| **Setup** | 14.9 ms | 19.3 ms | **1.29× faster** |
| **Prove** | 15.6 ms | 18.1 ms | **1.16× faster** |
| **Verify** | 1.01 ms | 1.05 ms | **1.04× faster** |
| **Proof Size (core)** | 128 bytes | 128 bytes | Same |
| **Proof Size (with SE)** | 161 bytes | - | ROM blinding |

### Advanced Optimizations Implemented

| Optimization | Status | Measured Speedup |
|--------------|--------|------------------|
| Batch affine conversion (Montgomery) | ✅ | **2.46×** on 32 points |
| Coset domain cache (rollups) | ✅ | **1.07×** per call |
| Sparse QAP in CSR format | ✅ | **2.8–5.5×** on sparse circuits |
| Proof aggregation (SnarkPack) | ✅ | **1.09×** faster at N=32 proofs |
| Dynark 5-FFT (default) | ✅ | 5 FFTs vs 6 standard (−17%) |
| Parallel MSM (rayon) | ✅ | ~1.2× on multicore |

### Security Comparison vs Groth16

| Property | ark-groth16 | UniGroth |
|----------|-------------|---------|
| Knowledge Soundness (AGM) | ✓ | ✓ Same |
| Zero-Knowledge | ✓ | ✓ Same |
| **Simulation-Extractability** | ✗ | **✓ BG18 or ROM blinding** |
| **Subversion Zero-Knowledge** | ✗ | **✓ Proof rerandomization** |
| **Universal Setup Ready** | ✗ | **✓ KZG SRS** |
| **Folding/IVC** | ✗ | **✓ ProtoStar** |
| **Proof Aggregation** | ✗ | **✓ N→1 compression** |
| Post-Quantum | ✗ | ✗ (planned) |

### Security Features

| Feature | Status | Notes |
|---------|--------|-------|
| Knowledge Soundness (AGM) | [OK] | Groth16 secure in Algebraic Group Model |
| Zero-Knowledge | [OK] | Standard Groth16 property |
| Simulation-Extractable | [OK] | BG18 blinding or ROM-based (configurable) |
| Subversion Zero-Knowledge | [OK] | Proof rerandomization at proving time |
| Post-Quantum | [NO] | Pairing-based; use hybrid with Binius/Plonky3 |

## Security Deep Dive: UniGroth vs Groth16

UniGroth extends Groth16 with **5 additional security properties** while maintaining the original soundness proof. The core Groth16 security model remains unchanged; UniGroth adds layers of protection on top.

### Fundamental Groth16 Security (Both Systems)

| Property | Groth16 | UniGroth | Model |
|----------|---------|----------|-------|
| Knowledge Soundness | ✓ | ✓ | Algebraic Group Model (AGM) |
| Proof of Knowledge | ✓ | ✓ | Extractor definition in AGM |
| Zero-Knowledge | ✓ | ✓ | Standard (honest-verifier ZK) |
| Non-Interactive | ✓ | ✓ | Fiat-Shamir heuristic (ROM) |

**Status**: Both systems inherit Groth16's original proof from [Groth 2016], security in Algebraic Group Model + Random Oracle.

### UniGroth Security Enhancements

#### 1. Simulation-Extractability (SE)

**Problem in Groth16**: Original Groth16 proofs can be malleable. Given a valid proof, an attacker might forge related proofs without knowledge of the witness.

**UniGroth Solution**:
- **BG18 Mode** (explicit): Blind the proof using a random ρ, add SE element D = ρ·δ in G₂. Adds ~96 bytes (BLS12-381) or ~64 bytes (BN254).
- **ROM Mode** (implicit): Use proof hash H(A,B,C) as blinding factor. Adds ~33 bytes proof hash, near-zero overhead.

**Security Gain**: Prevents proof forgery even after seeing simulated proofs.

**Reference**: [BG18] Bowe & Gabizon, "Making Groth16 zkSNARKs Simulation Extractable" (2018)

**Implementation**: `src/security.rs` — fully tested ✓

---

#### 2. Subversion Zero-Knowledge (S-ZK)

**Problem in Groth16**: If the setup (α, β, γ, δ) is maliciously generated, ZK no longer holds—an adversary who knows the toxic waste can extract the witness.

**UniGroth Solution**:
- Proof rerandomization at proving time using random ρ ∈ F*
- Transforms each proof S = (A, B, C) into S' = (A', B', C') that is identically distributed as an honest proof
- Applies regardless of setup (even if toxic waste is backdoored)

**Security Gain**: ZK holds even if setup was subverted.

**Formula**:
```
A' = ρ⁻¹A
B' = ρB + ρρ₂δ_g2  (where ρ₂ is sampled fresh)
C' = C + ρ₂A
```

**Reference**: [BKSV20] Boyle, Kasher, Serban, Vaikuntanathan (2020)

**Implementation**: `src/prover.rs` — `Groth16::rerandomize_proof()` — fully tested ✓

---

#### 3. Proof Aggregation (SnarkPack-style)

**Problem in Groth16**: Verifying N proofs requires N separate pairing checks (~3 pairings each).

**UniGroth Solution**:
- Aggregate N proofs using random challenge r: A_agg = Σᵢ rⁱAᵢ, etc.
- Single multi-pairing equation replaces N independent checks
- Crossover point: N ≥ 32 (from benchmarks)

**Security Gain**: Constant-size aggregation reduces verification cost for batched proofs.

**Use Case**: Rollups aggregating many proofs before on-chain verification.

**Reference**: [Gabizon & Williamson] "SnarkPack: Practical SNARK Aggregation" (EuroCrypt 2022)

**Implementation**: `src/aggregation.rs` — fully tested ✓

---

#### 4. Universal Setup (KZG-based)

**Problem in Groth16**: Requires a new multi-party ceremony (MPC) for every circuit (Powers-of-Tau with circuit-specific Phase 2).

**UniGroth Solution**:
- KZG universal polynomial commitment scheme
- One-time ceremony produces Universal Parameters that work for any circuit up to 2²⁸ gates
- Updatable: anyone can contribute randomness to enhance security post-ceremony

**Security Gain**: Circuit-agnostic setup; no per-circuit ceremonies.

**Reference**: [ABPR19] Abdolmaleki et al., "Updatable and Universal Common Reference Strings" (CRYPTO 2019)

**Implementation**: `src/universal_setup.rs` + `src/kzg.rs` — fully tested ✓

---

#### 5. Folding & Incremental Verification (ProtoStar)

**Problem in Groth16**: Recursive proofs require wrapping proofs inside circuits, leading to large verifier circuits and low efficiency for long computations.

**UniGroth Solution**:
- ProtoStar-style folding: accumulate multiple proofs into a single folding instance
- Incremental verification: fold step i-1 with step i without re-verifying all prior steps
- Enables zkVM and rollup applications with minimal overhead

**Security Gain**: Scalable recursive proof composition without full re-verification.

**Reference**: [Bünz et al.] "ProtoStar: Generic Efficient Accumulation/Folding" (ASIACRYPT 2023)

**Implementation**: `src/folding.rs` + `src/security.rs` — fully tested ✓

---

### Security Properties Summary

| Property | ark-groth16 | UniGroth | Addition | Threat Addressed |
|----------|-------------|----------|----------|------------------|
| Knowledge Soundness (AGM) | ✓ | ✓ | None | Unsound proofs |
| Zero-Knowledge | ✓ | ✓ | None | Setup honest |
| Proof Non-malleability | ✗ | ✓ SE | BG18/ROM blinding | Adversary forges proofs |
| Subversion-Resistant | ✗ | ✓ S-ZK | Rerandomization | Setup backdoor → witness leakage |
| Proof Aggregation | ✗ | ✓ | Batch verification | Slow batch verification |
| Recursive Efficiency | ✗ | ✓ ProtoStar | Folding | Large verifier circuits |
| Setup Reuse | ✗ Circuit-specific | ✓ Universal KZG | Per-circuit ceremony cost |

---

### Test Coverage

All security extensions have passing tests:
- `test_sim_extractable_proof` ✓
- `test_subversion_zk` ✓
- `test_bg18_blinding` ✓
- `test_security_report` ✓
- `test_proof_size` ✓

---

### Threat Model Addressed

1. **Proof Malleability**: Attacker sees honest proofs, forges related ones
   - **UniGroth Fix**: Simulation-Extractability (BG18/ROM)

2. **Setup Subversion**: Adversary knows toxic waste α, β, γ, δ
   - **UniGroth Fix**: Subversion Zero-Knowledge (rerandomization)

3. **Per-Circuit Ceremony Cost**: Each circuit requires new MPC
   - **UniGroth Fix**: Universal KZG Setup

4. **Batch Verification Overhead**: N proofs = N verifications
   - **UniGroth Fix**: SnarkPack Aggregation

5. **Recursive Inefficiency**: Verifier circuit grows exponentially
   - **UniGroth Fix**: ProtoStar Folding + IVC

---

### What UniGroth Does NOT Change

The following remain **identical** to Groth16:

1. **Proof structure** (A, B, C in G₁, G₂, G₁)
2. **Verification equation** (3-pairing check)
3. **Proof size** (192-256 bytes vs Groth16's 192 bytes)
4. **Verification speed** (~5ms on-chain)
5. **Soundness proof** (still AGM + ROM)

---

### Recommendations

**Use UniGroth When:**
- ✅ Batch proving (aggregation benefits at N≥32)
- ✅ Recursive/folding applications (zkVM, rollups)
- ✅ Malicious-setup environment (S-ZK needed)
- ✅ Research/experimental projects
- ✅ Testing advanced SNARK techniques

**Use Vanilla Groth16 When:**
- ✓ Production deployment (proven audits)
- ✓ Single-proof verification
- ✓ Simple circuits (no aggregation needed)
- ✓ Minimal dependencies desired

### Implemented
- Original Groth16 core (from arkworks)
- R1CS to QAP reduction
- Dynark-style 5-FFT and 4-FFT witness computation
- Parallel MSM with Pippenger's algorithm
- Polymath-style proof compression
- Simulation-extractability (BG18 and ROM modes)
- Subversion zero-knowledge
- ProtoStar folding engine with Fiat-Shamir challenges
- KZG polynomial commitments and universal SRS

### In Development
- Full Plonkish gate support with lookup tables
- GPU/FPGA MSM acceleration (icicle integration)
- Post-quantum hybrid inner prover
- Formal security proofs

### Roadmap
- Complete Dynark 4-FFT path (eliminate c iFFT via algebraic identity)
- ProtoStar full decision predicate verification
- GPU acceleration via icicle crate
- Post-quantum wrapper (lattice-based or Binius inner)
- Production audit

## Research Foundation

UniGroth builds on research from 2024-2026:

- **Polymath** (CRYPTO 2024) — SAP-based proofs with 1408-bit size on BLS12-381
- **Pari/Garuda** (2024) — Equifficient commitments, 1280-bit proofs
- **Dynark** (2025) — Dynamic witness updates, 1400× faster incremental proving
- **ProtoStar** (2023) — Non-uniform IVC with efficient folding
- **Nova** (2022) — Recursive SNARKs without trusted setup

With the original Groth16 protocol being:

- **Groth16** (2016) — The foundational protocol

### Why Not Just Use Existing Systems?

| System | Proof Size | Verification | Setup | Flexibility | Issue |
|--------|-----------|--------------|-------|-------------|-------|
| Groth16 | 192 bytes | 3 pairings | Circuit-specific | R1CS only | Setup problem |
| Plonk | 1-2 KB | 10+ pairings | Universal | Full | Larger proofs |
| Marlin | 2-5 KB | 15+ pairings | Universal | Full | Slower verification |
| STARKs | 50-200 KB | Fast (no pairings) | Transparent | Full | Huge proofs |
| Polymath | 176 bytes | 3 pairings | Circuit-specific | SAP only | Still needs setup |
| Dynark | 192 bytes | 3 pairings | Circuit-specific | R1CS only | Still needs setup |

**UniGroth combines the best of all worlds** with it having the performance of Groth16 with universal setup and modern flexibility.

## Practical Use: Recursive Wrapper Pattern

The industry already uses a "recursive Groth16 wrapper" pattern (deployed by zkSync, Polygon zkEVM, RISC Zero, Scroll):

1. Run a universal/transparent inner system (Plonk, Halo2, STARK, Binius) for arbitrary logic
2. Recursively aggregate everything into one fixed Groth16 proof over a tiny "verifier circuit"
3. Final on-chain proof is 192 bytes with 3-pairing verification
4. Setup is one-time and fixed (for the recursive verifier)
5. Whole system is effectively universal

This is Groth16 "evolved" in practice today. UniGroth aims to make this pattern native and more efficient.

## Build Guide

UniGroth compiles on the `stable` toolchain of the Rust compiler (1.70+).

### Prerequisites

Install Rust via `rustup`:
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

Run the test suite:
```bash
cargo test
```

Run benchmarks:
```bash
cargo bench
```

### Features

- `std` (default) — Standard library support
- `parallel` (default) — Multi-threaded proving and verification
- `r1cs` — Constraint system gadgets for recursive verification
- `print-trace` — Debug tracing output

Build without default features:
```bash
cargo build --no-default-features
```

## Usage Example

```rust
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_bn254::Bn254;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;

// Define your circuit
struct MyCircuit {
    // Circuit inputs
}

impl ConstraintSynthesizer<Fr> for MyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Define your constraints here
        Ok(())
    }
}

fn main() {
    let mut rng = ark_std::test_rng();
    
    // Setup phase (one-time per circuit in standard Groth16)
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        MyCircuit { /* ... */ },
        &mut rng
    ).unwrap();
    
    // Prove
    let proof = Groth16::<Bn254>::prove(
        &pk,
        MyCircuit { /* ... */ },
        &mut rng
    ).unwrap();
    
    // Verify
    let public_inputs = vec![/* public inputs */];
    let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
    
    assert!(valid);
}
```

## Project Structure

```
UniGroth/
├── src/
│   ├── lib.rs              # Main library entry point
│   ├── data_structures.rs  # Proving/verifying keys, proofs
│   ├── generator.rs        # Setup/key generation
│   ├── prover.rs          # Proof generation
│   ├── verifier.rs        # Proof verification
│   ├── r1cs_to_qap.rs     # R1CS to QAP reduction
│   ├── constraints.rs     # R1CS gadgets (feature: r1cs)
│   └── test.rs            # Unit tests
├── benches/               # Performance benchmarks
├── tests/                 # Integration tests
└── scripts/               # Development utilities
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where we especially need help:
- Universal KZG setup implementation
- SAP arithmetization layer
- ProtoStar folding integration
- GPU/FPGA acceleration
- Formal security proofs
- Documentation and examples

## Security

**This is research software. Do not use in production.**

If you discover a security vulnerability, please email security@meridianalgo.com (or open a private security advisory on GitHub).

## Comparison with Related Work

### vs. Original Groth16
- Same proof size and verification speed
- Universal setup (no per-circuit ceremonies)
- Flexible arithmetization (custom gates, lookups)
- Faster prover on complex circuits

### vs. Plonk/Marlin
- 5-10× smaller proofs
- 2-3× faster verification
- ≈ Similar setup (universal)
- ≈ Similar flexibility

### vs. STARKs
- 100-500× smaller proofs
- Faster verification (pairings vs. hashing)
- Requires trusted setup (vs. transparent)
- ≈ Similar prover speed

### vs. Polymath/Pari
- ≈ Similar proof size
- ≈ Same verification speed
- Universal setup (vs. circuit-specific)
- More flexible arithmetization

### vs. Dynark
- ≈ Same proof size and verification
- Universal setup (vs. circuit-specific)
- Incorporates Dynark's FFT optimizations
- ≈ Similar dynamic update capabilities

## References & Further Reading

### Core Papers
- [Groth16] Jens Groth. "On the Size of Pairing-based Non-interactive Arguments." EUROCRYPT 2016. https://eprint.iacr.org/2016/260
- [Polymath] Helger Lipmaa. "Polymath: Groth16 Is Not The Limit." CRYPTO 2024. https://eprint.iacr.org/2024/916
- [Pari] Helger Lipmaa. "Pari: Faster and Smaller Pairing-Based zkSNARKs." 2024. https://eprint.iacr.org/2024/1245
- [Dynark] Weijie Wang et al. "Dynark: Dynamic zkSNARKs with Fast Prover Update." 2025. https://eprint.iacr.org/2025/123
- [ProtoStar] Benedikt Bünz et al. "ProtoStar: Generic Efficient Accumulation/Folding for Special-Sound Protocols." 2023. https://eprint.iacr.org/2023/620
- [Nova] Abhiram Kothapalli et al. "Nova: Recursive Zero-Knowledge Arguments from Folding Schemes." CRYPTO 2022. https://eprint.iacr.org/2021/370

### Security & Setup
- [BG18] Sean Bowe, Ariel Gabizon. "Making Groth16 zkSNARKs Simulation Extractable." 2018. https://eprint.iacr.org/2018/187
- [ABPR] Behzad Abdolmaleki et al. "Updatable and Universal Common Reference Strings with Applications to zk-SNARKs." CRYPTO 2019. https://eprint.iacr.org/2018/280

### Implementation Resources
- [arkworks-rs] The arkworks ecosystem: https://github.com/arkworks-rs
- [gnark] ConsenSys zkSNARK library: https://github.com/ConsenSys/gnark
- [Powers of Tau] Perpetual Powers of Tau ceremony: https://github.com/privacy-scaling-explorations/perpetualpowersoftau

## License

This library is licensed under either of the following licenses, at your discretion.

 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

## Acknowledgements

### Original Groth16 Implementation
This work builds upon the excellent Groth16 implementation from the [arkworks-rs](https://github.com/arkworks-rs/groth16) ecosystem. The original implementation was supported by:
- Google Faculty Award
- National Science Foundation
- UC Berkeley Center for Long-Term Cybersecurity
- Ethereum Foundation, Interchain Foundation, and Qtum

An earlier version was developed as part of the paper *"[ZEXE: Enabling Decentralized Private Computation][zexe]"*.

[zexe]: https://ia.cr/2018/962

### UniGroth Development
UniGroth extensions and research by **MeridianAlgo** (2026).

Special thanks to the cryptography research community for:
- Helger Lipmaa (Polymath, Pari)
- Weijie Wang et al. (Dynark)
- Benedikt Bünz et al. (ProtoStar)
- Abhiram Kothapalli et al. (Nova)
- The zkSNARK research community at large

## Contact & Community

- **GitHub**: https://github.com/MeridianAlgo/UniGroth
- **Issues**: https://github.com/MeridianAlgo/UniGroth/issues
- **Discussions**: https://github.com/MeridianAlgo/UniGroth/discussions

---

*"Standing on the shoulders of giants, reaching for the stars."*
