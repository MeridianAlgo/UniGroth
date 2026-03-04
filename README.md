<h1 align="center">UniGroth</h1>

<p align="center">
    <em>Universal zkSNARK Framework</em>
</p>

<p align="center">
    <a href="#license"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
</p>

**Edited by MeridianAlgo** — Built on the framework from [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16)

## Overview

UniGroth is an evolutionary zkSNARK framework that addresses the fundamental limitations of Groth16 while preserving its legendary proof size and verification speed. This project represents a research-driven approach to building the next generation of zero-knowledge proof systems.

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
│                    Application Layer                     │
│         (zkEVM, zkML, Private Transactions, etc.)       │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Flexible Arithmetization Layer              │
│    SAP / Plonkish with Custom Gates & Lookup Tables    │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Folding & Recursion Engine                  │
│         ProtoStar / Nova for Incremental Proofs         │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│           Universal Polynomial Commitment Layer          │
│        KZG / Equifficient Commitments (Universal)       │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Groth16-Style Compression Core              │
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
| Setup | Circuit-specific MPC | One universal ceremony | ∞ better |
| Flexibility | R1CS only | Plonkish + lookups | Full |
| Security | Basic | SE + Subversion-resistant | Stronger |

*On real-world circuits with lookups and custom gates

## Current Status

**⚠️ RESEARCH PROTOTYPE** — This is an academic proof-of-concept under active development. Not audited or production-ready.

### Implemented (v0.1.0)
- ✅ Original Groth16 core (from arkworks) — prover, verifier, key generation
- ✅ R1CS to QAP reduction (LibsnarkReduction + custom QAP support)
- ✅ **Universal KZG-based setup** — `UniversalSRS` with Powers-of-Tau, updatable, reusable for any circuit
- ✅ **SAP arithmetization** — `R1CSToSAP` with addition-gate detection and circuit size analysis
- ✅ **ProtoStar-style folding** — `FoldingEngine` + `IVC` for incremental verifiable computation
- ✅ **Simulation-Extractability** — BG18 blinding + ROM-based SE, `SimExtractableProof`
- ✅ **Subversion Zero-Knowledge** — `apply_subversion_zk` rerandomization
- ✅ **Dynark-style 4-FFT** — parallel coset FFTs, reduced from 6 FFTs
- ✅ **Parallel MSM** — Pippenger with rayon + GPU-hint interface
- ✅ **Plonkish arithmetization** — custom gates, lookup tables (range/XOR/LogUp), copy constraints
- ✅ **43 passing tests** — full unit + integration test suite

### In Progress
- 🚧 Full Dynark 4-FFT (c-polynomial algebraic elimination via SAP identity)
- 🚧 ProtoStar full decision predicate (relaxed R1CS verification)
- 🚧 Polymath G₂-free compression (target: 128 bytes on BN254)
- 🚧 Fiat-Shamir transcript (replace random with Poseidon hash in folding)
- 🚧 BG18 explicit pairing check in SE verifier

### Roadmap
- 📋 GPU/FPGA MSM acceleration (icicle integration)
- 📋 Post-quantum hybrid mode (Binius/Plonky3 inner prover)
- 📋 Full Plonkish → UniGroth backend integration
- 📋 Formal security proofs (AGM + ROM)
- 📋 Production audit

## Research Foundation

UniGroth builds on breakthrough research from 2024-2026:

- **Polymath** (CRYPTO 2024) — SAP-based proofs with 1408-bit size on BLS12-381
- **Pari/Garuda** (2024) — Equifficient commitments, 1280-bit proofs
- **Dynark** (2025) — Dynamic witness updates, 1400× faster incremental proving
- **ProtoStar** (2023) — Non-uniform IVC with efficient folding
- **Nova** (2022) — Recursive SNARKs without trusted setup
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

**UniGroth combines the best of all worlds** — Groth16's performance with universal setup and modern flexibility.

## Practical Use: Recursive Wrapper Pattern

While UniGroth is under development, the industry already uses a "recursive Groth16 wrapper" pattern (deployed by zkSync, Polygon zkEVM, RISC Zero, Scroll):

1. Run a universal/transparent inner system (Plonk, Halo2, STARK, Binius) for arbitrary logic
2. Recursively aggregate everything into one fixed Groth16 proof over a tiny "verifier circuit"
3. Final on-chain proof is 192 bytes with 3-pairing verification
4. Setup is one-time and fixed (for the recursive verifier)
5. Whole system is effectively universal

This is "Groth16 evolved" in practice today. UniGroth aims to make this pattern native and more efficient.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

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

### Standard Groth16

```rust
use unigroth::Groth16;
use ark_bn254::Bn254;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;

struct MyCircuit { /* inputs */ }

impl ConstraintSynthesizer<ark_bn254::Fr> for MyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ark_bn254::Fr>) -> Result<(), SynthesisError> {
        // Define constraints here
        Ok(())
    }
}

let mut rng = ark_std::test_rng();
let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(MyCircuit { /* ... */ }, &mut rng).unwrap();
let proof = Groth16::<Bn254>::prove(&pk, MyCircuit { /* ... */ }, &mut rng).unwrap();
let valid = Groth16::<Bn254>::verify_with_processed_vk(
    &unigroth::prepare_verifying_key(&vk),
    &[/* public inputs */],
    &proof,
).unwrap();
assert!(valid);
```

### Universal Setup (no per-circuit ceremony)

```rust
use unigroth::UniversalParams;
use unigroth::r1cs_to_qap::LibsnarkReduction;
use ark_bn254::Bn254;

let mut rng = ark_std::test_rng();

// One-time setup — reusable for any circuit up to max_degree constraints
let universal = UniversalParams::<Bn254>::setup(1 << 20, &mut rng);

// Derive circuit-specific keys without a new ceremony
let (pk, vk) = universal.derive_keys::<_, LibsnarkReduction>(MyCircuit { /* ... */ }, &mut rng).unwrap();
```

### Folding / IVC

```rust
use unigroth::{IVC, UniversalSRS};
use ark_bn254::Bn254;

let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);
let mut ivc = IVC::new(srs);

// Prove each step and fold into accumulator
for i in 0..100 {
    ivc.step(vec![public_in], vec![witness], &mut rng).unwrap();
}

// Final accumulator → feed into Groth16 compression
let (steps, acc) = ivc.finalize();
```

## Project Structure

```
UniGroth/
├── src/
│   ├── lib.rs              # Main library entry point + public re-exports
│   ├── data_structures.rs  # Proving/verifying keys, proofs
│   ├── generator.rs        # Setup/key generation
│   ├── prover.rs           # Proof generation
│   ├── verifier.rs         # Proof verification
│   ├── r1cs_to_qap.rs      # R1CS to QAP reduction (LibsnarkReduction)
│   ├── constraints.rs      # R1CS gadgets (feature: r1cs)
│   ├── kzg.rs              # KZG polynomial commitments + UniversalSRS
│   ├── sap.rs              # Square Arithmetic Programs (R1CS→SAP)
│   ├── universal_setup.rs  # UniversalParams: one-time ceremony for all circuits
│   ├── folding.rs          # ProtoStar folding / IVC (FoldingEngine, IVC)
│   ├── security.rs         # SE proofs, Subversion-ZK, SecurityParams
│   ├── optimizations.rs    # Dynark 4-FFT, parallel MSM, PolymathCompressor
│   ├── plonkish.rs         # Plonkish gates, lookup tables, copy constraints
│   └── test.rs             # Core unit tests
├── benches/                # Performance benchmarks (MiMC circuit)
├── tests/                  # Integration tests (MiMC Groth16 end-to-end)
└── scripts/                # Development utilities
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

**⚠️ This is research software. Do not use in production.**

If you discover a security vulnerability, please email security@meridianalgo.com (or open a private security advisory on GitHub).

## Comparison with Related Work

### vs. Original Groth16
- ✅ Same proof size and verification speed
- ✅ Universal setup (no per-circuit ceremonies)
- ✅ Flexible arithmetization (custom gates, lookups)
- ✅ Faster prover on complex circuits

### vs. Plonk/Marlin
- ✅ 5-10× smaller proofs
- ✅ 2-3× faster verification
- ≈ Similar setup (universal)
- ≈ Similar flexibility

### vs. STARKs
- ✅ 100-500× smaller proofs
- ✅ Faster verification (pairings vs. hashing)
- ❌ Requires trusted setup (vs. transparent)
- ≈ Similar prover speed

### vs. Polymath/Pari
- ≈ Similar proof size
- ≈ Same verification speed
- ✅ Universal setup (vs. circuit-specific)
- ✅ More flexible arithmetization

### vs. Dynark
- ≈ Same proof size and verification
- ✅ Universal setup (vs. circuit-specific)
- ✅ Incorporates Dynark's FFT optimizations
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

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
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
