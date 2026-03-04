# UniGroth Project Summary

**Version**: 0.1.0  
**Date**: March 2026  
**Author**: MeridianAlgo  
**Based on**: arkworks-rs/groth16

## What is UniGroth?

UniGroth is a next-generation zkSNARK framework that evolves Groth16 into a universal, flexible, and more powerful proof system while maintaining its legendary 192-byte proofs and 3-pairing verification speed.

## The Problem with Groth16

Groth16 (2016) is the gold standard for zkSNARKs with the smallest proofs and fastest verification, but it has critical limitations:

1. **Circuit-specific trusted setup** - Every new circuit requires a new multi-party computation ceremony
2. **No flexibility** - Locked into R1CS, no custom gates or lookup tables
3. **Prover inefficiency** - Slower than modern systems on complex circuits
4. **Limited security** - Not simulation-extractable or subversion-resistant by default

## The UniGroth Solution

UniGroth addresses all these issues while keeping Groth16's strengths:

### Key Innovations

1. **Universal Setup** (Phase 2)
   - One-time Powers-of-Tau ceremony
   - Works for any circuit up to 2²⁸ gates
   - Updatable for enhanced security
   - No more per-circuit ceremonies

2. **Flexible Arithmetization** (Phase 3-4)
   - Square Arithmetic Programs (SAP) from Polymath/Pari
   - Full Plonkish gates with custom operations
   - Lookup tables for efficient range checks and bitwise ops
   - 2-5× smaller effective circuit size

3. **Maintained Performance** (Phase 5)
   - Proof size: 192-256 bytes (same as Groth16)
   - Verification: 3-5 pairings (~5-7ms, same gas cost)
   - Prover: 2-5× faster on real-world circuits
   - Dynark-style FFT optimizations

4. **Folding & Recursion** (Phase 6)
   - ProtoStar/Nova integration
   - Efficient proof aggregation
   - IVC for zkVMs and rollups
   - Minimal recursive overhead

5. **Enhanced Security** (Phase 7)
   - Simulation-extractability (SE)
   - Subversion zero-knowledge (S-ZK)
   - AGM + ROM security proofs
   - Optional post-quantum path

6. **Hardware Acceleration** (Phase 8)
   - GPU-optimized MSMs
   - FPGA support
   - Parallel proving
   - ASIC-friendly design

## Current Status (v0.1.0)

✅ **Completed**:
- Forked and rebranded from arkworks Groth16
- Updated all documentation
- Established project structure
- All tests passing
- Release build working

🚧 **In Development**:
- Universal KZG setup layer
- SAP arithmetization
- ProtoStar folding integration
- Performance benchmarks

📋 **Planned**:
- Full Plonkish gates
- Lookup tables
- GPU acceleration
- Post-quantum hybrid mode
- Production audit

## Performance Comparison

| System | Proof Size | Verification | Setup | Flexibility | Status |
|--------|-----------|--------------|-------|-------------|--------|
| Groth16 | 192 bytes | 3 pairings | Circuit-specific | R1CS only | Production |
| UniGroth | 192-256 bytes | 3-5 pairings | Universal | Full | Development |
| Plonk | 1-2 KB | 10+ pairings | Universal | Full | Production |
| Marlin | 2-5 KB | 15+ pairings | Universal | Full | Production |
| STARKs | 50-200 KB | Fast | Transparent | Full | Production |

**UniGroth combines the best of all worlds.**

## Research Foundation

UniGroth builds on breakthrough research:

- **Groth16** (2016) - The foundational protocol
- **Polymath** (CRYPTO 2024) - SAP-based 176-byte proofs
- **Pari/Garuda** (2024) - Equifficient commitments, 160-byte proofs
- **Dynark** (2025) - Dynamic witness updates, 1400× faster incremental proving
- **ProtoStar** (2023) - Non-uniform IVC with efficient folding
- **Nova** (2022) - Recursive SNARKs without trusted setup

## Use Cases

UniGroth is ideal for:

- **zkRollups** - Ethereum L2 scaling with minimal on-chain cost
- **zkVMs** - General-purpose verifiable computation
- **Private DeFi** - Confidential transactions and trading
- **Identity Systems** - Privacy-preserving authentication
- **Supply Chain** - Verifiable provenance without revealing details
- **ML Inference** - Prove correct model execution
- **Cross-chain Bridges** - Trustless asset transfers

## Development Roadmap

**24-month plan** organized in 10 phases:

- **Months 1-2**: Foundation (current)
- **Months 3-4**: Universal setup
- **Months 5-6**: SAP arithmetization
- **Months 7-8**: Plonkish gates & lookups
- **Months 9-10**: Compression & proof generation
- **Months 11-12**: Folding & recursion
- **Months 13-14**: Security enhancements
- **Months 15-16**: Hardware acceleration
- **Months 17-18**: Post-quantum path
- **Months 19-24**: Production readiness

See [ROADMAP.md](ROADMAP.md) for details.

## Technical Architecture

```
Application Layer (Circuits)
         ↓
Arithmetization (R1CS/SAP/Plonkish)
         ↓
Polynomial Commitments (KZG)
         ↓
Folding/IVC (ProtoStar/Nova)
         ↓
Compression (Groth16-style)
         ↓
Final Proof (192-256 bytes)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

## Getting Started

### Quick Install

```bash
# Add to Cargo.toml
[dependencies]
unigroth = { git = "https://github.com/MeridianAlgo/UniGroth.git" }
```

### Simple Example

```rust
use unigroth::Groth16;
use ark_bn254::Bn254;

// Setup
let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;

// Prove
let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;

// Verify
let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;
```

See [QUICKSTART.md](QUICKSTART.md) for complete examples.

## Documentation

- **[README.md](README.md)** - Project overview and vision
- **[QUICKSTART.md](QUICKSTART.md)** - Get started in minutes
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical deep dive
- **[ROADMAP.md](ROADMAP.md)** - Development plan
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute
- **[CHANGELOG.md](CHANGELOG.md)** - Version history

## Contributing

We welcome contributions! Priority areas:

- Universal setup implementation
- SAP arithmetization
- Folding scheme integration
- GPU acceleration
- Testing and benchmarking
- Documentation and examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

⚠️ **This is research software. Do not use in production.**

Current status:
- Based on audited arkworks Groth16 implementation
- No security audit for UniGroth extensions yet
- Planned comprehensive audit before v1.0

Report vulnerabilities: security@meridianalgo.com

## License

Dual-licensed under MIT and Apache 2.0, same as the original arkworks implementation.

## Acknowledgements

### Original Implementation
Built on the excellent Groth16 implementation from [arkworks-rs](https://github.com/arkworks-rs/groth16), supported by:
- Google Faculty Award
- National Science Foundation
- UC Berkeley Center for Long-Term Cybersecurity
- Ethereum Foundation, Interchain Foundation, Qtum

### UniGroth Development
Extended by **MeridianAlgo** (2026) with inspiration from:
- Helger Lipmaa (Polymath, Pari)
- Weijie Wang et al. (Dynark)
- Benedikt Bünz et al. (ProtoStar)
- Abhiram Kothapalli et al. (Nova)
- The broader zkSNARK research community

## Contact

- **GitHub**: https://github.com/MeridianAlgo/UniGroth
- **Issues**: https://github.com/MeridianAlgo/UniGroth/issues
- **Discussions**: https://github.com/MeridianAlgo/UniGroth/discussions

## Vision

UniGroth aims to become the default zkSNARK for production systems by 2027, combining:
- Groth16's legendary performance
- Universal setup convenience
- Modern flexibility and features
- Enhanced security guarantees
- Production-grade implementation

**Standing on the shoulders of giants, reaching for the stars.**

---

*Last Updated: March 2026*
