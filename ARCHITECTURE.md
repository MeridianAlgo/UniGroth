# UniGroth Architecture

This document describes the technical architecture of UniGroth, both current implementation and planned evolution.

## Current Architecture (v0.1.0)

UniGroth currently implements the standard Groth16 protocol from the 2016 paper. The codebase is organized as follows:

### Core Modules

#### `data_structures.rs`
Defines the fundamental types used throughout the system:
- `ProvingKey<E>` - Contains the circuit-specific parameters for proof generation
- `VerifyingKey<E>` - Contains the public parameters for proof verification
- `Proof<E>` - The zkSNARK proof (3 group elements: A, B, C)
- `PreparedVerifyingKey<E>` - Preprocessed verification key for faster verification

#### `generator.rs`
Implements the trusted setup ceremony:
- `generate_random_parameters()` - Creates proving and verifying keys
- Uses toxic waste (α, β, γ, δ, τ) to generate the SRS
- Circuit-specific: must be run for each new circuit

#### `prover.rs`
Implements proof generation:
- `create_random_proof()` - Main proving algorithm
- Computes witness assignment
- Evaluates QAP polynomials
- Performs multi-scalar multiplications (MSMs)
- Adds zero-knowledge randomness

#### `verifier.rs`
Implements proof verification:
- `verify_proof()` - Main verification algorithm
- Performs 3 pairing checks
- Validates public inputs
- ~5ms verification time

#### `r1cs_to_qap.rs`
Converts R1CS constraints to Quadratic Arithmetic Programs:
- `LibsnarkReduction` - Standard reduction algorithm
- Converts constraint system to polynomial form
- Extensible for custom reductions (future: SAP)

#### `constraints.rs` (feature: `r1cs`)
R1CS gadgets for recursive verification:
- Verifier circuit for proof composition
- Used in recursive SNARK constructions

### Data Flow

```
Circuit Definition
       ↓
   [Generator]
       ↓
   ProvingKey + VerifyingKey
       ↓
   [Prover]                    [Verifier]
       ↓                            ↓
   Proof  ──────────────────────→  bool
```

### Cryptographic Primitives

- **Elliptic Curves**: BN254, BLS12-381, BLS12-377, BW6-761, MNT4-298
- **Pairings**: Optimal Ate pairing
- **Field Arithmetic**: Provided by arkworks-algebra
- **Polynomial Operations**: FFT-based multiplication

## Planned Architecture (v1.0)

### Layered Design

```
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                       │
│              (Circuit Definitions)                       │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│              Arithmetization Layer                       │
│         (R1CS / SAP / Plonkish)                         │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│           Polynomial Commitment Layer                    │
│              (KZG / Equifficient)                       │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│              Folding/IVC Layer                          │
│            (ProtoStar / Nova)                           │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│           Compression Layer                             │
│        (Groth16-style encoding)                         │
└─────────────────────────────────────────────────────────┘
                         ↓
                    Final Proof
```

### New Modules (Planned)

#### `universal_setup.rs`
Universal trusted setup:
- Powers-of-Tau integration
- KZG commitment scheme
- Updatable SRS
- One-time ceremony for all circuits

#### `sap.rs`
Square Arithmetic Program support:
- SAP constraint system
- Optimized for addition-heavy circuits
- 2-3× smaller than R1CS for typical circuits

#### `plonkish.rs`
Flexible gate system:
- Custom gate API
- Lookup tables
- Standard gate library (range checks, bitwise ops)
- Gate composition framework

#### `folding.rs`
Incremental verification:
- ProtoStar folding scheme
- Nova IVC integration
- Recursive proof composition
- Efficient aggregation

#### `compression.rs`
Proof size optimization:
- Polymath-style G₂ replacement
- Equifficient commitments
- 192-256 byte final proofs

#### `security.rs`
Enhanced security features:
- Simulation-extractability
- Subversion zero-knowledge
- Random oracle blinding
- Security parameter configuration

#### `acceleration/`
Hardware acceleration:
- `gpu.rs` - GPU MSM and FFT
- `fpga.rs` - FPGA acceleration
- `parallel.rs` - Multi-core optimization

### Setup Ceremony Evolution

**Current (Groth16)**:
```
Circuit → Toxic Waste → Circuit-Specific SRS → Keys
```

**Future (UniGroth)**:
```
Powers-of-Tau (one-time) → Universal SRS
                              ↓
                         Any Circuit → Keys
```

### Proof Generation Evolution

**Current**:
1. Witness computation
2. R1CS to QAP reduction
3. Polynomial evaluation
4. MSM for A, B, C
5. Add randomness

**Future**:
1. Witness computation
2. Flexible arithmetization (SAP/Plonkish)
3. Polynomial commitment
4. Folding (if recursive)
5. Final compression
6. Enhanced randomness (SE)

### Performance Targets

| Component | Current | Target | Method |
|-----------|---------|--------|--------|
| Setup | Circuit-specific | Universal | KZG + PoT |
| Prover | Baseline | 2-5× faster | SAP + lookups + GPU |
| Proof Size | 192 bytes | 192-256 bytes | Polymath compression |
| Verifier | 3 pairings | 3-5 pairings | Maintained |
| Memory | Baseline | 30% less | Optimized layout |

## Security Model

### Current (Groth16)

**Assumptions**:
- Generic Group Model (GGM)
- Knowledge of Exponent (KEA)
- Trusted setup (toxic waste destroyed)

**Properties**:
- Zero-knowledge
- Knowledge soundness
- Succinctness

### Future (UniGroth)

**Additional Assumptions**:
- Algebraic Group Model (AGM) - weaker than GGM
- Random Oracle Model (ROM) - for SE
- KZG security (q-SDH)

**Enhanced Properties**:
- Simulation-extractability (SE)
- Subversion zero-knowledge (S-ZK)
- Universal composability
- Optional post-quantum security

## Compatibility

### Backward Compatibility

UniGroth maintains API compatibility with standard Groth16:
```rust
// Works with both Groth16 and UniGroth
let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, rng)?;
let proof = Groth16::<E>::prove(&pk, circuit, rng)?;
let valid = Groth16::<E>::verify(&vk, &public_inputs, &proof)?;
```

### Forward Compatibility

New universal setup API (planned):
```rust
// Universal setup (one-time)
let universal_srs = UniGroth::<E>::universal_setup(max_degree, rng)?;

// Derive keys for any circuit
let (pk, vk) = universal_srs.derive_keys(circuit)?;

// Same proving/verification API
let proof = UniGroth::<E>::prove(&pk, circuit, rng)?;
let valid = UniGroth::<E>::verify(&vk, &public_inputs, &proof)?;
```

## Testing Strategy

### Current Tests
- Unit tests for each module
- Integration tests with multiple curves
- Proof generation and verification
- Proof re-randomization

### Planned Tests
- Universal setup correctness
- SAP reduction equivalence
- Folding scheme security
- Performance benchmarks
- Fuzzing for edge cases
- Property-based testing
- Cross-implementation compatibility

## Dependencies

### Core Dependencies
- `ark-ff` - Finite field arithmetic
- `ark-ec` - Elliptic curve operations
- `ark-poly` - Polynomial operations
- `ark-serialize` - Serialization
- `ark-relations` - Constraint systems
- `ark-snark` - SNARK trait definitions

### Future Dependencies
- `ark-kzg` - KZG commitments (to be added)
- `ark-protostar` - Folding schemes (to be added)
- GPU libraries (CUDA/OpenCL)
- FPGA toolchains

## Build System

### Features
- `std` - Standard library (default)
- `parallel` - Multi-threading (default)
- `r1cs` - Constraint gadgets
- `print-trace` - Debug tracing
- `universal` - Universal setup (planned)
- `sap` - SAP arithmetization (planned)
- `folding` - IVC support (planned)
- `gpu` - GPU acceleration (planned)

### Profiles
- `dev` - Fast compilation, no optimization
- `release` - Full optimization, thin LTO
- `bench` - Benchmarking profile
- `test` - Testing with debug assertions

## Contributing to Architecture

When proposing architectural changes:

1. Consider backward compatibility
2. Maintain performance targets
3. Document security implications
4. Provide benchmarks
5. Update this document

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

**Last Updated**: March 2026  
**Version**: 0.1.0  
**Status**: Foundation phase
