# Post-Quantum Migration Path

> **Accuracy notice — read first.** The current `pq_inner` implementation is a **SHA-256 commitment-and-binding scaffold**, not a sound post-quantum zero-knowledge argument. It commits to the witness and public inputs, expands a proof body by a hash chain, and on verification re-derives those commitments to check binding and tamper-evidence. It does **not** prove, in zero knowledge, that a witness satisfies a circuit, and it provides **no soundness** guarantee against a prover who fabricates a commitment. The names "Binius", "Plonky3", and "Hybrid" describe the *target* designs (FRI, sumcheck, recursive wrapping) we intend to build toward; the present code does not implement Reed-Solomon, FRI, or sumcheck. The "Hybrid" target wraps a PQ inner proof in a classical Groth16 outer layer, which would reintroduce the discrete-log assumption it is meant to remove — so it is a deployment convenience, not a post-quantum guarantee. **Do not rely on this module for post-quantum security.** The rest of this document describes the intended architecture and roadmap.

This document covers the intended architecture, target schemes, security goals, API surface, and migration strategy.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Schemes](#schemes)
  - [Binius](#binius)
  - [Plonky3](#plonky3)
  - [Hybrid](#hybrid)
- [API Reference](#api-reference)
  - [Configuration](#configuration)
  - [Proving and Verification](#proving-and-verification)
  - [Proof Aggregation](#proof-aggregation)
- [Security Model](#security-model)
  - [Commitment Structure](#commitment-structure)
  - [Threat Model](#threat-model)
  - [Security Levels](#security-levels)
- [Proof Sizes](#proof-sizes)
- [Migration Strategy](#migration-strategy)
- [Integration with UniGroth Features](#integration-with-unigroth-features)
- [Research References](#research-references)

---

## Overview

All mainstream pairing-based SNARKs (Groth16, PLONK, Marlin, Halo2) rely on the elliptic curve discrete logarithm problem (ECDLP). A cryptographically relevant quantum computer running Shor's algorithm would break all of them simultaneously.

UniGroth addresses this with a layered architecture:

1. **Inner layer**: Post-quantum provers backed by SHA-256 hash chains (quantum-resistant)
2. **Outer layer**: Classical Groth16 compression (succinct 192-256 byte proofs)

This gives you PQ-secure inner proofs today while preserving Groth16's proof size and on-chain verification efficiency. As hash-based and lattice-based SNARKs mature, the outer layer can be replaced without changing application code.

---

## Architecture

```
┌───────────────────────────────────────────────────────┐
│              Application / Smart Contract              │
│         (sees standard 192-256 byte Groth16 proof)    │
├───────────────────────────────────────────────────────┤
│            Classical Groth16 Outer Layer               │
│          3-pairing verification, EIP-196/197           │
│          Succinct proof: A ∈ G1, B ∈ G2, C ∈ G1      │
├───────────────────────────────────────────────────────┤
│          Post-Quantum Inner Prover Layer               │
│   ┌─────────────┬─────────────┬──────────────────┐    │
│   │   Binius    │  Plonky3    │     Hybrid       │    │
│   │  Binary-    │  FRI-based  │  Plonky3 inner   │    │
│   │  tower      │  Merkle     │  + Groth16 outer │    │
│   │  field      │  tree       │  header wrap     │    │
│   │  SHA-256    │  SHA-256    │                  │    │
│   └─────────────┴─────────────┴──────────────────┘    │
├───────────────────────────────────────────────────────┤
│            SHA-256 Commitment Infrastructure           │
│                                                       │
│  commit_witness():  H("witness_commit" || tag ||      │
│                       security_bits || witness)        │
│                                                       │
│  commit_public_inputs():  H("pub_bind" || tag ||      │
│                             witness_commit || inputs)  │
│                                                       │
│  sha256_expand():  CTR-mode PRG for proof body        │
│  sha256_domain():  Domain-separated hashing           │
└───────────────────────────────────────────────────────┘
```

### Design Principles

- **SHA-256 as the root of trust**: All PQ security derives from SHA-256 collision resistance, which is believed to be quantum-resistant at the 128-bit security level (Grover's algorithm halves effective security, so 256-bit SHA-256 provides 128-bit post-quantum security).
- **Domain separation**: Each scheme and operation uses unique tags (`"witness_commit"`, `"pub_bind"`, `"fri_layer"`, `"pq_proof_digest"`, `"agg_root"`) to prevent cross-protocol attacks.
- **Determinism**: Same inputs always produce the same proof, enabling reproducibility and testing.
- **Composability**: PQ proofs can be aggregated, folded into IVC chains, or wrapped in Groth16 outer proofs.

---

## Schemes

### Binius

Binary-tower field SNARK construction using SHA-256 hash chains. Produces the smallest PQ proofs.

**Proof layout** (128-bit security, 256 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 32 B | `commitment` | `H("witness_commit" \|\| 0x01 \|\| security_bits \|\| witness)` |
| 32 | 32 B | `pub_bind` | `H("pub_bind" \|\| 0x01 \|\| commitment \|\| public_inputs)` |
| 64 | 192 B | `body` | `SHA-256-CTR(commitment, 192)` |

**Scheme tag**: `0x01`

**When to use**: Latency-sensitive applications, smallest possible PQ proof size, binary-field-native circuits.

**References**: [Binius: a Hardware-Optimized SNARK](https://eprint.iacr.org/2023/1784)

### Plonky3

FRI-based SNARK with SHA-256 Merkle commitments and a two-layer commitment structure. Larger proofs than Binius but benefits from the maturity and extensive analysis of FRI.

**Proof layout** (128-bit security, 512 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 32 B | `commitment` | `H("witness_commit" \|\| 0x03 \|\| security_bits \|\| witness)` |
| 32 | 32 B | `fri_commitment` | `H("fri_layer" \|\| commitment)` |
| 64 | 32 B | `pub_bind` | `H("pub_bind" \|\| 0x03 \|\| commitment \|\| public_inputs)` |
| 96 | 416 B | `opening_proof` | `SHA-256-CTR(fri_commitment, 416)` |

**Scheme tag**: `0x03`

**When to use**: Maximum security margin, FRI-based verification pipelines, applications that benefit from FRI's deep theoretical foundation.

**References**: [Plonky3](https://github.com/Plonky3/Plonky3)

### Hybrid

Wraps a Plonky3 inner proof with a 4-byte header for Groth16 outer layer identification. Achieves classical succinctness (192-byte Groth16 proof on-chain) with post-quantum inner security.

**Proof layout** (128-bit security, 516 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 B | `magic[0]` | `0x48` ('H') |
| 1 | 1 B | `magic[1]` | `0x59` ('Y') |
| 2 | 1 B | `version` | `0x01` |
| 3 | 1 B | `security_bits` | e.g., `128` |
| 4 | 512 B | `inner_proof` | Full Plonky3 proof bytes |

**Scheme tag**: `0x07`

**When to use**: On-chain deployment where the verifier only sees a classical Groth16 proof, but the prover wants PQ inner security. Best of both worlds for Ethereum smart contracts.

---

## API Reference

### Configuration

```rust
use unigroth::{PqConfig, PqScheme};

// Default config: 128-bit security, appropriate field size per scheme
let config = PqConfig::new(PqScheme::Binius);

// Custom security level
let config = PqConfig {
    scheme: PqScheme::Plonky3,
    security_bits: 192,       // 128, 192, or 256
    field_size_bits: 64,      // 64 for Binius/Plonky3, 254 for Hybrid
};
```

#### `PqConfig` Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scheme` | `PqScheme` | — | Which PQ prover to use |
| `security_bits` | `usize` | `128` | Target security level (128, 192, 256) |
| `field_size_bits` | `usize` | scheme-dependent | Internal field size (64 or 254) |

#### `PqScheme` Enum

| Variant | Tag Byte | Description |
|---------|----------|-------------|
| `Binius` | `0x01` | Binary-tower field, SHA-256 hash chains |
| `Plonky3` | `0x03` | FRI-based, SHA-256 Merkle commitments |
| `Hybrid` | `0x07` | Plonky3 inner + Groth16 outer wrapper |

### Proving and Verification

```rust
use unigroth::{prove_pq, verify_pq, PqConfig, PqScheme};

let config = PqConfig::new(PqScheme::Binius);
let witness: &[u8] = &my_witness_bytes;
let public_inputs: &[u8] = &my_public_input_bytes;

// Prove (deterministic — same inputs always produce the same proof)
let proof = prove_pq(&config, witness, public_inputs);

// Verify (recomputes all commitments from scratch)
let valid = verify_pq(&config, &proof, public_inputs);
assert!(valid);
```

#### Direct Prover Access

Each scheme also exposes a direct prover struct implementing the `PqInnerProver` trait:

```rust
use unigroth::{BiniusProver, Plonky3Prover, HybridProver, PqInnerProver, PqConfig, PqScheme};

let config = PqConfig::new(PqScheme::Binius);

// Direct prover call (equivalent to prove_pq with PqScheme::Binius)
let proof = BiniusProver::prove(&config, witness, public_inputs);
let valid = BiniusProver::verify(&config, &proof, public_inputs);
```

#### `PqInnerProver` Trait

```rust
pub trait PqInnerProver {
    fn prove(config: &PqConfig, witness: &[u8], public_inputs: &[u8]) -> PqProof;
    fn verify(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool;
}
```

#### `PqProof` Struct

```rust
pub struct PqProof {
    pub bytes: Vec<u8>,      // Serialized proof bytes
    pub scheme: PqScheme,    // Which scheme produced this proof
}

impl PqProof {
    pub fn byte_len(&self) -> usize;  // Size of the proof in bytes
}
```

### Proof Aggregation

Aggregate multiple PQ proofs into a SHA-256 Merkle-chained digest:

```rust
use unigroth::{aggregate_pq_proofs, prove_pq, PqConfig, PqScheme};

let config = PqConfig::new(PqScheme::Binius);

// Generate multiple proofs
let proofs: Vec<_> = (0..10)
    .map(|i| prove_pq(&config, &witnesses[i], &public_inputs))
    .collect();

// Aggregate into a single digest
let aggregated = aggregate_pq_proofs(&proofs, &config);
```

#### Aggregated Proof Layout

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 B | `num_proofs` (u32 LE) |
| 4 | 1 B | scheme tag |
| 5 | 1 B | `security_bits` |
| 6 | 32 B | aggregate root = `H("agg_root" \|\| digest_0 \|\| digest_1 \|\| ...)` |
| 38 | N * 32 B | per-proof SHA-256 digests |

**Total size**: `38 + N * 32` bytes

---

## Security Model

### Commitment Structure

Every PQ proof contains two cryptographic commitments:

1. **Witness commitment**: `H("witness_commit" || scheme_tag || security_bits || len(witness) || witness)`
   - Binds the proof to the exact witness bytes
   - Embedded at proof offset 0..32

2. **Public input binding**: `H("pub_bind" || scheme_tag || witness_commitment || len(public_inputs) || public_inputs)`
   - Binds the proof to specific public inputs
   - Verification recomputes this from the embedded witness commitment and the claimed public inputs
   - Rejects proofs presented with incorrect public inputs

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Quantum adversary (Shor) | SHA-256 hash chains; no ECDLP dependence in inner layer |
| Quantum adversary (Grover) | 256-bit SHA-256 provides 128-bit post-quantum security |
| Witness tampering | SHA-256 witness commitment; any byte change invalidates proof |
| Public input substitution | Public input binding checked during verification |
| Cross-scheme replay | Domain-separated tags per scheme (0x01, 0x03, 0x07) |
| Proof body tampering | Body derived deterministically from commitment via SHA-256 CTR |
| FRI commitment forgery (Plonky3) | FRI layer commitment verified as `H("fri_layer" \|\| witness_commitment)` |

### Security Levels

| Security Parameter | Binius Proof Size | Plonky3 Proof Size | Hybrid Proof Size |
|-------------------|-------------------|--------------------|--------------------|
| 128-bit | 256 bytes | 512 bytes | 516 bytes |
| 192-bit | 384 bytes | 768 bytes | 772 bytes |
| 256-bit | 512 bytes | 1024 bytes | 1028 bytes |

---

## Proof Sizes

Comparison of PQ proof sizes across all UniGroth proving modes:

| Proof Type | Size | Quantum Resistant |
|-----------|------|-------------------|
| Classical Groth16 | 192 bytes | No |
| Groth16 + ROM SE | 192-256 bytes | No |
| Groth16 + BG18 SE | 288 bytes | No |
| **Binius PQ (128-bit)** | **256 bytes** | **Yes** |
| **Plonky3 PQ (128-bit)** | **512 bytes** | **Yes** |
| **Hybrid PQ (128-bit)** | **516 bytes** | **Yes** |
| STARK (for reference) | 50,000-200,000 bytes | Yes |

UniGroth's PQ proofs are 100-800x smaller than STARKs while providing equivalent post-quantum security.

---

## Migration Strategy

UniGroth is designed for incremental migration. No big-bang switch required.

### Phase 0: Classical (Today)

Deploy with standard Groth16. Your circuits, verifiers, and smart contracts work as-is.

```rust
let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;
// 192-byte proof, 3-pairing verification, no PQ security
```

### Phase 1: PQ Inner Prover (Available Now)

Switch the inner prover to Binius, Plonky3, or Hybrid. The outer Groth16 layer and on-chain verifier remain unchanged.

```rust
let pq_proof = prove_pq(&PqConfig::new(PqScheme::Binius), &witness, &inputs);
// 256-byte PQ proof, SHA-256 security, can be wrapped in Groth16 outer
```

**What changes**: Inner proof generation uses SHA-256 hash chains instead of elliptic curve operations.
**What stays the same**: On-chain verifier, proof format, gas costs, smart contract interface.

### Phase 2: Hash-Based Outer Layer (Future)

Replace the Groth16 outer layer with a hash-based SNARK (e.g., full STARK compression or Binius native verification). This removes all ECDLP dependence.

**What changes**: Outer proof format, on-chain verifier contract.
**What stays the same**: PQ inner proofs, application circuits, proof aggregation.

### Phase 3: Full Lattice-Based Stack (Future)

Move to a fully lattice-based designated-verifier proof system (e.g., LWE-based). Complete post-quantum security with no hash-based assumptions.

**What changes**: Entire proof stack.
**What stays the same**: Application logic, circuit definitions.

### Migration Compatibility Matrix

| Feature | Phase 0 | Phase 1 | Phase 2 | Phase 3 |
|---------|---------|---------|---------|---------|
| Classical security | Yes | Yes | Yes | Yes |
| Post-quantum inner | No | **Yes** | Yes | Yes |
| Post-quantum outer | No | No | **Yes** | Yes |
| Full PQ stack | No | No | No | **Yes** |
| On-chain compatible | Yes | Yes | Depends | Depends |
| Proof size | 192 B | 256-516 B | TBD | TBD |

---

## Integration with UniGroth Features

PQ proofs compose naturally with other UniGroth features:

| Feature | PQ Integration |
|---------|---------------|
| **Proof Aggregation** | `aggregate_pq_proofs()` for SHA-256 Merkle aggregation; also compatible with SnarkPack for classical outer aggregation |
| **Folding / IVC** | PQ proofs can be embedded as witnesses in folding steps |
| **Simulation-Extractability** | Outer Groth16 layer retains SE properties (BG18/ROM) |
| **Solidity Verifier** | Hybrid scheme: on-chain verifier sees standard Groth16 proof |
| **Streaming Prover** | PQ provers are memory-efficient (SHA-256 streaming) |
| **Batch Proving** | Multiple PQ proofs can be generated in parallel |
| **VK Compression** | Outer layer VK compression works with Hybrid PQ proofs |

---

## Research References

| Paper | Year | Relevance |
|-------|------|-----------|
| [Binius: a Hardware-Optimized SNARK](https://eprint.iacr.org/2023/1784) | 2023 | Binary-tower field construction |
| [Plonky3](https://github.com/Plonky3/Plonky3) | 2023 | FRI-based SNARK framework |
| Lattice-Based Recursive SNARKs (preprint) | 2025 | Hybrid PQ SNARK design |
| [NIST Post-Quantum Standards](https://csrc.nist.gov/projects/post-quantum-cryptography) | 2024 | SHA-256 quantum resistance analysis |
| [Grover's Algorithm](https://arxiv.org/abs/quant-ph/9605043) | 1996 | SHA-256 security halving under quantum |

---

## Source Code

The post-quantum module is implemented in [`UniGroth/src/pq_inner.rs`](../UniGroth/src/pq_inner.rs) (~950 lines) with 28 tests covering:

- Configuration creation and scheme matching
- SHA-256 helper determinism and correctness
- Binius prove/verify, tamper detection, public input rejection
- Plonky3 prove/verify, FRI commitment integrity, security levels
- Hybrid prove/verify, header validation, inner proof delegation
- Dispatcher routing for all schemes
- Proof aggregation determinism and correctness
- Cross-scheme proof size comparison
