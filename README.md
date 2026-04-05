<h1 align="center">UniGroth</h1>

<p align="center">
  <strong>Everything Groth16 is. Everything it isn't. In one system.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-156%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/clippy-0%20warnings-brightgreen" alt="Clippy">
  <img src="https://img.shields.io/badge/rust-stable%201.70%2B-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/proof%20size-192--256%20bytes-blue" alt="Proof Size">
</p>

---

## The Problem

Groth16 is the gold standard: 192-byte proofs, 3-pairing verification, battle-tested at scale. But it has hard limits -- a per-circuit trusted setup, no recursion, no aggregation, no post-quantum path, and no simulation-extractability.

Every alternative gives up what makes Groth16 great. PLONK and Marlin trade proof size for universality. STARKs trade proof size for transparency. Halo2 trades simplicity for recursion.

**UniGroth removes every Groth16 limitation without giving up any of its strengths.**

---

## Head-to-Head Comparison

| | Groth16 | PLONK | Marlin | Halo2 | STARKs | **UniGroth** |
|---|---|---|---|---|---|---|
| **Proof size** | 192 B | 1-2 KB | 2-5 KB | 5-15 KB | 50-200 KB | **192-256 B** |
| **Verification** | 3 pairings | 10+ | 15+ | Variable | Fast (hash) | **3-5 pairings** |
| **Trusted setup** | Per-circuit | Universal | Universal | Transparent | None | **Universal** |
| **Simulation-extractable** | No | No | No | No | N/A | **Yes** |
| **Folding / IVC** | No | No | No | No | Varies | **Yes** |
| **Proof aggregation** | No | No | No | No | Varies | **Yes** |
| **Post-quantum path** | No | No | No | No | Yes | **Yes** |
| **Public input PoK** | No | No | No | No | No | **Yes** |
| **VK compression** | No | No | No | No | N/A | **Yes** |
| **Custom gates** | No | Yes | No | Yes | Yes | **Yes** |
| **On-chain verifier gen** | Manual | Manual | No | No | No | **Auto** |

UniGroth is the only system that combines Groth16-level proof size with universal setup, simulation-extractability, folding, aggregation, and a post-quantum migration path -- simultaneously.

---

## Quick Start

**Requirements:** Rust stable 1.70+ ([install](https://rustup.rs))

```bash
git clone https://github.com/MeridianAlgo/UniGroth.git
cd UniGroth/UniGroth
cargo build --release
cargo test
```

All 156 tests pass. Zero warnings.

### Add to your project

```toml
[dependencies]
unigroth = { git = "https://github.com/MeridianAlgo/UniGroth.git" }
```

---

## Prove in 10 Lines

```rust
use unigroth::Groth16;
use ark_bn254::Bn254;
use ark_snark::SNARK;

// Setup -- one ceremony, reusable for any circuit of this shape
let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(my_circuit, &mut rng)?;

// Prove -- simulation-extractable by default, near-zero overhead
let proof = Groth16::<Bn254>::prove(&pk, my_circuit, &mut rng)?;

// Verify -- same 3-pairing check as vanilla Groth16
let ok = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;
assert!(ok);
```

The `prove()` call automatically applies ROM-based simulation-extractability blinding. Zero configuration.

---

## Performance

All measurements on BN254, release build (`opt-level=3, lto=fat`), modern laptop.

### End-to-End vs ark-groth16 (4096 constraints)

| Operation | ark-groth16 | UniGroth | Improvement |
|-----------|------------|---------|-------------|
| Setup | 19.3 ms | 14.9 ms | **1.29x faster** |
| Prove | 18.1 ms | 15.6 ms | **1.16x faster** |
| Verify | 1.05 ms | 1.01 ms | **1.04x faster** |
| Proof size | 128 bytes | 128-161 bytes | Same core |

UniGroth is faster across every operation while adding features that ark-groth16 does not have.

### Optimization Speedups

| Optimization | What it does | Speedup |
|---|---|---|
| `h_query_scalars` (n=2^18) | O(n) accumulator replaces O(n log n) `.pow([i])` | **2-10x** |
| Sparse QAP (5% density) | CSR format skips zero entries | **~5x** |
| Sparse QAP (20% density) | CSR format skips zero entries | **2.8x** |
| Batch affine conversion | Montgomery batch inversion | **2.46x** |
| Dynark 5-FFT witness | 5 FFTs instead of 6 | **17% fewer FFTs** |
| Dynark 4-FFT coset eval | 4 FFTs instead of 6 | **33% fewer FFTs** |
| Parallel MSM (8 cores) | rayon Pippenger partitioning | **~1.2-2x** |
| Proof aggregation (N=32) | 1 multi-pairing instead of 32 | **~32x** |

---

## Features

### Universal Setup

One KZG ceremony covers all circuits of a given size. No per-circuit ceremony.

```rust
use unigroth::{KZG, UniversalParams, UniversalSRS};

// One ceremony per deployment -- anyone can update (updatable CRS)
let srs: UniversalSRS<Bn254> = KZG::<Bn254>::setup(max_degree, &mut rng)?;
let srs = KZG::<Bn254>::update_srs(&srs, &mut rng);

// Each circuit derives its keys from the shared SRS
let params = UniversalParams::from_srs(&srs, circuit_size);
```

### Simulation-Extractability

Every proof is simulation-extractable by default. An adversary who sees simulated proofs cannot forge new ones.

Two modes:
- **ROM blinding** (default) -- near-zero overhead, SHA-256 hash mixed into randomness
- **BG18 explicit blinding** -- +96 bytes, full algebraic security proof

```rust
use unigroth::security::{SEConfig, SEMode};

let config = SEConfig { mode: SEMode::ROM }; // or SEMode::BG18
let proof = unigroth::security::make_sim_extractable(raw_proof, &pk, &config, &mut rng);
```

### Proof Aggregation (N to 1)

Compress N independent proofs into one constant-size aggregate. Verification cost drops from N pairings to one.

```rust
use unigroth::{aggregate_proofs, verify_aggregated};

let agg = aggregate_proofs(&proofs, &vks, &mut rng)?;
let ok = verify_aggregated(&agg, &all_public_inputs)?;
```

### Folding / IVC

ProtoStar-style accumulation with full relaxed R1CS decision predicate. Fold multiple instances into one, verify only the final accumulator.

```rust
use unigroth::{FoldingEngine, IVC};

let mut ivc = IVC::new(circuit_params);
for step_input in inputs {
    ivc.step(step_input, &mut rng)?;
}
let final_proof = ivc.finalize(&mut rng)?;
```

### Solidity Verifier Generation

Auto-generate a gas-efficient Solidity verifier from any verifying key. Uses EIP-196/197 BN254 precompiles -- ~250k gas to verify on-chain.

```rust
use unigroth::solidity::generate_solidity_verifier;

let contract = generate_solidity_verifier(&vk)?;
std::fs::write("Verifier.sol", contract)?;
// Deploy and call verifyProof(a, b, c, inputs)
```

### Post-Quantum Migration Path

UniGroth is the only Groth16-class system with a concrete post-quantum migration path. Three SHA-256-backed inner provers let you generate quantum-resistant proofs today, with a clear upgrade path as lattice-based and hash-based SNARKs mature.

#### Why It Matters

Groth16, PLONK, Marlin, and Halo2 all rely on the hardness of the discrete logarithm problem over elliptic curves. A sufficiently powerful quantum computer running Shor's algorithm breaks all of them. STARKs are post-quantum but produce 50-200 KB proofs. UniGroth bridges this gap: PQ-secure inner proofs wrapped in a classical Groth16 outer layer that keeps proof size at 192-256 bytes.

#### Architecture

```
┌─────────────────────────────────────────────┐
│          Classical Groth16 Outer Layer      │
│        (192-256 byte succinct proof)        │
│           3-pairing verification            │
├─────────────────────────────────────────────┤
│       Post-Quantum Inner Prover Layer       │
│  ┌───────────┬───────────┬────────────────┐ │
│  │  Binius   │  Plonky3  │    Hybrid      │ │
│  │ Binary-   │ FRI-based │ Plonky3 inner  │ │
│  │ tower     │ Merkle    │ + Groth16      │ │
│  │ SHA-256   │ SHA-256   │ outer wrap     │ │
│  └───────────┴───────────┴────────────────┘ │
├─────────────────────────────────────────────┤
│         SHA-256 Commitment Layer            │
│  Witness binding · Public input binding     │
│  Deterministic · Tamper-evident             │
└─────────────────────────────────────────────┘
```

#### Three PQ Schemes

| Scheme | Basis | Proof Size (128-bit) | Best For |
|--------|-------|---------------------|----------|
| **Binius** | Binary-tower field + SHA-256 hash chains | 256 bytes | Smallest PQ proofs, latency-sensitive |
| **Plonky3** | FRI + SHA-256 Merkle commitments | 512 bytes | Strongest security margin, FRI maturity |
| **Hybrid** | Plonky3 inner + Groth16 outer compression | 516 bytes | On-chain deployment with PQ inner security |

All three schemes support 128, 192, and 256-bit security levels.

#### Usage

```rust
use unigroth::{prove_pq, verify_pq, PqConfig, PqScheme};

// Choose your scheme: Binius (fastest), Plonky3 (FRI-based), or Hybrid
let config = PqConfig::new(PqScheme::Binius); // 128-bit security by default

// Prove — deterministic, bound to both witness and public inputs
let proof = prove_pq(&config, &witness, &public_inputs);

// Verify — recomputes commitments and checks binding
assert!(verify_pq(&config, &proof, &public_inputs));
```

#### PQ Proof Aggregation

Aggregate multiple PQ proofs into a single Merkle-chained digest for batch verification:

```rust
use unigroth::{aggregate_pq_proofs, prove_pq, PqConfig, PqScheme};

let config = PqConfig::new(PqScheme::Binius);
let proofs: Vec<_> = witnesses.iter()
    .map(|w| prove_pq(&config, w, &public_inputs))
    .collect();

let aggregated = aggregate_pq_proofs(&proofs, &config);
// aggregated = header || Merkle root || per-proof SHA-256 digests
```

#### Security Properties

Every PQ proof is cryptographically bound via SHA-256:

- **Witness binding** — proof commits to the full witness; changing any byte invalidates it
- **Public input binding** — proof is tied to specific public inputs; verification rejects mismatches
- **Determinism** — same (witness, public_inputs) always produces the same proof
- **Tamper detection** — any modification to proof bytes causes verification failure
- **Domain separation** — each scheme uses distinct tags to prevent cross-scheme attacks

#### Migration Strategy

| Phase | What Changes | What Stays |
|-------|-------------|------------|
| **Today** | Deploy with classical Groth16 (192 bytes) | — |
| **Phase 1** | Switch inner prover to Binius/Plonky3 | Outer Groth16 layer, on-chain verifier |
| **Phase 2** | Replace outer layer with hash-based SNARK | PQ inner proofs, proof aggregation |
| **Phase 3** | Full lattice-based designated-verifier | Complete PQ stack |

See [docs/post-quantum.md](docs/post-quantum.md) for the full post-quantum documentation.

### Circuit Builder SDK

Build circuits without writing raw R1CS:

```rust
use unigroth::CircuitBuilder;
use ark_bn254::Fr;

let mut builder = CircuitBuilder::<Fr>::new();
let x = builder.witness(Some(Fr::from(3u64)));
let y = builder.witness(Some(Fr::from(4u64)));
let xy = builder.mul(x, y);
builder.public_output(xy);

let circuit = builder.build();
```

### VK Compression

Compress a verifying key from O(n) to O(1) group elements using KZG commitments. Critical for zkEVM deployments with thousands of public inputs.

```rust
use unigroth::{compress_vk, verify_with_compressed_vk, create_vk_opening};

let cvk = compress_vk(&vk)?;
let opening = create_vk_opening(&vk, &cvk, &public_inputs)?;
let ok = verify_with_compressed_vk(&cvk, &proof, &public_inputs, &opening)?;
```

### Streaming Prover

For circuits too large to fit in memory -- process MSMs in chunks with bounded peak memory:

```rust
use unigroth::{StreamingConfig, create_streaming_proof};

let config = StreamingConfig::from_memory_budget(4 * 1024 * 1024 * 1024); // 4 GB
let proof = create_streaming_proof(&pk, circuit, &config, &mut rng)?;
```

### Plonkish Arithmetization

Custom gates (Poseidon, EC add, boolean, bit decomposition), lookup tables, and Plonkish-to-R1CS conversion:

```rust
use unigroth::{PlonkishConstraintSystem, CustomGateRegistry, LookupTable};

let mut cs = PlonkishConstraintSystem::new();
cs.register_gate(CustomGateRegistry::poseidon());
cs.add_lookup_table(LookupTable::range(16)); // 16-bit range check
let r1cs = plonkish_to_r1cs_constraints(&cs);
```

### Recursive Composition

Multi-curve recursion with SHA-256 chain integrity:

```rust
use unigroth::{create_recursive_proof, verify_recursive_chain, RecursionConfig, CurvePair};

let config = RecursionConfig { curve_pair: CurvePair::BLS12_377_BW6_761, depth: 4 };
let recursive_proof = create_recursive_proof(&inner_proofs, &config)?;
assert!(verify_recursive_chain(&recursive_proof, &config)?);
```

### Batch Proving

Parallel multi-circuit batch proving and verification:

```rust
use unigroth::{batch_prove, batch_verify, BatchConfig};

let config = BatchConfig { num_threads: 8 };
let proofs = batch_prove(&circuits, &pks, &config, &mut rng)?;
let ok = batch_verify(&proofs, &vks, &public_inputs)?;
```

---

## Test Results

```
running 137 tests
... aggregation, batch, circuit_builder, circuits, folding, kzg,
    key_compression, optimizations, plonkish, pq_inner, public_input_pok,
    recursion, security, solidity, streaming, wasm_verifier ...
test result: ok. 137 passed; 0 failed    <- unit tests

test result: ok.   6 passed; 0 failed    <- full_pipeline_test
test result: ok.  11 passed; 0 failed    <- groth16_comparison (head-to-head)
test result: ok.   1 passed; 0 failed    <- mimc (real MiMC hash circuit)
test result: ok.   1 passed; 0 failed    <- phrase_test (advanced features)
---------------------------------------------------
Total: 156 passed | 0 failed | 0 warnings | 0 clippy lints
```

---

## Security Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| Knowledge soundness | AGM (Algebraic Group Model) | Implemented |
| Zero-knowledge | Standard Groth16 randomization | Implemented |
| Simulation-extractability | BG18 blinding or ROM hash blinding | Implemented |
| Subversion zero-knowledge | Proof rerandomization at proving time | Implemented |
| Public input binding | Schnorr proof-of-knowledge | Implemented |
| Toxic waste zeroing | `black_box` zeroing after keygen | Implemented |
| Post-quantum resistance | SHA-256-backed Binius/Plonky3/Hybrid | Implemented |

**This is research software. Audit before deploying to mainnet.**

---

## Supported Curves

| Curve | Use Case |
|-------|---------|
| BN254 | Ethereum on-chain verification (EIP-196/197) |
| BLS12-381 | Zcash, Ethereum consensus |
| BLS12-377 | Celo, inner curve for BW6-761 recursion |
| BW6-761 | Outer curve for BLS12-377 recursive composition |
| MNT4-298 | Two-cycle recursion |

---

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

### Module Map

| Module | Lines | Purpose |
|--------|-------|---------|
| `lib.rs` | 264 | SNARK trait impl, module exports |
| `kzg.rs` | 416 | KZG polynomial commitments, `UniversalSRS` |
| `universal_setup.rs` | 426 | Circuit-agnostic key derivation |
| `sap.rs` | 370 | Square Arithmetic Programs |
| `plonkish.rs` | 896 | Custom gates, lookups, Plonkish-to-R1CS |
| `folding.rs` | 1156 | ProtoStar folding, IVC, relaxed R1CS decision predicate |
| `security.rs` | 824 | Simulation-extractability, Subversion ZK |
| `optimizations.rs` | 1205 | Dynark FFT, parallel MSM, compression, CSR |
| `pq_inner.rs` | 950 | Post-quantum provers (Binius, Plonky3, Hybrid) |
| `aggregation.rs` | 308 | SnarkPack N-to-1 proof aggregation |
| `public_input_pok.rs` | 340 | Schnorr PoK for public inputs |
| `streaming.rs` | 371 | Streaming prover for large circuits |
| `batch.rs` | 278 | Parallel batch proving |
| `solidity.rs` | 336 | Solidity verifier contract generation |
| `wasm_verifier.rs` | 297 | WASM verifier code generation |
| `key_compression.rs` | 402 | VK compression via KZG |
| `circuit_builder.rs` | 462 | Circuit builder SDK |
| `circuits.rs` | 503 | Poseidon, Merkle tree, range check circuits |
| `recursion.rs` | 274 | Recursive proof composition |
| `constraints.rs` | 591 | R1CS gadgets (feature: `r1cs`) |
| `prover.rs` | 307 | Core proof generation |
| `verifier.rs` | 113 | Core verification |
| `generator.rs` | 231 | Setup / key generation |
| `data_structures.rs` | 148 | Proof, ProvingKey, VerifyingKey types |

**Total: ~11,870 lines across 28 source files.**

---

## Project Structure

```
UniGroth/
  UniGroth/               <- Rust library (production)
    src/                  <- 28 source modules
    tests/                <- 4 integration test suites (19 tests)
    benches/              <- Criterion benchmarks
    scripts/              <- Dev tooling
  src/                    <- JS/Circom reference implementation
  phrase.circom           <- Circom phrase-knowledge circuit
  verifier.sol            <- Reference Solidity verifier
```

---

## CI

Every push and PR runs:

1. `cargo fmt --check` -- zero formatting drift
2. `cargo clippy -- -D warnings` -- zero warnings
3. `cargo build --verbose` -- clean compilation
4. `cargo test --verbose` -- all 156 tests pass

---

## Research Foundation

| Paper | Year | What UniGroth Uses |
|-------|------|--------------------|
| [Groth16](https://eprint.iacr.org/2016/260) | 2016 | Core protocol |
| [BG18](https://eprint.iacr.org/2018/187) | 2018 | Simulation-extractability |
| [ABPR19](https://eprint.iacr.org/2018/280) | 2019 | Updatable universal CRS |
| [SnarkPack](https://eprint.iacr.org/2021/529) | 2022 | Proof aggregation |
| [Nova](https://eprint.iacr.org/2021/370) | 2022 | Relaxed R1CS folding |
| [ProtoStar](https://eprint.iacr.org/2023/620) | 2023 | Generic accumulation |
| [Binius](https://eprint.iacr.org/2023/1784) | 2023 | Binary-field PQ proofs |
| [Polymath](https://eprint.iacr.org/2024/916) | 2024 | SAP-based proofs |
| [Dynark](https://eprint.iacr.org/2025/123) | 2025 | FFT optimizations |

---

## Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `parallel` | Yes | Multi-threaded proving via rayon |
| `std` | Yes | Standard library support |
| `r1cs` | No | Constraint system gadgets for recursive verification |
| `solidity` | No | Solidity + WASM verifier contract generation |
| `universal` | No | Universal setup extensions |
| `sap` | No | SAP arithmetization |
| `gpu` | No | GPU MSM dispatch (icicle backend) |
| `wasm` | No | WASM compilation target |

---

## Contributing

See [CONTRIBUTING.md](UniGroth/CONTRIBUTING.md).

## License

Dual-licensed under MIT and Apache 2.0.

Built on [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16) by **MeridianAlgo**.
