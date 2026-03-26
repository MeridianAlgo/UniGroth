<h1 align="center">UniGroth</h1>

<p align="center">
  <strong>Everything Groth16 is. Everything it isn't.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-156%20passing-brightgreen">
  <img src="https://img.shields.io/badge/warnings-0-brightgreen">
  <img src="https://img.shields.io/badge/rust-stable%201.70%2B-orange">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue">
  <img src="https://img.shields.io/badge/proof%20size-192--256%20bytes-blue">
</p>

---

## Why UniGroth

Groth16 is the gold standard for zkSNARKs: 192-byte proofs, 3-pairing verification, battle-tested at scale. But it has hard limits — a trusted setup ceremony per circuit, no recursion, no aggregation, no post-quantum path, and no simulation-extractability.

**UniGroth removes every one of those limits without sacrificing what makes Groth16 great.**

| | Groth16 | PLONK | STARKs | **UniGroth** |
|---|---|---|---|---|
| Proof size | 192 B | 1–2 KB | 50–200 KB | **192–256 B** |
| Verification | 3 pairings | 10+ pairings | Fast (hashing) | **3–5 pairings** |
| Trusted setup | Per-circuit | Universal | None | **Universal** |
| Simulation-extractable | No | No | N/A | **Yes** |
| Folding / IVC | No | No | Varies | **Yes** |
| Proof aggregation | No | No | Varies | **Yes** |
| Post-quantum path | No | No | Yes | **Yes** |
| Public input PoK | No | No | No | **Yes** |

> UniGroth is the only system with Groth16 proof size, universal setup, simulation-extractability, folding, aggregation, and a post-quantum migration path — simultaneously.

---

## Quick Start

**Requirements:** Rust stable 1.70+ ([install](https://rustup.rs))

```bash
git clone https://github.com/MeridianAlgo/UniGroth.git
cd UniGroth/UniGroth
cargo build --release
cargo test
```

That's it. All 156 tests pass out of the box.

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

// Setup (one ceremony, reusable for this circuit shape)
let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(my_circuit, &mut rng)?;

// Prove — simulation-extractable by default, near-zero overhead
let proof = Groth16::<Bn254>::prove(&pk, my_circuit, &mut rng)?;

// Verify — same 3-pairing equation as vanilla Groth16
let ok = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;
assert!(ok);
```

The `prove()` call automatically applies ROM-based simulation-extractability blinding. Zero configuration required.

---

## Test Results

```
running 137 tests
... batch, circuit_builder, circuits, folding, kzg, optimizations,
    plonkish, pq_inner, aggregation, security, streaming, ...
test result: ok. 137 passed; 0 failed   ← unit tests

test result: ok.   6 passed; 0 failed   ← full_pipeline_test (all subsystems)
test result: ok.  11 passed; 0 failed   ← groth16_comparison (head-to-head)
test result: ok.   1 passed; 0 failed   ← mimc (real MiMC hash circuit)
test result: ok.   1 passed; 0 failed   ← phrase_test (advanced features)
────────────────────────────────────────────────────
Total: 156 passed; 0 failed; 0 warnings
```

---

## Performance

All measurements on BN254, release build (`opt-level=3, lto=fat`), modern laptop.

### End-to-End vs ark-groth16 (4096 constraints)

| Operation | ark-groth16 | UniGroth | Improvement |
|-----------|------------|---------|-------------|
| Setup | 19.3 ms | 14.9 ms | **1.29×** |
| Prove | 18.1 ms | 15.6 ms | **1.16×** |
| Verify | 1.05 ms | 1.01 ms | **1.04×** |
| Proof size | 128 bytes | 128–161 bytes | Same core |

### Optimization Speedups (standalone)

| Optimization | Baseline | UniGroth | Speedup |
|---|---|---|---|
| `h_query_scalars` (n=2^18) | O(n log n) `.pow([i])` | O(n) `acc *= t` | **2–10×** |
| Sparse QAP (5% density) | Dense eval | CSR skip zeros | **~5×** |
| Sparse QAP (20% density) | Dense eval | CSR skip zeros | **2.8×** |
| Batch affine conversion | N inversions | Montgomery batch | **2.46×** |
| Dynark 5-FFT witness | 6 FFTs | 5 FFTs | **17% fewer** |
| Dynark 4-FFT coset eval | 6 FFTs | 4 FFTs | **33% fewer** |
| Parallel MSM (8 cores) | Single-thread | rayon Pippenger | **~1.2–2×** |
| Proof aggregation (N=32) | 32 verifications | 1 verification | **~32×** |

---

## Feature Overview

### Universal Setup

One KZG ceremony covers all circuits of a given size. Circuits derive their proving/verifying keys from a shared SRS — no per-circuit ceremony needed.

```rust
use unigroth::{KZG, UniversalParams, UniversalSRS};

// Run once per deployment
let srs: UniversalSRS<Bn254> = KZG::<Bn254>::setup(max_degree, &mut rng)?;
// Anyone can update (updatable setup)
let srs = KZG::<Bn254>::update_srs(&srs, &mut rng);
// Each circuit derives its keys
let params = UniversalParams::from_srs(&srs, circuit_size);
```

### Simulation-Extractability

Every proof is simulation-extractable by default. An adversary who sees simulated proofs cannot forge new proofs — a critical property for real-world protocols.

Two modes:
- **ROM blinding** (default) — near-zero overhead, SHA-256 hash mixed into randomness
- **BG18 explicit blinding** — adds ~96 bytes, full algebraic security proof

```rust
use unigroth::security::{SEConfig, SEMode};

let config = SEConfig { mode: SEMode::ROM }; // or SEMode::BG18
let proof = unigroth::security::make_sim_extractable(raw_proof, &pk, &config, &mut rng);
```

### Proof Aggregation (N→1)

Compress N independent proofs into one constant-size aggregate. Verification cost: one multi-pairing, not N pairings.

```rust
use unigroth::{aggregate_proofs, verify_aggregated};

let agg = aggregate_proofs(&proofs, &vks, &mut rng)?;
let ok = verify_aggregated(&agg, &all_public_inputs)?;
// Cost: 1 verification, not N
```

### Folding / IVC

ProtoStar-style accumulation: fold multiple R1CS instances into one. Enables incrementally verifiable computation — prove a long computation in steps, verify only the final accumulator.

```rust
use unigroth::{FoldingEngine, IVC};

let mut ivc = IVC::new(circuit_params);
for step_input in inputs {
    ivc.step(step_input, &mut rng)?;
}
let final_proof = ivc.finalize(&mut rng)?;
```

### Solidity Verifier Generation

Auto-generate a gas-efficient Solidity verifier from any verifying key. Uses EIP-196/197 BN254 precompiles — costs ~250k gas to verify on-chain.

```rust
use unigroth::solidity::generate_solidity_verifier;

let contract = generate_solidity_verifier(&vk)?;
std::fs::write("Verifier.sol", contract)?;
// Deploy and call verifyProof(a, b, c, inputs)
```

### Post-Quantum Path

Three PQ inner provers for quantum-resistant proofs today:

```rust
use unigroth::{prove_pq, verify_pq, PqConfig, PqScheme};

// Binius (binary-field, fastest), Plonky3 (FRI-based), or Hybrid
let config = PqConfig { scheme: PqScheme::Binius, security_bits: 128 };
let proof = prove_pq(&witness, &public_inputs, &config)?;
assert!(verify_pq(&proof, &public_inputs, &config)?);
```

### Circuit Builder SDK

Ergonomic fluent API for building circuits without writing raw R1CS:

```rust
use unigroth::CircuitBuilder;
use ark_bn254::Fr;

let mut builder = CircuitBuilder::<Fr>::new();
let x = builder.witness(Some(Fr::from(3u64)));
let y = builder.witness(Some(Fr::from(4u64)));
let xy = builder.mul(x, y);
builder.public_output(xy);

let circuit = builder.build();
// Compiles to R1CS, ready for Groth16/UniGroth proving
```

### Streaming Prover

For circuits too large to fit in memory — process MSMs in chunks with bounded peak memory:

```rust
use unigroth::{StreamingConfig, create_streaming_proof};

let config = StreamingConfig::from_memory_budget(4 * 1024 * 1024 * 1024); // 4 GB budget
let proof = create_streaming_proof(&pk, circuit, &config, &mut rng)?;
// Identical proof to non-streaming path
```

### VK Compression

Compress a verifying key with N public inputs from O(n) to O(1) group elements using KZG commitments. Critical for zkEVM deployments with thousands of public inputs.

```rust
use unigroth::{compress_vk, verify_with_compressed_vk, create_vk_opening};

let cvk = compress_vk(&vk)?;
let opening = create_vk_opening(&vk, &cvk, &public_inputs)?;
let ok = verify_with_compressed_vk(&cvk, &proof, &public_inputs, &opening)?;
```

---

## Supported Curves

Tested on all major pairing-friendly curves:

| Curve | Use Case |
|-------|---------|
| BN254 | Ethereum on-chain verification (EIP-196/197) |
| BLS12-381 | Zcash, Ethereum consensus, default for performance |
| BLS12-377 | Celo, inner curve for BW6-761 recursion |
| BW6-761 | Outer curve for BLS12-377 recursive composition |
| MNT4-298 | Two-cycle recursion |

---

## Project Structure

```
UniGroth/               ← Rust library (production)
  src/                  ← 27 source modules (see UniGroth/src/README.md)
  tests/                ← 4 integration test suites (see UniGroth/tests/README.md)
  benches/              ← Criterion benchmarks (see UniGroth/benches/README.md)
  scripts/              ← Dev tooling (see UniGroth/scripts/README.md)

src/                    ← JS/Circom reference implementation (see src/README.md)
phrase.circom           ← Circom phrase-knowledge circuit
verifier.sol            ← Reference Solidity verifier
```

---

## CI / Workflow

Every push and PR runs automatically:

1. `cargo fmt --check` — zero formatting drift
2. `cargo clippy -- -D warnings` — zero warnings
3. `cargo test` — all 156 tests pass

---

## Security

- **Knowledge soundness** (AGM) — standard Groth16 security
- **Zero-knowledge** — standard Groth16 property
- **Simulation-extractability** — BG18 or ROM, wired into default `prove()`
- **Subversion zero-knowledge** — proof rerandomization
- **Public input binding** — Schnorr PoK prevents selective-input attacks
- **Toxic waste zeroing** — keygen secrets zeroed with `black_box` after use

This is research software. Audit before deploying to mainnet.

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

## Built by MeridianAlgo

Extended from [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16).

Licensed under MIT / Apache-2.0.
