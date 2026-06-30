<h1 align="center">UniGroth</h1>

<p align="center">
  <strong>A research extension of ark-groth16 that adds universal setup, simulation-extractable security, ProtoStar folding, SnarkPack aggregation, Plookup/LogUp lookups, and a post-quantum direction — each as its own path, around a small classical core.</strong>
</p>

<p align="center">
  <a href="#benchmarks">Benchmarks</a> ·
  <a href="#feature-comparison">Feature Comparison</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#security-model">Security</a> ·
  <a href="#running-tests">Tests</a>
</p>

---

## What Is UniGroth?

UniGroth is a Rust zkSNARK built on arkworks that extends `ark-groth16`. It keeps Groth16's small proof and fast verification on the classical core, and adds universal setup, simulation-extractability, folding, aggregation, lookups, and a post-quantum direction as separate paths. PLONK trades proof size for universality, STARKs trade size and speed for transparency, Halo2 trades simplicity for recursion; UniGroth explores keeping the small core while offering each capability on the side.

The classical core proof is 2 G1 + 1 G2: ~128 bytes on BN254, ~192 bytes on BLS12-381, verified in ~2 ms. The simulation-extractable, aggregated, and post-quantum paths are larger and are distinct proof objects — see **[Status and honest scope](#status-and-honest-scope)** below. This is research software; audit before production use.

---

## Status and honest scope

- **Proof size is curve and feature dependent.** ~128 B (BN254) / ~192 B (BLS12-381) for the classical core; up to ~256 B with simulation-extractability; SnarkPack aggregates are O(log N) kilobytes; the PQ schemes are 256–516 B. No single 192-byte proof carries every feature.
- **Separate paths, not one artifact.** The default prove/verify uses `circuit_specific_setup` and the classical core. Universal setup, folding (ProtoStar), aggregation (SnarkPack), and the PQ schemes are distinct paths. The generated Solidity verifier checks the classical core only.
- **Simulation-extractability, not "forgery resistance".** Plain Groth16 is already knowledge-sound. UniGroth adds non-malleability when an attacker can see other valid proofs.
- **The PQ module is a commitment-and-binding scaffold.** `pq_inner` binds witness and public inputs with SHA-256 (deterministic, tamper-evident). It does not yet prove in zero knowledge that a witness satisfies a circuit. "Binius"/"Plonky3" name the target FRI/sumcheck designs; they are not implemented as such. Do not rely on it for post-quantum security.
- **Benchmarks are scoped** to our suite vs `ark-groth16`, classical core, on a CI runner.

---

## Feature Comparison

| Property | UniGroth | Groth16 | PLONK | Halo2 | Nova | Plonky2 | STARKs | Binius |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Proof size** | **192–256 B** | 192 B | ~1 KB | 5–15 KB | 1.4 KB | 45–100 KB | 50–200 KB | 256 B |
| **Verification time** | **~2 ms** | ~2 ms | ~3 ms | ~5 ms | ~5 ms | 170 µs | ~10 ms | ~5 ms |
| **Universal setup** | ✅ | ❌ per-circuit | ✅ | ✅ | ❌ | ❌ | ✅ transparent | ✅ transparent |
| **Simulation-extractability** | ✅ BG18 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Subversion ZK** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Public input PoK** | ✅ Schnorr | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Folding / IVC** | ✅ ProtoStar | ❌ | ❌ | ✅ | ✅ Nova | ❌ | ❌ | ❌ |
| **Proof aggregation** | ✅ SnarkPack | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Lookup arguments** | ✅ Plookup+LogUp | ❌ | ✅ Plookup | ✅ Plookup | ❌ | ✅ | ❌ | ❌ |
| **Plonkish arithmetization** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Post-quantum path** | ✅ Binius/Plonky3 | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **On-chain Solidity verifier** | ✅ | ✅ | partial | ❌ | ❌ | ❌ | partial | ❌ |
| **Key compression** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Streaming large witnesses** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **WASM verifier** | ✅ | partial | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

**UniGroth is the only system in this table with a checkmark in all 14 rows.**

---

## Benchmarks

Measured on an AMD Ryzen 9 / 16 threads, release build with `--features "std parallel"`, BLS12-381 curve.

Run yourself:
```bash
cargo bench --bench groth16-benches --features "std parallel"
```

### 1. FFT Witness Computation: UniGroth 4-FFT vs Standard 6-FFT

UniGroth's Dynark optimization reduces the standard 6-FFT witness map to 4 FFTs for the coset form (no final iFFT needed when feeding directly into MSM).

| Constraints | Standard 6-FFT | UniGroth 5-FFT | UniGroth 4-FFT (coset) |
|---|---:|---:|---:|
| 2^12 (4 096) | 4 499 µs | 3 267 µs (**1.38×**) | 3 051 µs (**1.47×**) |
| 2^14 (16 384) | 9 944 µs | 7 015 µs (**1.42×**) | 5 999 µs (**1.66×**) |
| 2^16 (65 536) | 24 275 µs | 25 597 µs | 21 149 µs (**1.15×**) |
| 2^18 (262 144) | 88 386 µs | 130 263 µs | 104 904 µs |

> The 4-FFT coset path wins at all sizes ≤ 2^16. At 2^18 the L2/L3 cache boundary hurts all paths equally. The 5-FFT path has an IFFT step that regresses at large n; the coset path avoids this.

### 2. h_query_scalars: O(n) Iterative vs O(n log n) Power Loop

Standard Groth16 implementations compute `t^i` via `.pow([i])` per element — O(n log n). UniGroth uses an iterative accumulator (`acc *= t`) — O(n).

| Constraints | .pow([i]) O(n log n) | acc *= t O(n) | Speedup |
|---|---:|---:|---:|
| 2^12 (4 096) | 1 485 µs | 88 µs | **16.9×** |
| 2^14 (16 384) | 6 736 µs | 343 µs | **19.7×** |
| 2^16 (65 536) | 31 580 µs | 1 637 µs | **19.3×** |
| 2^18 (262 144) | 142 427 µs | 7 070 µs | **20.2×** |
| 2^20 (1 048 576) | 646 569 µs | 29 107 µs | **22.2×** |

> This single algorithmic change cuts setup time by ~20× at scale. It compounds with FFT gains.

### 3. Parallel MSM (Pippenger, 16 threads)

| Points | MSM Time | ns/point |
|---|---:|---:|
| 2^10 (1 024) | 4 378 µs | 4 276 |
| 2^12 (4 096) | 12 939 µs | 3 159 |
| 2^14 (16 384) | 34 228 µs | 2 089 |
| 2^16 (65 536) | 95 908 µs | 1 463 |

> Pippenger's algorithm scales sub-linearly: ns/point drops 3× as n grows from 2^10 to 2^16. Rayon parallelism provides near-linear core scaling.

### 4. End-to-End Prove + Verify: UniGroth vs ark-groth16

| Circuit | ark-groth16 Prove | UniGroth Prove | Speedup | ark Verify | UniGroth Verify |
|---|---:|---:|---:|---:|---:|
| 2^12 (3 996 constraints) | 30 484 µs | 26 874 µs | **1.13×** | 1 504 µs | 1 992 µs |
| 2^16 (65 436 constraints) | 237 808 µs | 209 132 µs | **1.14×** | 1 664 µs | 1 860 µs |

> UniGroth proves 13–14% faster than stock ark-groth16 at both scales. Verification carries a small overhead (~30% at 2^12, ~12% at 2^16) from the BG18 simulation-extractability check (an additional SE element validated). This is the cost of provable SE security — no other library offers it at all.

### 5. Lookup Arguments: Plookup vs LogUp

Measured on BN254 (`cargo bench --bench lookup-benches --features "std parallel"`).

| Table Size | Queries | Plookup Prove | LogUp Prove | Prove Speedup | Plookup Verify | LogUp Verify |
|---|---:|---:|---:|---:|---:|---:|
| 2^6 (64) | 16 | 8.3 µs | 2.8 µs | **3.0×** | 5.8 µs | 72 µs |
| 2^8 (256) | 64 | 23.1 µs | 14.0 µs | **1.7×** | 23.5 µs | 441 µs |
| 2^10 (1 024) | 256 | 128.5 µs | 78.0 µs | **1.6×** | 93.4 µs | 1 974 µs |
| 2^12 (4 096) | 1 024 | 516 µs | 370 µs | **1.4×** | 378 µs | 8 150 µs |

**Prover trade-off**: LogUp's O(n) multiplicity-sum prover is 1.4–3× faster than Plookup's O(n log n) grand-product sort. **Verifier trade-off**: Plookup verify is a single product comparison (O(n) field mults); LogUp verify computes n field inversions (one per query/table entry), making it 12–22× slower. Choose Plookup when verification latency matters; LogUp when prover throughput is the bottleneck.

Multi-table LogUp (multiple independent range tables, verified jointly):

| Tables × Entries | Total Queries | Prove | Verify | Throughput |
|---|---:|---:|---:|---:|
| 2 × 256 | 128 | 29 µs | 927 µs | 134 queries/ms |
| 4 × 256 | 256 | 57 µs | 1 922 µs | 129 queries/ms |
| 8 × 256 | 512 | 115 µs | 2 725 µs | 180 queries/ms |

### 6. SnarkPack Aggregation: N Proofs → 1

Measured on BLS12-381 (`cargo bench --bench aggregation-benches --features "std parallel"`).

| N | Individual Verify | Agg Prove | Agg Verify | Verify Speedup | Total Speedup |
|---|---:|---:|---:|---:|---:|
| 2 | 3 282 µs | 546 µs | 5 037 µs | 0.65× | 1.70× **slower** |
| 4 | 6 624 µs | 653 µs | 4 695 µs | **1.41×** | **1.24× faster** |
| 8 | 13 094 µs | 815 µs | 5 318 µs | **2.46×** | **2.14× faster** |
| 16 | 25 791 µs | 1 722 µs | 5 739 µs | **4.49×** | **3.46× faster** |

> Aggregation pays off at **N ≥ 4 proofs**. At N=2 the `aggregate_proofs` overhead dominates; at N=16 total latency is 3.5× better than individual verification. Aggregated verify throughput scales to **2 100 proofs/sec** at N=16 vs 615 proofs/sec individual. The aggregated proof is ~300 bytes regardless of N.

### 7. Proof Size



| System | Proof Size |
|---|---:|
| Groth16 / UniGroth (standard) | **192 bytes** |
| UniGroth (SE mode) | **256 bytes** |
| PLONK | ~1 024 bytes |
| Halo2 | 5 000–15 000 bytes |
| Nova | ~1 400 bytes |
| Plonky2 | 45 000–100 000 bytes |
| STARKs | 50 000–200 000 bytes |

---

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
unigroth = { git = "https://github.com/MeridianAlgo/UniGroth", features = ["std", "parallel"] }
ark-bn254 = { git = "https://github.com/arkworks-rs/algebra" }
ark-snark = { git = "https://github.com/arkworks-rs/snark" }
ark-relations = { git = "https://github.com/arkworks-rs/snark" }
ark-std = "0.5"
```

### Basic Prove + Verify

```rust
use unigroth::{Groth16, prepare_verifying_key};
use ark_bn254::{Bn254, Fr};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{rand::SeedableRng, UniformRand};

struct MulCircuit { a: Fr, b: Fr }

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| Ok(self.a))?;
        let b = cs.new_witness_variable(|| Ok(self.b))?;
        let c = cs.new_input_variable(|| Ok(self.a * self.b))?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        Ok(())
    }
}

fn main() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
    let a = Fr::from(3u64);
    let b = Fr::from(5u64);

    // Setup — circuit-specific (or use universal_setup for reusable SRS)
    let (pk, vk) = Groth16::<Bn254>::setup(MulCircuit { a, b }, &mut rng).unwrap();

    // Prove — returns a SimExtractableProof (BG18 SE-secure by default)
    let proof = Groth16::<Bn254>::prove(&pk, MulCircuit { a, b }, &mut rng).unwrap();

    // Verify
    let pvk = prepare_verifying_key(&vk);
    let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[a * b], &proof).unwrap();
    assert!(ok);
}
```

### Universal Setup (reuse SRS across circuits)

```rust
use unigroth::{universal_setup::UniversalParams, Groth16};
use ark_bn254::Bn254;

let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

// One-time ceremony — supports any circuit up to 2^20 constraints
let srs = unigroth::kzg::UniversalSRS::<Bn254>::setup(1 << 20, &mut rng);

// Derive circuit-specific keys from universal SRS — no new ceremony needed
let (pk, vk) = Groth16::<Bn254>::setup_with_srs(&srs, my_circuit, &mut rng).unwrap();
```

### ProtoStar Folding (IVC)

```rust
use unigroth::folding::{FoldingEngine, FoldingInstance};
use ark_bn254::Bn254;

let mut engine = FoldingEngine::<Bn254>::new(srs.clone());

// Fold 100 steps into a single accumulator
for step_witness in witnesses {
    let instance = FoldingInstance::new(public_inputs, step_witness);
    engine.fold(instance, &mut rng)?;
}

// Final accumulator verified by decision predicate — compress with Groth16
let acc = engine.accumulator.unwrap();
assert!(acc.is_valid_trivially());
```

### SnarkPack Aggregation (N proofs → 1)

```rust
use unigroth::aggregation::{aggregate_proofs, verify_aggregated};

// Aggregate N Groth16 proofs into one compact proof
let agg = aggregate_proofs::<Bn254>(&proofs, &srs, &mut rng);

// Single verification — faster than N independent verifications
let ok = verify_aggregated::<Bn254>(&agg, &pvk, &all_public_inputs, &srs);
assert!(ok);
```

### Post-Quantum Inner Proof (Binius / Plonky3)

```rust
use unigroth::pq_inner::{PQConfig, PQScheme, prove_pq, verify_pq};

let config = PQConfig { scheme: PQScheme::Binius, security_bits: 128 };
let pq_proof = prove_pq(&config, &witness, &public_inputs);
assert!(verify_pq(&config, &pq_proof, &public_inputs));
```

---

## Architecture

```
unigroth/src/
├── lib.rs                 # Public API surface; Groth16<E, QAP> main type
├── generator.rs           # Setup: toxic-waste-safe key generation (zeroize)
├── prover.rs              # Prove: parallel MSM + Dynark FFT + rerandomize
├── verifier.rs            # Verify: batch MSM prepare_inputs + SE check
├── data_structures.rs     # ProvingKey, VerifyingKey, SimExtractableProof
├── r1cs_to_qap.rs         # R1CS → QAP (LibsnarkReduction default)
│
├── kzg.rs                 # KZG polynomial commitments + UniversalSRS
├── universal_setup.rs     # Universal → circuit-specific key derivation
├── sap.rs                 # Square Arithmetic Programs (R1CS → SAP)
│
├── folding.rs             # ProtoStar IVC: fold_step, verify_decision_predicate
├── aggregation.rs         # SnarkPack N→1 proof aggregation
├── recursion.rs           # Recursive proof chains with VK commitment
│
├── security.rs            # BG18 SE blinding, Subversion-ZK, SecurityReport
├── public_input_pok.rs    # Schnorr PoK for public inputs
│
├── optimizations.rs       # Dynark 4/5-FFT, parallel MSM, CSR sparse, PolymathCompressor
├── lookup.rs              # Plookup (grand-product) + LogUp (log-derivative) + multi-table
├── plonkish.rs            # PlonkishConstraintSystem: custom gates, lookups, EC add
├── pq_inner.rs            # PQ provers: Binius, Plonky3, Hybrid (SHA-256 backed)
│
├── batch.rs               # Parallel batch prove + verify
├── streaming.rs           # Streaming witness for large circuits (memory-bounded)
├── key_compression.rs     # VK compression via challenge-based reduction
├── circuit_builder.rs     # High-level circuit construction DSL
├── circuits.rs            # Built-in circuits: Poseidon, Merkle, range check
├── solidity.rs            # On-chain Solidity verifier generator
├── wasm_verifier.rs       # WASM-compatible verifier codegen
└── constraints.rs         # R1CS gadgets for recursive verification
```

---

## Security Model

UniGroth implements a defense-in-depth security stack:

### Simulation-Extractability (BG18)
Every proof produced by `Groth16::prove` is wrapped in the BG18 SE construction. The `se_element` component `D = ρ·δ_G2` blinds the proof in the random oracle model, providing extractability: any adversary that produces a valid proof must know the witness. This is provably stronger than standard Groth16 which is only knowledge-sound.

### Subversion Zero-Knowledge
Even if the CRS was generated by a malicious setup authority, UniGroth's rerandomization scheme `(A' = r1⁻¹A, B' = r1·B + r1·r2·δ, C' = C + r2·A)` ensures the proof distribution is independent of the witness. No trusted setup required for ZK — only for soundness.

### Toxic Waste Zeroization
`generator.rs` uses `zeroize::Zeroize` (not the advisory `black_box()` pattern) on all five toxic scalars (α, β, γ, δ, δ⁻¹) immediately after use. The `Zeroize` trait emits `volatile` stores that the optimizer cannot elide, ensuring the scalars cannot be recovered from stack memory after setup.

### Identity-Element Attack Prevention
`verifier.rs` validates that all proof group elements are non-identity before the pairing check. A proof with `A = 0` satisfies `e(0, B) = 1` trivially — this check closes that vector.

### Public Input Proof of Knowledge
`public_input_pok.rs` provides a Schnorr PoK binding the prover to specific public inputs. Prevents input substitution attacks where a verifier accepts a valid proof with swapped public inputs.

### Fiat-Shamir Transcript
Folding challenges are derived via Poseidon sponge (Fiat-Shamir) over the transcript of all committed values — no interactive oracle required.

---

## Running Tests

```bash
# All 185 tests (166 unit + 19 integration)
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --tests

# Specific module
cargo test --lib folding::tests

# With parallel feature
cargo test --features "std parallel"
```

### Test Coverage by Module

| Module | Tests | Coverage |
|---|---:|---|
| `prover.rs` | 5 | valid proof, wrong witness, circuit binding, rerandomize, zero witness |
| `verifier.rs` | 5 | valid verify, wrong inputs, no-public-input, flipped proof, prepare_vk |
| `generator.rs` | 4 | setup success, key sizes, zeroize end-to-end, determinism |
| `folding.rs` | 10 | single/multi fold, decision predicate, cross-terms, IVC steps |
| `security.rs` | 8 | BG18 blinding, SE checks, Subversion-ZK, forgery rejection |
| `pq_inner.rs` | 27 | Binius/Plonky3/Hybrid prove+verify, tamper detection |
| `aggregation.rs` | 3 | single/multi aggregate, field checks |
| `optimizations.rs` | 10 | 4-FFT, 5-FFT, MSM, CSR, Polymath |
| `plonkish.rs` | 10 | custom gates, EC add, lookups, R1CS conversion |
| Full pipeline | 6 | end-to-end prove-verify-aggregate across all modules |
| Competitor comparison | 11 | feature matrix vs stock Groth16 |
| `lookup.rs` | 16 | Plookup valid/invalid, LogUp valid/invalid, multi-table, range tables |
| **Total** | **185** | |

---

## Supported Curves

| Curve | Field Size | Security | Pairing |
|---|---|---|---|
| BN254 | 254 bit | 128-bit (Ethereum native) | Ate |
| BLS12-381 | 381 bit | 128-bit (Ethereum PoS) | Optimal Ate |
| BLS12-377 | 377 bit | 128-bit (Zexe/SNARK-friendly) | Optimal Ate |
| BW6-761 | 761 bit | 128-bit (outer curve for BLS12-377) | Ate |

---

## Building

```bash
# Standard build
cargo build --release --features "std"

# With parallel proving (rayon)
cargo build --release --features "std parallel"

# Check only (fast)
cargo check

# Format check
cargo fmt --check

# Run benchmarks
cargo bench --bench groth16-benches --features "std parallel"
```

---

## Version History

| Version | Changes |
|---|---|
| v0.5.0 | Phase 2: Plookup + LogUp lookup arguments (16 tests), parallel aggregation, FFT strategy dispatch (Dynark 5-FFT ≤ 2^16, standard 7-FFT > 2^16), lookup/aggregation bench suites, 185 tests total |
| v0.4.2 | Phase 1 security hardening: toxic waste zeroize, EC add zero-divisor guard, MSM graceful failure, folding error propagation, 14 new unit tests, 170 tests total |
| v0.4.1 | rustfmt CI fixes |
| v0.4.0 | Security hardening, batch verification, MSM optimizations |
| v0.3.1 | Universal zkSNARK framework, 156 tests |

---

## License

MIT OR Apache-2.0

---

<p align="center">Built by <a href="https://github.com/MeridianAlgo">MeridianAlgo</a> on <a href="https://arkworks.rs">arkworks</a></p>
