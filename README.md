<h1 align="center">UniGroth</h1>

<p align="center">
  <strong>A faster, hardened Groth16 in Rust, with batch verification and a lab of research extensions.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-288%20Rust%20%2B%204%20JS-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/clippy-0%20warnings-brightgreen" alt="Clippy">
  <img src="https://img.shields.io/badge/rust-stable%201.70%2B-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/proof-128%20B%20(BN254)-blue" alt="Proof Size">
</p>

---

## What it is

UniGroth is an extension of [`ark-groth16`](https://github.com/arkworks-rs/groth16). The core is standard Groth16 (3-pairing verification, 2 G1 + 1 G2 proofs: 128 bytes on BN254, 192 bytes on BLS12-381) with a faster prover, stricter verifier checks, and Fiat-Shamir batch verification. Around the core sit research modules (lookups, folding, polynomial commitments, a post-quantum scaffold), each documented with its current limits.

**Research software. Audit before production or mainnet use.**

## Why use it over plain Groth16

| | ark-groth16 | **UniGroth** |
|---|---|---|
| Prove, 2^12 constraints (BLS12-381) | 20.6 ms | **14.0 ms (1.47× faster)** |
| Prove, 2^16 constraints | 160 ms | **134 ms (1.19× faster)** |
| Verify | 1.36–1.39 ms | 1.35–1.36 ms (parity) |
| Batch-verify 32 proofs | 24.9 ms (one by one) | **7.6 ms (3.3× faster)** |
| Rejects identity points and BG18-tagged proofs | ✗ | ✓ |
| Toxic waste zeroized after setup | ✗ | ✓ |
| Solidity / WASM verifier generation | ✗ | ✓ |
| Circuit library (Poseidon, Merkle, range, MiMC auth) | ✗ | ✓ |

Measured on a 12-thread ARM64 Windows machine with `cargo bench --bench groth16-benches` and `cargo run --release --features compare --bin compare`. Prover speedups vary run to run (an earlier run on the same machine gave 1.33× and 1.08×). Rerun on your hardware; the [Benchmarks workflow](.github/workflows/bench.yml) does the same in CI.

Where the speed comes from:

| Optimization | Effect (measured) |
|---|---|
| Quotient polynomial on an n-point coset instead of 2n | 1.41–1.73× faster quotient FFTs |
| `h_query` scalars by running product instead of `pow` | 13–22× faster |
| Batch affine normalization, parallel MSMs | fewer inversions, multicore |
| Small-input verifier uses direct scalar multiplication | removes Pippenger overhead for < 16 inputs |

## Quick start

```bash
git clone https://github.com/MeridianAlgo/UniGroth.git
cd UniGroth/UniGroth
cargo test --workspace
```

```toml
[dependencies]
unigroth = { git = "https://github.com/MeridianAlgo/UniGroth.git" }
```

```rust
use unigroth::Groth16;
use ark_bn254::Bn254;
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut OsRng)?;
let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut OsRng)?;
let ok = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;
```

Always pass a cryptographically secure RNG (e.g. `OsRng`): predictable proving randomness breaks zero-knowledge, and predictable setup randomness lets anyone forge proofs.

## Configuration

Library-wide constants live in one module, `unigroth::config`:

| Constant | Value | Meaning |
|---|---|---|
| `VERSION` | crate version | tag stored proofs and keys |
| `SECURITY_BITS` | 128 | target security level |
| `POSEIDON_WIDTH` / `POSEIDON_FULL_ROUNDS` / `POSEIDON_PARTIAL_ROUNDS` | 3 / 8 / 57 | Poseidon 2-to-1 parameters |
| `VERIFIER_MSM_THRESHOLD` | 16 | inputs at which the verifier switches to MSM |
| `DOMAIN_*` | byte strings | Fiat-Shamir / digest domain tags (part of the wire format) |

## Features

### Batch verification

Verify many proofs for one verifying key with a single multi-pairing. The batching challenge is derived by Fiat-Shamir over the key, every statement and every proof, so a bad proof cannot hide in the batch.

```rust
use unigroth::{aggregate_proofs, verify_aggregated};

let agg = aggregate_proofs(&proofs);
let ok = verify_aggregated(&vk, &public_inputs_per_proof, &agg);
```

The bundle is O(N): it stores all N proofs. It saves verifier time, not proof size.

`batch_verify_optimized(&pvk, &proofs_and_inputs, &mut rng)` does the same with verifier-chosen randomness.

### Batch proving

```rust
use unigroth::{batch_prove, BatchConfig};

let result = batch_prove::<Bn254, LibsnarkReduction, _, _>(&pk, circuits, &BatchConfig::default(), &mut OsRng);
```

Each proof gets its own seed drawn from your RNG.

### Verifying-key compression

Store a 32-byte SHA-256 digest instead of the O(n) input-commitment vector. The vector is supplied at verification time and checked against the digest; the verifier always recomputes the public-input term itself.

```rust
use unigroth::{compress_vk, create_vk_opening, verify_with_compressed_vk};

let cvk = compress_vk(&vk);            // store this
let opening = create_vk_opening(&vk);  // ship alongside proofs
let ok = verify_with_compressed_vk(&cvk, &opening, &proof, &public_inputs);
```

### Circuit library

- `PoseidonHashCircuit`, `MerkleProofCircuit`: Poseidon with every S-box constrained, Grain-LFSR round constants and MDS matrix.
- `RangeCheckCircuit`: bit decomposition, limited below the field size so it cannot wrap.
- `AuthCircuit`: MiMC commitment + nullifier for login / anti-replay (see [`wasm-auth`](UniGroth/wasm-auth/README.md) for browser proving).
- `CircuitBuilder`: add / mul / assert / boolean / conditional select without writing raw R1CS.

### On-chain and browser verifiers

`generate_solidity_verifier(&vk, "MyVerifier")` emits a BN254 contract using the EIP-196/197 precompiles; `generate_wasm_verifier(&vk, "my_circuit")` emits a wasm-bindgen crate. Names must be plain identifiers, and generated verifiers reject non-canonical inputs and identity points. Both check the classical Groth16 proof only.

### Public-input proof of knowledge

`prove_public_input_pok` / `verify_public_input_pok`: a Schnorr proof bound by Fiat-Shamir to one specific Groth16 proof.

### KZG and IPA polynomial commitments

`KZG` supports commit, open, verify and Fiat-Shamir batch verify. The IPA (`ipa_commit` / `ipa_prove` / `ipa_verify`) is Bulletproofs-style, with the inner product bound through a dedicated generator.

## Research modules and their limits

These compile, are tested, and are useful for experiments. **Do not rely on them for security** until the listed gaps are closed.

| Module | Status |
|---|---|
| `universal_setup` | Holds the α, β, γ trapdoors in memory; whoever holds `UniversalParams` can forge proofs for every derived circuit. This is a convenience wrapper, not a transparent setup. Not serializable, zeroized on drop. |
| `security` (SE) | `proof_hash` is a fingerprint that nothing verifies. Groth16 proofs stay rerandomizable, so simulation-extractability is not claimed. BG18-mode proofs are rejected by the verifier. |
| `folding` | The decision predicate trusts a prover-supplied error vector. |
| `commitment` FRI | Does not check folding consistency, so it is not a low-degree test. |
| `pq_inner` | SHA-256 binding scaffold. Anyone can build an accepted "proof" for any statement. Not post-quantum secure. |
| `recursion` | Hash-linked audit chain; does not verify inner proofs. |
| `mpc` | Share tags are unkeyed checksums, not authentication. |
| `sap` | Delegates to the standard QAP reduction (the earlier SAP map dropped constraints). |
| `lookup`, `lasso` | Lookup arguments; challenges must come from Fiat-Shamir or the verifier. |

See [docs/post-quantum.md](docs/post-quantum.md) for the post-quantum roadmap.

## Security

v0.8.0 is a security release. It fixes forgeable verifiers (aggregation, VK compression, the Poseidon and Merkle circuits, the SAP reduction, KZG batching, IPA, Lasso), a hardcoded setup seed in `auth_setup`, clock-seeded batch proving, and replay via non-canonical nullifier encodings in `wasm-auth`. Full list: [CHANGELOG](UniGroth/CHANGELOG.md).

Guarantees the core relies on:

- Knowledge soundness and zero-knowledge of Groth16 (AGM), given a trusted setup and a CSPRNG.
- Deserialization with validation enforces on-curve and subgroup checks.
- The verifier rejects wrong input counts, identity points and BG18 elements.
- Setup trapdoors are zeroized on a best-effort basis; Rust does not guarantee that no copies remain.

Report vulnerabilities privately through a GitHub security advisory on this repository.

## JavaScript reference implementation

`src/` contains a small JavaScript R1CS toolkit (MiMC circuit builder, prover, verifier). **It is not zero-knowledge:** proofs carry the full witness, and the verifier re-checks every constraint. Use it to learn or debug circuits; use the Rust library, or `phrase.circom` with snarkjs, for private proofs. Run `npm test`.

## Supported curves

BN254 (Ethereum precompiles), BLS12-381, BLS12-377 and BW6-761 (recursion pair), MNT4-298.

## Project layout

```
UniGroth/                 Rust workspace
  src/                    library modules (config.rs holds global constants)
  src/bin/                compare (vs ark-groth16), auth_setup
  tests/ benches/         integration tests and benchmarks
  wasm-auth/              browser prover / server verifier for the auth circuit
src/ test/                JavaScript reference implementation and tests
phrase.circom verifier.sol  Circom / snarkjs demo circuit and verifier
site/                     demo site
```

## CI

Every push and PR runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo build`, `cargo test --workspace`, and `npm test`, with a read-only workflow token.

## Research foundation

[Groth16](https://eprint.iacr.org/2016/260) · [BKSV20 rerandomization](https://eprint.iacr.org/2020/811) · [SnarkPack](https://eprint.iacr.org/2021/529) · [Nova](https://eprint.iacr.org/2021/370) · [ProtoStar](https://eprint.iacr.org/2023/620) · [Poseidon](https://eprint.iacr.org/2019/458) · [Lasso](https://eprint.iacr.org/2023/1216) · [Bulletproofs](https://eprint.iacr.org/2017/1066)

## License

Dual-licensed under MIT and Apache 2.0. Built on [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16) by **MeridianAlgo**.
