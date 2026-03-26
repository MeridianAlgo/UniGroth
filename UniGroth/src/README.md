# UniGroth — Source Modules

This directory contains the full UniGroth library implementation. Every module is production-ready, tested, and wired into the main prover/verifier pipeline.

## Module Map

### Core Groth16 (drop-in replacement)

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root: exports all modules, implements `SNARK` trait with SE by default |
| `data_structures.rs` | `Proof<E>`, `ProvingKey<E>`, `VerifyingKey<E>`, `PreparedVerifyingKey<E>` |
| `generator.rs` | Trusted setup — `generate_random_parameters_with_reduction` |
| `prover.rs` | `create_random_proof_with_reduction` — parallel MSMs, circuit-bound randomness |
| `verifier.rs` | `verify_proof_with_prepared_inputs` — 3-pairing or 4-pairing SE path |
| `r1cs_to_qap.rs` | R1CS → QAP reduction; O(n) `h_query_scalars`; parallel constraint eval |
| `constraints.rs` | In-circuit Groth16 verifier gadgets (feature: `r1cs`) |
| `test.rs` | Multi-curve correctness tests: BN254, BLS12-381, BLS12-377, BW6-761 |

### Universal Setup

| File | Purpose |
|------|---------|
| `kzg.rs` | KZG polynomial commitments: `commit`, `open`, `verify`, `batch_verify`, `update_srs` |
| `universal_setup.rs` | `UniversalParams` — circuit-agnostic key derivation from powers-of-tau SRS |
| `sap.rs` | Square Arithmetic Programs: R1CS → SAP reduction, gate counting |

### Advanced Arithmetization

| File | Purpose |
|------|---------|
| `plonkish.rs` | Custom gate registry (Poseidon, EC add, boolean, range), lookup tables (range, XOR, LogUp), Plonkish→R1CS |
| `circuit_builder.rs` | Fluent builder SDK: `witness`, `mul`, `add`, `conditional_select`, `public_output` |
| `circuits.rs` | Ready-to-use circuit library: Poseidon hash, Merkle tree proof, range check |

### Folding & Recursion

| File | Purpose |
|------|---------|
| `folding.rs` | ProtoStar folding engine: relaxed R1CS, cross-term vectors, Fiat-Shamir, IVC |
| `recursion.rs` | Recursive proof composition: SHA-256 chain integrity, multi-curve, cost analysis |

### Security

| File | Purpose |
|------|---------|
| `security.rs` | `SimExtractableProof<E>`, `SEConfig` (ROM/BG18), `SecurityReport`, Subversion ZK |
| `public_input_pok.rs` | Schnorr proof-of-knowledge binding prover to their public input choices |

### Optimizations

| File | Purpose |
|------|---------|
| `optimizations.rs` | Dynark 5-FFT / 4-FFT coset eval, parallel Pippenger MSM, CSR sparse QAP, `CosetDomainCache`, `PolymathCompressor` |
| `aggregation.rs` | SnarkPack-style N→1 proof aggregation with multi-pairing verification |
| `streaming.rs` | Memory-bounded streaming MSM prover — handles 2^20+ constraint circuits |
| `batch.rs` | Parallel multi-circuit batch proving and verification |
| `key_compression.rs` | KZG VK compression: O(n) → O(1) verifying key for zkEVM deployments |

### Deployment

| File | Purpose |
|------|---------|
| `solidity.rs` | Auto-generate Solidity verifier contracts (EIP-196/197 BN254 precompiles) |
| `wasm_verifier.rs` | Generate standalone Rust-WASM verifier with `wasm-bindgen` entry points |

### Post-Quantum Path

| File | Purpose |
|------|---------|
| `pq_inner.rs` | Binius (binary-field), Plonky3 (FRI/SHA-256), and Hybrid inner provers with public input binding; PQ proof aggregation |

### Binaries

| File | Purpose |
|------|---------|
| `bin/compare.rs` | Head-to-head benchmark: UniGroth vs ark-groth16 (feature: `compare`) |

## Performance Properties Implemented

- **O(n) `h_query_scalars`** — iterative accumulation replaces O(n log n) `.pow([i])` loop
- **5-FFT witness computation** — Dynark coset polynomial trick eliminates 2 FFTs vs standard 7-FFT path
- **4-FFT coset evaluation** — further eliminates final iFFT via algebraic identity
- **Parallel MSMs** — `rayon::join` runs h_acc, l_aux_acc, A, B concurrently
- **Batch affine conversion** — Montgomery batch inversion at proof output (2.46× on 32 points)
- **CSR sparse QAP** — skip zero rows entirely; 2.8–5.5× on typical zkEVM circuits
- **LTO = fat** — cross-crate inlining gives ~10–15% free speedup on release builds

## Security Properties Wired In

- **Simulation-extractability** — default `prove()` calls `make_sim_extractable` (ROM blinding, near-zero overhead)
- **Circuit binding** — `circuit_bound_rand()` mixes SHA-256(vk) into randomness
- **Toxic waste zeroing** — `alpha, beta, gamma, delta` zeroed with `black_box` after keygen
- **Subversion ZK** — proof rerandomization available at any time
