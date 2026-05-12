# UniGroth v0.5 → v1.0 Roadmap
## Dominating Every zkSNARK Competitor

*Last updated: 2026-05-10*

---

## 1. Current Position

UniGroth is the **only zkSNARK** that simultaneously delivers:

| Property | UniGroth | Best Competitor |
|----------|----------|-----------------|
| Proof size | **192–256 B** | Groth16 192 B (no extras) |
| Universal setup | ✅ KZG | PLONK, Marlin |
| Simulation-extractability | ✅ BG18 | None (unique) |
| Subversion ZK | ✅ | None (unique) |
| Public input PoK | ✅ | None (unique) |
| Folding / IVC | ✅ ProtoStar | Nova, HyperNova |
| Proof aggregation | ✅ SnarkPack | SnarkPack |
| Post-quantum path | ✅ Binius/Plonky3 | Binius, STARKs |
| Plonkish arithmetization | ✅ | PLONK, Halo2 |
| On-chain Solidity verifier | ✅ | Groth16 wrappers |

**What competitors still beat us on:**
- Plonky2: recursive proof verification in **170 μs** (we are ~1–5 ms)
- PLONK/Halo2: comprehensive **lookup arguments** (plookup/LogUp)
- STARKs/Binius: **fully transparent setup** (no SRS ceremony)
- Jolt: **Lasso generalized lookups** for RISC-V VM opcodes
- Everyone: our **GPU MSM is a CPU-fallback stub**

---

## 2. Codebase Audit Findings

### 2.1 Stubs / Non-functional Code

| Location | Issue | Risk |
|----------|-------|------|
| `optimizations.rs:806–810` | `GpuMsmDispatcher` always falls back to CPU; Icicle backend not linked | Medium — GPU claims in README are false |
| `optimizations.rs:836` | `ProverProfile` comment says "1.33× FFT" but ratio is inverted; speedup is actually 50% | Low — docs mislead |
| `optimizations.rs` entire | `estimate_speedup()` result **never used** by actual prover | High — optimization infrastructure dead |

### 2.2 Security Gaps

| Gap | Location | Severity |
|-----|----------|----------|
| **123 `.unwrap()` calls** — panic on invalid input | folding.rs (39), security.rs (26), prover.rs (13) | Medium |
| **Field inversion without zero-guard** | `plonkish.rs:309,830` — `.inverse().unwrap()` panics on zero divisor | High |
| **Batch prove is sequential** | `batch.rs:109–120` loop, no `rayon::par_iter()` | Medium |
| **No constant-time field arithmetic** | Subgroup checks leak timing via `mul_bigint(MODULUS)` | Medium |
| **`black_box()` for toxic waste** | `generator.rs` — not guaranteed volatile write; compiler may optimize out | Medium |
| **MSM failure not propagated** | `aggregation.rs:125,185` — `.expect("MSM failed")` panics instead of returning `Err` | Medium |

### 2.3 Test Coverage Gaps

| Module | Tests | Status |
|--------|-------|--------|
| `prover.rs` | 0 | **Missing** — core prover untested directly |
| `verifier.rs` | 0 | **Missing** — verifier untested directly |
| `generator.rs` | 0 | **Missing** — BatchMulPreprocessing untested |
| `sap.rs` | 1 | Poor |
| `aggregation.rs` | 3 | Minimal |
| `batch.rs` | 2 | Minimal |
| `kzg.rs` | 3 | Minimal |
| `pq_inner.rs` | 31 | Excellent |
| `folding.rs` | 13 | Good |

### 2.4 Performance Bottlenecks

| Bottleneck | Location | Potential Gain |
|------------|----------|----------------|
| Sequential batch proving | `batch.rs:109–120` | `k`× speedup where `k` = batch size |
| GPU MSM disabled | `optimizations.rs:806` | 5–20× for n > 2^12 |
| Aggregation accumulation sequential | `aggregation.rs:130–145` | 2–4× |
| ProverProfile not wired | `optimizations.rs:835–848` | 10–20% average |
| FFT strategy selection unused | `optimizations.rs` | 20–50% on sparse witnesses |

---

## 3. Competitive Gap Analysis

### 3.1 Head-to-Head Matrix

| System | Proof Size | Verify Time | Setup | Recursion | PQ | SE | Aggregation |
|--------|------------|-------------|-------|-----------|----|----|-------------|
| Groth16 | 192 B | 1.0ms | per-circuit | ❌ | ❌ | ❌ | ❌ |
| PLONK | 1 KB | 3–5ms | universal | limited | ❌ | ❌ | ❌ |
| Halo2 | 5–15 KB | 5–10ms | transparent | ★★★★★ | ❌ | ❌ | via recursion |
| Nova | 1.4 KB | 1–2ms | trusted SRS | ★★★★★ | ❌ | ❌ | via folding |
| Plonky2 | 45–100 KB | **0.17ms** | transparent | ★★★★★ | ❌ | ❌ | via tree |
| Binius | 256 B | 1–2ms | transparent | limited | **✅** | ❌ | ❌ |
| STARKs | 50–200 KB | 5–20ms | transparent | yes | **✅** | ❌ | yes |
| **UniGroth** | **192–256 B** | **1ms** | universal | ★★★★ | **✅** | **✅** | **✅** |

### 3.2 To Beat Each Competitor

| Competitor | What They Have We Lack | Priority |
|------------|------------------------|----------|
| Plonky2 | 170 μs recursive verify (FRI-based) | P1 |
| PLONK/Halo2 | Full plookup/LogUp/Lasso lookup arguments | P1 |
| Halo2 | Native recursive proof composition with Pasta curve pairs | P2 |
| STARKs/Binius | Transparent setup option (no SRS ceremony) | P2 |
| Jolt | Lasso generalized lookups (arbitrary function tables) | P2 |
| All | Working GPU MSM via Icicle | P1 |

---

## 4. Phase 1: Security Hardening + Critical Fixes (v0.4.2 — 2–3 weeks)

These are bugs and security gaps. Ship immediately.

### 4.1 Replace All `.unwrap()` in Production Paths

**Target**: All `unwrap`/`expect` outside `#[cfg(test)]` blocks.

- `folding.rs:338` — `GeneralEvaluationDomain::new().unwrap()` → return `SynthesisError`
- `folding.rs:454,466,473` — Serialization unwraps → `SynthesisError::AssignmentMissing`
- `aggregation.rs:125,185` — MSM unwraps → propagate `R1CSResult`
- `plonkish.rs:309,830` — Add zero-guard before `.inverse()`; return `SynthesisError` if zero
- `security.rs:101,514` — Replace with `?` operator

**Files**: `folding.rs`, `aggregation.rs`, `plonkish.rs`, `security.rs`

### 4.2 Fix Toxic Waste Zeroing

`generator.rs` uses `std::hint::black_box()` which is compiler-advisory only. Replace with:

```rust
// Use zeroize crate (already in Cargo.toml as of v0.4.0)
use zeroize::Zeroize;
alpha.zeroize();
beta.zeroize();
// ... all toxic waste scalars
```

**Files**: `generator.rs`

### 4.3 Wire ProverProfile Into Actual Prover

`ProverProfile::estimate_speedup()` computes the right FFT strategy but the result is discarded. Wire it:

```rust
// prover.rs: before FFT, query profile
let profile = ProverProfile::analyze(&cs);
let fft_strategy = profile.select_fft_strategy();
// Pass fft_strategy to FFT dispatch
```

**Files**: `prover.rs`, `optimizations.rs`

### 4.4 Parallelize Batch Proving

`batch.rs:109–120` loop is sequential. Replace with rayon:

```rust
use rayon::prelude::*;
let results: Vec<_> = circuits
    .par_iter()
    .zip(params.par_iter())
    .map(|(circuit, pk)| Groth16::prove(pk, circuit, rng))
    .collect();
```

**Files**: `batch.rs`

### 4.5 Add Unit Tests for Core Modules

Minimum viable coverage for `prover.rs`, `verifier.rs`, `generator.rs`:

- `prover.rs`: Test `create_random_proof` on known circuit, test randomness is circuit-bound, test zero-witness fails
- `verifier.rs`: Test correct proof passes, flipped bit fails, wrong inputs fail, empty inputs fail
- `generator.rs`: Test BatchMulPreprocessing on small R1CS, test toxic waste is zeroed after generate

Target: bring all modules to ≥ 5 direct unit tests.

---

## 5. Phase 2: Performance Wins (v0.5.0 — 1–2 months)

### 5.1 GPU MSM via Icicle (HIGHEST ROI)

**Estimated speedup**: 5–20× for circuits with n > 2^12 constraints.

Current `GpuMsmDispatcher` detects GPU eligibility correctly (`n > 4096`) but always CPU-falls back. Link the Icicle backend:

```toml
# Cargo.toml
[features]
gpu = ["icicle-bn254", "icicle-cuda-runtime"]

[dependencies]
icicle-bn254 = { version = "1.0", optional = true }
icicle-cuda-runtime = { version = "1.0", optional = true }
```

Wire into `GpuMsmDispatcher::dispatch()`:

```rust
#[cfg(feature = "gpu")]
fn dispatch_gpu(bases, scalars) -> G {
    icicle_bn254::msm::msm(bases, scalars)
}
```

**Files**: `optimizations.rs`, `Cargo.toml`

### 5.2 Lookup Arguments (Plookup + LogUp)

**Estimated circuit compression**: 2–5× on hash-heavy circuits.

Add `src/lookup.rs`:

- **Plookup** (sorted lookup tables): For range checks, boolean decompositions, XOR tables
- **LogUp** (log-derivative sumcheck): Multi-table lookup in O(n log n) instead of O(n²)
- Integrate with Plonkish constraint system via `LookupTable` enum

```rust
pub enum LookupArgument {
    Plookup(PlookupConfig),    // single table, logarithmic
    LogUp(LogUpConfig),        // multi-table, log-derivative
}
```

The Plonkish module already has `LookupTable { range_check, xor_table }` — extend to full plookup protocol.

**Files**: New `src/lookup.rs`, `plonkish.rs`

### 5.3 Custom Gate Library Expansion

Current Plonkish has: Poseidon S-box, boolean, 2-bit decomposition.

Add:

| Gate | Use Case | Circuit Reduction |
|------|----------|------------------|
| Full Poseidon round (all S-boxes + MDS) | ZK-friendly hashing | 3× fewer constraints |
| SHA-256 sigma/addition | Ethereum/Bitcoin compatibility | 5× fewer constraints |
| EC addition (complete, 5-wire) | Signature verification | 4× fewer constraints |
| Montgomery field mult | Modular arithmetic | 2× fewer constraints |
| Keccak-f round via lookup | zkEVM compatibility | 10× fewer constraints |

**Files**: `plonkish.rs`, new `src/gates/` directory

### 5.4 Batch Aggregation Parallelism

`aggregation.rs:130–145` input accumulation is sequential. Parallelize via rayon reduction:

```rust
let agg_inputs: Vec<_> = proofs
    .par_iter()
    .map(|(p, inputs)| prepare_inputs(pvk, inputs))
    .collect::<Result<_>>()?;

let final_acc = agg_inputs
    .par_iter()
    .zip(rs.par_iter())
    .map(|(inp, r)| inp.mul(*r))
    .reduce(G1::zero(), |a, b| a + b);
```

**Estimated speedup**: 2–4× for batch size ≥ 8.

**Files**: `aggregation.rs`

### 5.5 Benchmarking Suite Expansion

Current benchmarks exist but compare only against `ark-groth16`. Expand to include:

```
benches/
  groth16_comparison.rs   (existing)
  plonk_comparison.rs     (new — vs bellman PLONK)
  nova_comparison.rs      (new — vs microsoft/Nova)
  recursion_bench.rs      (new — recursive proof depth 1–16)
  lookup_bench.rs         (new — circuit with 1k lookups vs manual)
  gpu_bench.rs            (new — CPU vs GPU MSM at n=2^12,16,20)
  aggregation_bench.rs    (new — batch size 1,8,32,128)
```

**Files**: `benches/`

---

## 6. Phase 3: Feature Parity → Dominance (v0.6.0–v0.8.0 — 3–6 months)

### 6.1 Ultra-Fast Recursion (FRI-based, ~170 μs target)

**Goal**: Match Plonky2's 170 μs recursive verification overhead.

Two options (pick one):

**Option A — FRI polynomial commitments** (transparent, no pairing SRS):
- Replace KZG with FRI commitments in recursive context
- Enables Plonky2-style recursion speed
- Trade-off: larger proofs (5–10 KB), no pairings needed

**Option B — IPA with Pasta curve pairs** (Halo2 approach):
- Use Pallas/Vesta cycle for recursive accumulation
- Keeps algebraic structure but avoids SRS
- Trade-off: 5× larger proofs than Groth16 for final proof

**Recommendation**: Option A (FRI) for recursion-heavy use cases, keep KZG for single-proof use cases. Make configurable via feature flag.

**Architecture**:
```rust
pub enum PolynomialCommitment {
    Kzg(KzgConfig),   // fast single proof, 192B, trusted setup
    Fri(FriConfig),   // transparent, recursion-optimal, 10-50KB
    Ipa(IpaConfig),   // transparent, Pasta curves, 2-5KB
}
```

**Files**: New `src/commitment/`, `src/fri.rs`, `src/ipa.rs`

### 6.2 ZK Gadget Library (Foundation for zkVM/zkEVM)

Add `src/gadgets/`:

```
gadgets/
  mod.rs
  recursive_verifier.rs   — Groth16 verify inside constraint system
  poseidon_hash.rs        — algebraic hash gadget
  ecdsa_verify.rs         — secp256k1 signature verify in ZK
  eddsa_verify.rs         — Ed25519/JubJub signature
  range_check.rs          — strict range constraint (u8, u16, u32, u64, u128)
  memory_access.rs        — deterministic lookup for program counters
  merkle_proof.rs         — Merkle inclusion proof gadget
```

These enable:
- zkEVM inner proof generation
- ZK-rollup state transition proofs
- Nested recursive proofs

**Key**: `recursive_verifier.rs` lets UniGroth prove a Groth16 proof inside another Groth16 proof — enables arbitrary recursion depth without FRI.

### 6.3 Transparent Setup Option (Eliminate Ceremony)

Add `src/transparent.rs` with hash-based polynomial commitments as alternative to KZG:

- **Ligero** or **Brakedown** commitments — no trusted setup, square-root proof size
- Allows users to choose: `--feature trusted-kzg` (default, 192 B) vs `--feature transparent` (larger, no ceremony)
- Critical for regulatory environments that cannot trust any ceremony

```rust
// User-facing choice
pub enum SetupMode {
    Kzg { srs: UniversalSRS<E> },           // 192B proofs, ceremony required
    Transparent { security_bits: usize },    // 2-5KB proofs, no ceremony
}
```

### 6.4 Distributed Proving

For circuits too large for single machine (n > 2^22):

- **Distributed FFT**: Partition domain across workers, exchange boundary values
- **Distributed MSM**: Assign scalar ranges to workers, reduce at master
- **Network protocol**: Simple gRPC or tokio channel between proving nodes
- **Worker discovery**: Static config (`proving_cluster.toml`) initially

```toml
[proving_cluster]
master = "127.0.0.1:9001"
workers = ["127.0.0.1:9002", "127.0.0.1:9003"]
```

**Estimated speedup**: Near-linear with worker count for n > 2^20.

---

## 7. Phase 4: Moonshots (v0.9.0–v1.0.0 — 6–12 months)

### 7.1 Lasso Generalized Lookups (Jolt-style)

Lasso is the most powerful lookup argument known:
- Arbitrary function tables (not just range/boolean)
- O(n log n) prover, O(log n) verifier
- Enables: SHA-256, Keccak, AES, VM opcode tables

Requires: Sumcheck protocol implementation.

### 7.2 Adaptive Proving Strategy (Auto-Optimization)

Wire `ProverProfile` into a full runtime optimizer:

1. **Circuit analyzer**: Inspect sparsity, gate distribution, lookup density
2. **Strategy selector**: Pick FFT (4/5/6), MSM (CPU/GPU/distributed), lookup (plookup/LogUp/Lasso)
3. **Runtime dispatcher**: Execute selected strategy

Expected: 10–30% average speedup with zero user code changes.

### 7.3 zkVM Integration

Build a simple RISC-V zkVM on top of UniGroth:
- Gadgets for RISC-V opcode constraint system
- Memory access via Merkle proof gadget
- Program counter tracking via range check gadget
- Combines: lookup arguments + gadget library + distributed proving

### 7.4 Multi-Party Proving (MPC-Friendly)

Allow N parties to jointly prove without revealing individual witnesses:
- Distributed witness generation (each party holds their secret)
- Aggregated commitment reveal at end
- Applications: private ML inference, collaborative auditing

### 7.5 WebAssembly Target

```toml
[features]
wasm = ["wasm-bindgen", "getrandom/js"]
```

- Browser-compatible proof generation (limited to small circuits)
- Proof verification in browser (no server needed)
- Enable ZK applications in web without trust assumptions

---

## 8. Benchmarking Strategy: Proving Dominance

### 8.1 What to Measure

For each release, publish numbers across three circuit sizes:

| Circuit Size | Constraints | Typical Use |
|-------------|-------------|-------------|
| Small | 4,096 | Merkle proof, signature |
| Medium | 1,048,576 (2^20) | zkEVM block, rollup batch |
| Large | 67,108,864 (2^26) | Full blockchain state, zkVM |

For each: **setup time**, **prove time**, **verify time**, **proof size**, **memory peak**.

### 8.2 Competitors to Beat (per category)

| Category | Target to Beat | Current UniGroth | Target |
|----------|---------------|-----------------|--------|
| Proof size | Groth16 (192 B) | 192–256 B | 128 B (aggregated) |
| Single verify | Groth16 (1.0ms) | 1.01ms | 0.8ms |
| Batch verify (32) | PLONK batch | competitive | 0.05ms/proof |
| Recursive verify | Plonky2 (170 μs) | 1–5ms | < 500 μs |
| Prover throughput | Plonky2 | 1.16× Groth16 | 3× Groth16 |
| Transparent setup | STARKs | N/A (KZG) | option available |

### 8.3 CI Benchmark Gate

Add to CI: if any metric regresses > 5%, block merge.

```yaml
# .github/workflows/bench.yml
- name: Benchmark regression check
  run: cargo bench -- --baseline main 2>&1 | python scripts/check_regression.py --threshold 0.05
```

---

## 9. Implementation Timeline

```
Q2 2026 (now)
  v0.4.2  ──── Phase 1: Security hardening
               • Replace 123 unwraps in production paths
               • Fix plonkish.rs zero-divisor panic
               • Wire ProverProfile into prover
               • Parallelize batch prove
               • Add unit tests for prover/verifier/generator
               ETA: 2–3 weeks

  v0.5.0  ──── Phase 2: Performance
               • GPU MSM via Icicle (feature flag)
               • Plookup + LogUp lookup arguments
               • Custom gate library (Poseidon full, SHA-256, EC add)
               • Batch aggregation parallelism
               • Expanded benchmark suite
               ETA: 6–8 weeks

Q3 2026
  v0.6.0  ──── Phase 3a: Recursion
               • FRI-based fast recursion (target < 500 μs)
               • IPA option with Pasta curve pairs
               • PolynomialCommitment enum (kzg/fri/ipa)
               ETA: 6–8 weeks

  v0.7.0  ──── Phase 3b: ZK Gadgets + Transparent Setup
               • Gadget library (recursive verifier, ECDSA, Merkle, range)
               • Transparent setup option (Ligero/Brakedown)
               ETA: 6–8 weeks

Q4 2026
  v0.8.0  ──── Phase 3c: Distributed Proving
               • Distributed FFT + MSM
               • Worker cluster protocol
               • n > 2^22 circuit support
               ETA: 6–8 weeks

  v0.9.0  ──── Phase 4a: Moonshots
               • Lasso generalized lookups
               • Adaptive proving strategy
               • WebAssembly target
               ETA: 8–10 weeks

  v1.0.0  ──── Phase 4b: Production Release
               • zkVM integration (RISC-V opcodes)
               • MPC-friendly proving
               • Full audit (third-party)
               • 99.9% test coverage target
               ETA: 10–12 weeks
```

---

## 10. Unique Value Proposition After v1.0

UniGroth v1.0 will be the **only production zkSNARK system** combining:

1. **Groth16-scale proof size** (192 B baseline) — smallest in class
2. **Universal + transparent setup options** — no ceremony required if needed
3. **Simulation-extractability** (SE/BG18) — stronger security than all competitors
4. **Subversion zero-knowledge** — proven secure against malicious setup
5. **Folding + IVC** — ProtoStar with full decision predicate
6. **Ultra-fast recursion** — target < 500 μs (competitive with Plonky2)
7. **Full lookup argument suite** — Plookup, LogUp, Lasso
8. **Post-quantum migration** — Binius/Plonky3/Hybrid inner provers
9. **GPU acceleration** — Icicle backend for large circuits
10. **Distributed proving** — horizontal scale beyond single machine
11. **ZK gadget library** — enables zkEVM, zkVM, and recursive composition
12. **WebAssembly target** — browser-compatible proofs

**No other system has all 12. Most have 2–3.**

---

## 11. Appendix: File-Level Action Items

| File | Action | Phase |
|------|--------|-------|
| `folding.rs` | Replace 39 unwraps with `?` | P1 |
| `security.rs` | Replace 26 unwraps with `?` | P1 |
| `aggregation.rs` | Replace MSM panics, parallelize accumulation | P1+P2 |
| `plonkish.rs` | Zero-guard before `.inverse()` | P1 |
| `generator.rs` | Replace `black_box()` with `zeroize()` | P1 |
| `batch.rs` | Parallelize prove loop with rayon | P1 |
| `optimizations.rs` | Link Icicle GPU, wire ProverProfile | P1+P2 |
| `prover.rs` | Wire FFT strategy; add unit tests | P1+P2 |
| `verifier.rs` | Add unit tests | P1 |
| New `src/lookup.rs` | Plookup + LogUp implementation | P2 |
| New `src/gates/` | Custom gate library | P2 |
| New `src/commitment/` | FRI + IPA polynomial commitments | P3 |
| New `src/gadgets/` | ZK gadget library | P3 |
| New `src/transparent.rs` | Ligero/Brakedown transparent setup | P3 |
| `benches/` | Expand to 7-file benchmark suite | P2 |
| `.github/workflows/` | Add benchmark regression CI gate | P2 |

---

*Generated from codebase audit (123 unwraps, 12-module analysis) + competitive landscape research (10 competitor systems). All performance claims based on published benchmarks and arkworks benchmarking suite.*
