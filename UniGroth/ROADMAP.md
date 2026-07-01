# UniGroth Roadmap

*Last updated: 2026-06-30. Reflects the actual v0.7.0 tree, not aspirations.*

---

## 0. Read this first

The previous roadmap (dated 2026-05-10) told you to *create* `lookup.rs`, `gates.rs`,
`commitment.rs`, `transparent.rs`, `lasso.rs`, and `zkvm.rs`. All of them already exist.
It listed zeroing toxic waste and parallelizing batch proving as open work. Both are
already done. A roadmap that doesn't match the tree is worse than no roadmap, so this one
starts from what is actually on disk.

**The honest problem is not "we're missing features." It's the opposite.** This crate has
~19,500 LOC across 40 modules, most of them advertising a headline zk feature. The last
five commits before this roadmap were all *walking back overclaims* in the README and docs.
That is the signal. The work ahead is **closing the gap between what the code claims and
what has been verified sound** — not adding a 41st module.

"Beat every competitor at everything" is not on this roadmap, on purpose. No zkSNARK wins
that way. Groth16 wins on proof size, Plonky2 on recursion speed, STARKs on transparency —
each by being the best at *one* thing. Chasing all of them at once is what produced 40
half-audited modules and a README that needed five corrections. This roadmap picks a lane.

---

## 1. Verified state of the tree (v0.7.0)

Built with `cargo build --release` → **exit 0**. ~250 `#[test]` across 33 modules, all
passing per the badges. That is real and worth stating.

What "passing tests" does and does not tell you:
- It tells you the code compiles and is internally self-consistent.
- It does **not** tell you a forged or malformed proof is rejected, or that a protocol
  matches its paper. Most modules test "my prover's output verifies," which is necessary
  but proves nothing about soundness. `pq_inner` has 31 passing tests and, per the README,
  is still not a sound post-quantum argument. Treat every other novel path the same way
  until it has negative tests.

### Module status — honest labels

| Status | Meaning |
|--------|---------|
| **Core** | Classical Groth16 path, inherited from `ark-groth16`. Battle-tested upstream. |
| **Done** | Verified complete in this session. |
| **Stub** | Advertised but not wired; falls back or no-ops. |
| **Scaffold** | Present and self-consistent, but explicitly *not* the sound protocol it names. |
| **Unaudited** | Compiles + self-tests pass; soundness (forgery-rejection, paper-fidelity) unverified. |

| Module | Status | Note |
|--------|--------|------|
| `prover.rs` / `verifier.rs` / `generator.rs` / `r1cs_to_qap.rs` | Core | Classical Groth16. `generator.rs` now `zeroize()`s toxic waste (Done). |
| `batch.rs` | Done | Parallel prove via `par_iter`. |
| `optimizations.rs` (GPU MSM) | **Stub** | `dispatch()` always CPU-falls-back; icicle not linked. README/roadmap must not claim GPU. |
| `pq_inner.rs` | **Scaffold** | SHA-256 commitment/binding, tamper-evident. NOT a zero-knowledge PQ argument. Already flagged in README. |
| `lasso.rs`, `lookup.rs` | Unaudited (good coverage) | Have real rejection tests (out-of-range, wrong-sum, tampered-round, query-not-in-table, tampered-sorted) — all pass. Soundness *parameters* still unaudited. |
| `gates.rs`, `gadgets.rs` | Unaudited | Mostly constraint-*count* assertions, not satisfaction/soundness. Verify what they enforce, not just their size. |
| `recursion.rs` | Unaudited | Has tamper/empty-chain rejection tests that pass. |
| `zkvm.rs` | **Scaffold** | Symbolic constraint *counter*, not a system: `ZkvmConstraint` is `{kind, step_idx, description}` with no field values, no witness, no satisfaction check, no prove/verify. The "RISC-V zkVM" is a circuit-sizing estimator. Docstrings corrected 2026-06-30. |
| `commitment.rs` (FRI/IPA) | Unaudited | Real FRI/IPA; verify + tamper tests pass. Soundness *parameters* (query count, security bits) unverified. |
| `transparent.rs` | **Scaffold** | No `commit`/`open`/`prove`/`verify` — only config enums + `estimate_bytes()` size estimates. The "transparent setup" headline is a sizing calculator; the real FRI/IPA in `commitment.rs` is NOT wired into any transparent setup/prove/verify flow. See audit note. |
| `folding.rs`, `aggregation.rs`, `plonkish.rs`, `mpc.rs` | Unaudited | Same caveat. `folding.rs` has 39 non-test `unwrap()`s — not yet audited for reachability the way the verify/PoK/aggregation paths were. |
| `universal_setup.rs`, `key_compression.rs`, `public_input_pok.rs`, `adaptive.rs`, `streaming.rs`, `sap.rs` | Unaudited | — |
| `solidity.rs`, `wasm_verifier.rs`, `auth.rs` | Unaudited | Solidity verifier checks the classical core only. |

Everything under "Unaudited" may well be correct. The point is nobody has *shown* it, and
the docstrings assert completeness anyway. That's the debt.

---

## 2. The lane: smallest-proof simulation-extractable SNARK

The one defensible, genuinely-differentiated claim in this repo is:

> A Groth16-core SNARK (192–256 B proofs, 3-pairing verify) with **simulation-extractability**
> and **subversion-ZK** on the default path, at near-zero overhead over vanilla Groth16.

That is a real, narrow, checkable claim, and no mainstream library ships it as the default.
Everything else — universal setup, folding, aggregation, PQ, lookups, zkVM — should be
positioned as **separate experimental paths**, not headline features, until each is audited.

Recommendation: make the crate *excellent and trustworthy* on this one lane first. A small
SE-Groth16 that a user can actually depend on beats twelve features they can't.

---

## 3. Prioritized work (real, not aspirational)

### P0 — Robustness & honesty

**Status: audited 2026-06-30 — the attacker-reachable part is already done.** The earlier
version of this section (inherited from the 2026-05-10 roadmap) claimed ~230 `unwrap()`s and
several `.inverse().unwrap()` sites were exploitable panics. That was wrong; the audit found
every flagged site already guarded or structurally unreachable:

- `verifier.rs` verify path: no non-test unwraps at all.
- `verify_public_input_pok` (`public_input_pok.rs:152,155`): guarded — line 139 returns
  `false` on any length mismatch before the MSMs, so they cannot fail.
- Inversion sites (`prover.rs:270`, `generator.rs:111`, `universal_setup.rs:199`,
  `plonkish.rs:309,834`): each divisor is a nonzero-forced loop variable, setup randomness
  (nonzero w.p. `1−2⁻²⁵⁴`, same as upstream `ark-groth16`), or already behind an `is_zero()`
  guard. Two of them are in `#[test]` code.
- `aggregate_proofs` (`aggregation.rs:156`): prover-side, `powers.len() == c_bases.len()` by
  construction, so the `.expect` is unreachable.
- The remaining unwraps are in setup/prove (your own trusted input), tests, or
  `serialize_compressed(&mut Vec)` — I/O to a `Vec` is infallible.

Conclusion: **do not do a mechanical 230-site `unwrap→Result` sweep.** It would add dead
guards to crypto paths for no security gain. A `#![deny(clippy::unwrap_used)]` gate is also
not worth it — clippy can't see the runtime guards and would demand `#[allow]` noise
everywhere.

Remaining P0 (small, real):
1. **Optional polish:** turn `aggregate_proofs`' `.expect("G1 MSM failed")` and the PoK
   prove-side MSM `unwrap`s into `debug_assert!`-backed comments or a returned error *only if*
   these functions are ever moved to a public API that takes untrusted lengths. Today they
   don't, so this is cosmetic. Left as a `ponytail:` marker, not urgent work.
2. **Keep README and this file honest.** GPU is a stub → don't imply otherwise anywhere.
   PQ is a scaffold → keep saying so. This is the cheapest security work there is, and the
   only P0 item that actually needs ongoing attention.

### P1 — Turn claims into verified truth (the actual differentiator work)

For each **Unaudited** module, add the tests that would fail if it were broken:
- **Negative tests:** a proof of a false statement, a bit-flipped proof, wrong public
  inputs, and empty inputs must all be *rejected*. This is what "tests pass" is currently
  missing.
- **Cross-check against `ark-*`** where an equivalent exists.
- Promote a module out of "Unaudited" in the table above only when it has negative tests.

Start with the lane (§2): `prover.rs`, `verifier.rs`, `public_input_pok.rs`, and the SE
blinding path. These carry the headline claim, so they earn verification first.

**Lane audit progress (2026-06-30):**
- `verifier.rs` and `public_input_pok.rs` already had solid forgery-rejection coverage
  (flipped-A, wrong-inputs, tampered-response/commitment, cross-proof non-malleability).
  The roadmap's "most modules only test happy path" is too pessimistic *for the lane*.
- Added to `verifier.rs`: identity-point rejection (A=0, C=0), flipped-C, and wrong-arity
  input rejection (0 and 2 inputs against a 1-input statement) — exercising the documented
  identity-attack guard and the `prepare_inputs` length guard.
- **Subtlety worth recording:** a *rerandomized* Groth16 proof still verifies, and that is
  correct — SE does not require verify to reject a rerandomization of your own valid proof
  (you still know the witness). The default path's SE is a proving-time/ROM property, not a
  verify-time rejection. Do not "fix" this with a test asserting rerandomized proofs fail;
  it would be wrong. The real SE claim needs an extractability argument or audit, not a
  behavioral test — that stays open.
- Added to `security.rs`: the explicit BG18 4-pairing path (`se_element = Some(D)`) had
  acceptance untested — `test_bg18_blinding` only asserted `D` is *present*, never ran a
  genuine BG18 proof through `verify_sim_extractable`. New test verifies a real BG18 proof
  accepts, and that tampering `D` or the blinded `A'` is rejected.
- **BG18 was BROKEN — bug found and fixed (2026-06-30).** The new acceptance test exposed
  that a genuine BG18 proof was *rejected by its own verifier*. `make_sim_extractable` set
  the blinding element `D = ρ·δG₂`, but `A' = A + ρ·δ_g1` introduces a factor `e(δ_g1,B)^ρ`
  into the pairing equation that only `D = ρ·B` cancels (`e(δ_g1, ρB − D) = 1`). Fixed to
  `D = ρ·proof.b`. The whole BG18 path was non-functional and untested-at-acceptance until
  now — a concrete example of why P1 (run the *acceptance* case, not just "field present")
  matters. NOTE: this fixes *functionality*; the SE security of the corrected construction
  still needs the extractability argument/audit noted below.
- Remaining lane gap: an actual extractability/soundness *argument* for the SE claim (not a
  behavioral test). That is audit/paper work, still open.

**Folding audit (2026-06-30) — a real incompleteness found:**
- `FoldingAccumulator` carries `acc_e` ("error term commitment"), but `verify_decision_predicate`
  never checks the prover-supplied `error_vector` against `acc_e` for `fold_count > 1`.
  `verify_accumulator` only checks `acc_e == 0` at `fold_count == 1` (Check 3). So the error
  commitment is decorative at verification time — an incompleteness versus the ProtoStar/Nova
  spec the module cites, where the folded error commitment is a first-class checked object.
- It is not *obviously* exploitable in the current code: Step 4 pins the witness via the KZG
  commitment `acc_w`, and given a pinned witness + `μ` the error is forced by the Step 3
  equation. But two things make this fragile: (a) Step 4 is **skipped entirely when
  `acc_w` is `None`** (empty-witness accumulators have neither witness nor error binding);
  (b) any future change that relaxes the witness commitment check turns the free error term
  into a soundness break.
- Root cause: `FoldingEngine` never received the constraint system, so it *couldn't* fold
  the real relaxed-R1CS error — `acc_e` was built from `compute_cross_term_scalar`, an ad-hoc
  inner-product heuristic that doesn't even use the R1CS matrices, unrelated to the
  per-constraint `compute_cross_term_vector` the decision predicate uses.

**Fix implemented 2026-06-30 (UNVERIFIED — see caveat):**
- `FoldingEngine` is now constraint-aware: `new_with_constraints(srs, matrices)` makes the
  engine fold the *real* per-constraint error vector (via `compute_cross_term_vector`),
  maintain the `ProverState` internally, and commit it into `acc_e` via `commit_error_vector`
  (a KZG-style coefficient commitment Σᵢ powersᵢ·eᵢ over the SRS). `prover_state()` exposes
  the folded state for the verifier.
- `verify_decision_predicate` gained Step 5: `acc_e == commit_error_vector(error_vector)`,
  so the error term is now bound. Fresh single-instance accumulators are unaffected (both
  sides are the identity).
- Legacy `new(srs)` is preserved (heuristic `acc_e`, unbound) so non-constraint callers
  (`IVC`) still compile; `IVC` should migrate to the constraint-aware path next.
- The three multi-fold decision-predicate tests were migrated to the sound engine path;
  `test_decision_predicate_rejects_tampered_error` pins error rejection.
- **CAVEAT:** none of this could be compiled or tested locally — the machine's WDAC policy
  now blocks cargo build-script executables (`zerocopy`) even for the library build. The
  change was type-reviewed by hand only. **It must be `cargo build` + `cargo test`'d in CI
  before it is trusted or merged.** If CI is not immediately available, treat this commit as
  a proposal, not a verified fix.
- **Test execution is blocked in the current environment** by a Windows Application Control
  (WDAC) policy that refuses freshly-built, unsigned cargo build-script executables in the
  dev-dependency subtree. The release *library* builds clean; only the test harness is
  affected. Run `cargo test` in CI or an unrestricted shell to confirm the added tests.

### P2 — Finish or delete the stubs (stop half-shipping)

- **GPU MSM:** either link icicle behind the `gpu` feature and benchmark it, or delete the
  dispatcher and the GPU language. A stub that pretends is worse than an honest gap.
  - *Decision taken 2026-06-30: CUT the GPU language, keep the working CPU path.* Linking
    icicle needs CUDA hardware that can't be tested/verified here, so "link" is out of scope.
    Rewrote `GpuMsmDispatcher`'s docstring to state it is CPU-only and that the `gpu` feature
    is an inert extension point (no acceleration), so nothing advertises GPU that doesn't
    exist. The dispatcher's body was already honest (CPU fallback + warning). Remaining: purge
    any residual "GPU acceleration" wording from README/benchmarks if present.
- **`pq_inner`:** decide — is UniGroth building a real FRI/sumcheck PQ argument, or is this
  a binding gadget? If the former, that's a multi-month project and belongs as its own
  crate; if the latter, rename it so nobody mistakes it for a SNARK.

### P3 — Performance, measured (no new features)

Profile the classical prove/verify path (the lane) and optimize hotspots with before/after
`criterion` numbers checked into `benches/`. No optimization lands without a measurement.
Likely candidates already noted upstream: MSM window sizing, FFT coset work (last commit
already cut this), witness-map allocation. Add a CI gate that blocks >5% regression.

### Not on the roadmap (deliberately)

- New feature modules before the existing ones are audited.
- Matching Plonky2 recursion latency, Jolt lookups, or "everything STARKs do." Different
  lane; revisit only if the P1 audit work proves the core is trustworthy first.
- Any "beat everyone at everything" headline. It's not a plan; it's the thing that caused
  the debt.

---

## 4. Sequencing

```
P0  Robustness & honesty        ~1 week    unwraps → Result, zero-guards, honest docs
P1  Soundness verification      ongoing    negative tests, lane-first; audit gate per module
P2  Finish/delete stubs         as decided GPU: link or cut. PQ: build-real or rename.
P3  Measured perf               ongoing    profile lane, criterion diffs, CI regression gate
```

No calendar promises. The old roadmap's Q2/Q3/Q4 grid aged badly in six weeks; dates on
research work are fiction. Ship P0, then let P1 set the pace.

---

## 5. Definition of "done" for v1.0

Not "has 12 features no one else has." Instead:

1. Malformed input never panics a verifier. (Audited true today for the classical + PoK +
   aggregation paths; must be re-checked for each module as it leaves "Unaudited".)
2. Every module either has forgery-rejection tests or is clearly labeled experimental.
3. No stub advertised as a working feature anywhere in the repo.
4. The SE-Groth16 lane (§2) has a third-party audit or a written, reproducible soundness
   argument.
5. README claims and code capabilities match with zero correction commits needed.

That is a library people can trust. Trust is the moat here — not feature count.
