# UniGroth — Integration Tests

This directory contains integration and comparison tests that exercise the full UniGroth pipeline end-to-end.

## Test Suites

### `mimc.rs` — MiMC Hash Circuit (1 test)

End-to-end test using a real MiMC hash circuit:
- Builds an R1CS constraint system from the MiMC round function
- Generates a proving key and verifying key
- Proves knowledge of the preimage
- Verifies the proof via the full SE verifier path

This is the canonical "does it actually work on a real circuit" test.

### `phrase_test.rs` — Advanced Features (1 test)

Exercises the full UniGroth feature set in a single pipeline:
- Universal setup (KZG SRS + circuit-agnostic key derivation)
- Simulation-extractable proving (ROM blinding)
- Proof aggregation (N-to-1 compression)
- Folding/IVC step execution
- VK compression and streaming prover

### `full_pipeline_test.rs` — Module Integration (6 tests)

One test per major UniGroth subsystem:

| Test | What It Covers |
|------|---------------|
| `test_full_pipeline_prove_verify_aggregate` | Core prove → verify → aggregate pipeline |
| `test_universal_setup_pipeline` | KZG SRS → `UniversalParams` → circuit key derivation |
| `test_folding_ivc_pipeline` | ProtoStar folding, cross-terms, IVC accumulation |
| `test_plonkish_full_pipeline` | Custom gates, lookup tables, Plonkish→R1CS conversion |
| `test_optimization_pipeline` | 4-FFT, CSR sparse QAP, parallel MSM, VK compression |
| `test_pq_inner_full_pipeline` | Binius, Plonky3, Hybrid prove+verify+aggregate |

### `groth16_comparison.rs` — Head-to-Head vs ark-groth16 (11 tests)

Systematic comparison demonstrating UniGroth's superiority:

| Test | What It Proves |
|------|---------------|
| `compare_correctness_both_verify_same_circuit` | UniGroth produces valid proofs on the same circuit as ark-groth16 |
| `compare_proof_size_unigroth_competitive` | UniGroth proof size stays within 192-256 bytes |
| `compare_optimizations_unigroth_superior` | Optimization layer measurably faster than vanilla Groth16 |
| `compare_security_unigroth_strictly_superior` | SE, Subversion ZK, PoK all absent from ark-groth16 |
| `compare_universal_setup_unigroth_exclusive` | Universal setup unavailable in ark-groth16 |
| `compare_folding_ivc_unigroth_exclusive` | Folding/IVC unavailable in ark-groth16 |
| `compare_aggregation_unigroth_exclusive` | Proof aggregation unavailable in ark-groth16 |
| `compare_plonkish_unigroth_exclusive` | Plonkish arithmetization unavailable in ark-groth16 |
| `compare_pq_path_unigroth_exclusive` | PQ inner provers unavailable in ark-groth16 |
| `compare_public_input_pok_unigroth_exclusive` | Public input PoK unavailable in ark-groth16 |
| `compare_feature_matrix_summary` | Full feature matrix summary assertion |

## Running Tests

```bash
# All 156 tests
cargo test

# Integration only
cargo test --test mimc
cargo test --test phrase_test
cargo test --test full_pipeline_test
cargo test --test groth16_comparison

# With output (useful for understanding what each test does)
cargo test -- --nocapture
```

## Test Results

```
test result: ok. 137 passed; 0 failed  (unit tests)
test result: ok.   6 passed; 0 failed  (full_pipeline_test)
test result: ok.  11 passed; 0 failed  (groth16_comparison)
test result: ok.   1 passed; 0 failed  (mimc)
test result: ok.   1 passed; 0 failed  (phrase_test)
────────────────────────────────────────
Total:            156 passed; 0 failed
```
