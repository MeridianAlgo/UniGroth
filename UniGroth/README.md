# unigroth (crate)

Rust library for UniGroth: an extension of `ark-groth16` with a faster prover, stricter verifier checks, Fiat-Shamir batch verification, a circuit library, Solidity/WASM verifier generation, and documented research modules.

Full documentation, benchmarks against ark-groth16, and the list of research-module limits are in the [project README](../README.md). Changes are in [CHANGELOG.md](CHANGELOG.md).

```bash
cargo test --workspace                                     # all tests
cargo clippy -- -D warnings                                # lints, as CI runs them
cargo bench --bench groth16-benches --features "std parallel" -- --nocapture
cargo run --release --features compare --bin compare       # head-to-head vs ark-groth16
cargo run --release --features auth-bin --bin auth_setup -- --out keys/
```

Global constants (security level, Poseidon parameters, Fiat-Shamir domain tags) are in `src/config.rs` (`unigroth::config`).

**Research software. Audit before production or mainnet use.**

## License

MIT or Apache 2.0, at your option.
