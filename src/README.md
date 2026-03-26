# UniGroth — JavaScript / Circom Reference Implementation

This directory contains a JavaScript reference implementation and Circom circuit definition for the phrase-knowledge proof used in early UniGroth prototyping.

> **Note:** The production implementation is the Rust library in `../UniGroth/`. This JS layer is a reference/tooling aid.

## Files

| File | Purpose |
|------|---------|
| `index.js` | Entry point — orchestrates circuit compilation, proof generation, and verification |
| `circuit.js` | Circom circuit wrapper — compiles `phrase.circom` and generates witness |
| `field.js` | BN254 field arithmetic helpers (addition, multiplication, modular inverse) |
| `commitment.js` | SHA-256 commitment scheme for the phrase preimage |
| `prover.js` | snarkjs-based Groth16 prover wrapper |
| `verifier.js` | snarkjs-based Groth16 verifier wrapper |

## Usage

```bash
# Install dependencies
npm install

# Run the full pipeline
node src/index.js

# Compute the phrase hash (for generating test inputs)
node compute_hash.js
```

## Circuit

`phrase.circom` defines a circuit that proves knowledge of a phrase whose SHA-256 hash matches a public commitment — without revealing the phrase. Used for demonstration purposes.

## Relation to Rust Implementation

The Rust library (`../UniGroth/`) provides all production features: universal setup, simulation-extractability, folding, aggregation, and Solidity verifier generation. This JS layer uses standard snarkjs/Groth16 and is kept for tooling compatibility.
