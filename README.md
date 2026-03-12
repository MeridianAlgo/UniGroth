# UniGroth ⚡

**UniGroth** is a high-performance, simulation-extractable (SE) implementation of the Groth16 SNARK. It combines state-of-the-art prover optimizations (like Dynark 4-FFT and parallel MSMs) with advanced security wrappers to provide a fast and secure zero-knowledge proof system.

---

## 🔥 Key Features

### 🚀 Performance Optimizations
- **Dynark 4-FFT**: Proof generation requires only **4 FFTs** instead of the standard 6, significantly reducing computation overhead.
- **Parallel MSM**: Prover Multi-Scalar Multiplications (MSMs) for $H, L, A, B_{G1},$ and $B_{G2}$ follow a concurrent execution path using `rayon`.
- **$O(n)$ Setup**: Optimized `h_query` scalar computation from $O(n \log n)$ to $O(n)$ using successive multiplication.
- **Zero-Allocation Prover**: Modified `calculate_coeff` logic to process assignments through slices, eliminating redundant memory copies.

### 🛡️ Security & Arithmetization
- **Simulation-Extractability (SE)**: Integrated BG18 and ROM blinding techniques to prevent proof malleability.
- **Square Arithmetic Programs (SAP)**: Optional arithmetization that is more efficient than standard R1CS for certain circuit types.
- **Updatable Setup**: Supports universal trusted setups compatible with powers-of-tau ceremonies.

---

## 🏗️ Project Structure

- `/UniGroth`: The core Rust implementation of the SNARK.
- `/src`: Node.js logic for proof generation, commitment schemes, and field arithmetic.
- `phrase.circom`: A sample circuit demonstrating the "secret phrase" proof of knowledge.
- `verifier.sol`: A performance-optimized Solidity contract for on-chain verification.

---

## 🛠️ Getting Started

### Prerequisites

- **Rust**: `cargo` (nightly recommended for best performance)
- **Node.js**: `npm`
- **Circom**: To compile `.circom` files

### Installation

```bash
# Clone the repository
git clone https://github.com/MeridianAlgo/UniGroth.git
cd UniGroth

# Install JS dependencies
npm install

# Build the Rust core
cd UniGroth
cargo build --release
```

### Running Tests

```bash
# Run all Rust integration tests
cargo test --release
```

---

## 📜 Usage Example

To generate a proof for the `phrase` circuit:

1. **Compile the circuit**:
   ```bash
   circom phrase.circom --r1cs --wasm --sym
   ```
2. **Generate Witness**: Use the provided `src/prover.js` or `snarkjs`.
3. **Generate Proof**:
   ```rust
   let proof = Groth16::<Bn254>::create_proof_with_reduction(circuit, pk, r, s)?;
   ```

---

## ⚖️ License

This project is licensed under the Apache License 2.0 or the MIT License.
