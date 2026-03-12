# UniGroth

UniGroth is a specialized implementation of the Groth16 SNARK designed for high-performance and simulation-extractable (SE) security. It integrates modern prover optimizations like Dynark 4-FFT and parallel multi-scalar multiplications (MSM) with robust security wrappers, providing a fast and reliable zero-knowledge proof system for production environments.

---

## Core Features

### Performance Improvements
- **Optimized FFT Execution**: We use the Dynark 4-FFT approach, allowing proof generation in 4 FFT steps rather than the standard 6, reducing the computational bottleneck.
- **Concurrent MSM Operations**: Major Multi-Scalar Multiplications (H, L, A, B_G1, and B_G2) are executed in parallel using Rayon, maximizing CPU utilization during proof generation.
- **Linear-Time Setup**: The h-query scalar computation has been optimized from $O(n \log n)$ to $O(n)$, speeding up trusted setup and pre-processing for large circuits.
- **Allocation Efficiency**: The prover's internal logic has been refactored to use slices for assignments, avoiding redundant memory copies and lowering the memory footprint.

### Security and Flexibility
- **Simulation-Extractability (SE)**: Built-in support for BG18 and ROM blinding techniques helps prevent malleable proof attacks.
- **Square Arithmetic Programs (SAP)**: Provides an alternative arithmetization that can outperform standard R1CS in specific use cases.
- **Universal Setup Support**: Designed to work with updatable trusted setups, making it compatible with modern powers-of-tau ceremonies.

---

## Project Structure

- **UniGroth**: The core Rust library where the SNARK logic lives.
- **src**: Node.js implementation for proof handling, commitment schemes, and field arithmetic.
- **phrase.circom**: An example circuit for "secret phrase" proofs.
- **verifier.sol**: A gas-optimized Solidity verifier for on-chain proof validation.

---

## Getting Started

### Prerequisites
- **Rust**: Latest stable or nightly (nightly recommended for peak performance).
- **Node.js**: Long-term support (LTS) version.
- **Circom**: Required for compiling the arithmetic circuits.

### Setup and Testing
1. Clone the project and install dependencies:
   ```bash
   git clone https://github.com/MeridianAlgo/UniGroth.git
   cd UniGroth
   npm install
   ```
2. Build and test the Rust implementation:
   ```bash
   cd UniGroth
   cargo build --release
   cargo test --release
   ```

---

## Contributions and Development
We focus on maintaining a balance between cutting-edge SNARK research and practical, high-speed implementations. If you are interested in zero-knowledge optimizations or security hardening, feel free to dive into the codebase.

---

## License
This project is available under the Apache License 2.0 or the MIT License.
