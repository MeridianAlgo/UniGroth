# UniGroth Quick Start Guide

Get up and running with UniGroth in minutes.

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

Install Rust via rustup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

### Add UniGroth to Your Project

Add to your `Cargo.toml`:
```toml
[dependencies]
unigroth = { git = "https://github.com/MeridianAlgo/UniGroth.git" }
ark-bn254 = { git = "https://github.com/arkworks-rs/algebra.git", features = ["curve"] }
ark-relations = { git = "https://github.com/arkworks-rs/snark.git" }
ark-std = "0.5.0"
```

## Your First Proof

Here's a complete example proving knowledge of a square root:

```rust
use ark_bn254::{Bn254, Fr};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_std::UniformRand;
use unigroth::{
    Groth16, Proof, ProvingKey, VerifyingKey,
    prepare_verifying_key, verify_proof,
};

// Circuit: prove you know x such that x² = public_input
#[derive(Clone)]
struct SquareRootCircuit {
    // Private witness
    x: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareRootCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // Allocate private input
        let x = cs.new_witness_variable(|| {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public input (x²)
        let x_squared = cs.new_input_variable(|| {
            let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x_val * x_val)
        })?;

        // Constraint: x * x = x_squared
        cs.enforce_constraint(
            lc!() + x,
            lc!() + x,
            lc!() + x_squared,
        )?;

        Ok(())
    }
}

fn main() {
    let mut rng = ark_std::test_rng();

    println!("Setting up...");
    
    // Setup phase (one-time per circuit)
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        SquareRootCircuit { x: None },
        &mut rng,
    ).expect("Setup failed");

    println!("Generating proof...");

    // Prover: knows x = 3
    let x = Fr::from(3u32);
    let circuit = SquareRootCircuit { x: Some(x) };
    
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .expect("Proving failed");

    println!("Verifying proof...");

    // Verifier: only knows x² = 9
    let x_squared = x * x;
    let public_inputs = vec![x_squared];

    let pvk = prepare_verifying_key(&vk);
    let valid = verify_proof(&pvk, &proof, &public_inputs)
        .expect("Verification failed");

    println!("Proof is valid: {}", valid);
    assert!(valid);
}
```

## Running the Example

```bash
cargo run --example square_root
```

## Common Patterns

### 1. Range Proof

Prove a value is within a range without revealing it:

```rust
struct RangeCircuit {
    value: Option<Fr>,
    min: Fr,
    max: Fr,
}

impl ConstraintSynthesizer<Fr> for RangeCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let value = cs.new_witness_variable(|| {
            self.value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce: value >= min
        // Enforce: value <= max
        // (Implementation details omitted for brevity)

        Ok(())
    }
}
```

### 2. Merkle Tree Membership

Prove you know a leaf in a Merkle tree:

```rust
use ark_crypto_primitives::{
    crh::CRHScheme,
    merkle_tree::{Config, Path},
};

struct MerkleTreeCircuit<C: Config> {
    leaf: Option<C::Leaf>,
    path: Option<Path<C>>,
    root: C::InnerDigest,
}

// Implementation uses ark-crypto-primitives gadgets
```

### 3. Signature Verification

Prove you have a valid signature:

```rust
use ark_crypto_primitives::signature::SignatureScheme;

struct SignatureCircuit<S: SignatureScheme> {
    public_key: S::PublicKey,
    message: Vec<u8>,
    signature: Option<S::Signature>,
}
```

## Performance Tips

### 1. Use Parallel Features

Enable parallel proving:
```toml
[dependencies]
unigroth = { git = "...", features = ["parallel"] }
```

### 2. Reuse Prepared Keys

Prepare verification keys once:
```rust
let pvk = prepare_verifying_key(&vk);
// Reuse pvk for multiple verifications
```

### 3. Batch Verification

Verify multiple proofs efficiently:
```rust
// Coming in future versions
Groth16::batch_verify(&pvk, &proofs, &public_inputs)?;
```

## Debugging

### Enable Tracing

```toml
[dependencies]
unigroth = { git = "...", features = ["print-trace"] }
```

```rust
use ark_std::start_timer;

let timer = start_timer!(|| "Proving");
let proof = Groth16::prove(&pk, circuit, &mut rng)?;
end_timer!(timer);
```

### Check Constraint Satisfaction

```rust
use ark_relations::r1cs::ConstraintSystem;

let cs = ConstraintSystem::<Fr>::new_ref();
circuit.generate_constraints(cs.clone())?;

println!("Number of constraints: {}", cs.num_constraints());
println!("Is satisfied: {}", cs.is_satisfied()?);
```

## Testing Your Circuits

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_square_root_circuit() {
        let mut rng = ark_std::test_rng();
        
        // Setup
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            SquareRootCircuit { x: None },
            &mut rng,
        ).unwrap();

        // Test with valid witness
        let x = Fr::from(5u32);
        let circuit = SquareRootCircuit { x: Some(x) };
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        
        let public_inputs = vec![x * x];
        let pvk = prepare_verifying_key(&vk);
        assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());

        // Test with invalid public input (should fail)
        let wrong_inputs = vec![Fr::from(100u32)];
        assert!(!verify_proof(&pvk, &proof, &wrong_inputs).unwrap());
    }
}
```

## Supported Curves

UniGroth supports multiple pairing-friendly curves:

```rust
use ark_bn254::Bn254;      // BN254 (fast, 128-bit security)
use ark_bls12_381::Bls12_381;  // BLS12-381 (standard, 128-bit)
use ark_bls12_377::Bls12_377;  // BLS12-377 (for recursion)
use ark_bw6_761::BW6_761;      // BW6-761 (for BLS12-377 recursion)

// Use any curve with Groth16
let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
```

## Next Steps

- Read the [README](README.md) for project overview
- Check [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
- See [ROADMAP.md](ROADMAP.md) for upcoming features
- Browse [examples/](examples/) for more complex circuits
- Join discussions on GitHub

## Common Issues

### "Assignment Missing" Error

Make sure all witness variables have values:
```rust
// Bad
let x = cs.new_witness_variable(|| Ok(self.x))?;

// Good
let x = cs.new_witness_variable(|| {
    self.x.ok_or(SynthesisError::AssignmentMissing)
})?;
```

### Constraint Not Satisfied

Check your constraint logic:
```rust
// Verify constraints are correct
let cs = ConstraintSystem::<Fr>::new_ref();
circuit.generate_constraints(cs.clone())?;
println!("Satisfied: {}", cs.is_satisfied()?);
```

### Slow Proving

- Enable `parallel` feature
- Use release mode: `cargo build --release`
- Consider circuit optimization (fewer constraints)

## Getting Help

- GitHub Issues: https://github.com/MeridianAlgo/UniGroth/issues
- Discussions: https://github.com/MeridianAlgo/UniGroth/discussions
- arkworks Discord: https://discord.gg/arkworks

---

Happy proving! 🚀
