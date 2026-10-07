//! # UniGroth
//!
//! Groth16 with a verifiable universal setup and a hardened verifier, built on
//! [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16).
//!
//! - **Groth16 core**: setup, prove, verify; proofs are plain Groth16 (128
//!   bytes on BN254).
//! - **Hardened verification**: every verifier (single, batch, aggregate)
//!   rejects identity, off-curve and wrong-subgroup proof points; batch
//!   verification uses Fiat-Shamir challenges bound to the whole batch.
//! - **Universal setup** ([`universal_setup`]): BGM17-style Phase 1 powers of
//!   τ plus a per-circuit Phase 2 for δ, with proofs of knowledge, transcript
//!   checks and a random-beacon final step.
//! - **Circuits**: Poseidon, Merkle, range checks, a MiMC auth circuit and a
//!   small circuit builder; Solidity/WASM verifier generation (feature `solidity`).
//!
//! **Research software. Not audited.** Groth16 proofs are rerandomizable (not
//! simulation-extractable): bind context such as a sender or nonce into the
//! public inputs if that matters.
//!
//! ## Experimental modules
//!
//! Folding, FRI/IPA commitments, the "post-quantum" inner provers, recursion,
//! MPC, lookups, Plonkish gates, zkVM and the prover-optimization experiments
//! are behind the `experimental` feature. Several are scaffolds with known
//! soundness gaps (some are forgeable); each module documents its limits. Do
//! not use them for anything that needs security.
//!
//! ## Example
//!
//! ```rust,ignore
//! use ark_bn254::Bn254;
//! use ark_snark::SNARK;
//! use unigroth::Groth16;
//!
//! let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;
//! let proof = Groth16::<Bn254>::prove(&pk, circuit_with_witness, &mut rng)?;
//! assert!(Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(
    clippy::many_single_char_names,
    clippy::op_ref,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::doc_nested_refdefs
)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

// ─── Groth16 core ────────────────────────────────────────────────────────────

/// Library-wide constants: security level, Poseidon parameters, domain tags.
pub mod config;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// Constraints for the Groth16 verifier.
#[cfg(feature = "r1cs")]
pub mod constraints;

/// Subversion-ZK rerandomization and the security report.
pub mod security;

// ─── Setup ───────────────────────────────────────────────────────────────────

/// KZG polynomial commitments over a validated powers-of-τ SRS.
pub mod kzg;

/// Universal setup: verifiable Phase 1 / Phase 2 ceremony and key derivation.
pub mod universal_setup;

// ─── Verification helpers ────────────────────────────────────────────────────

/// Batch verification of many proofs for one verifying key.
pub mod aggregation;

/// Batch proving and verification.
pub mod batch;

/// Verifying-key compression: a digest of the input-commitment vector.
pub mod key_compression;

/// Schnorr proof of knowledge binding a prover to their public inputs.
pub mod public_input_pok;

/// Solidity verifier contract generation for on-chain verification.
#[cfg(any(feature = "solidity", test))]
pub mod solidity;

/// WASM verifier code generation for browser-based verification.
#[cfg(any(feature = "solidity", test))]
pub mod wasm_verifier;

// ─── Circuits ────────────────────────────────────────────────────────────────

/// Authentication circuit: knowledge of a secret with a replay-resistant nullifier.
pub mod auth;

/// Circuit builder for small R1CS circuits.
pub mod circuit_builder;

/// Circuit library: Poseidon, Merkle trees, range checks.
pub mod circuits;

/// Serde compatibility helpers for arkworks types (feature: `serde`).
#[cfg(feature = "serde")]
pub mod serde_compat;

// ─── Experimental (feature `experimental`; see crate docs) ───────────────────

/// Experimental: runtime strategy selection heuristics.
#[cfg(feature = "experimental")]
pub mod adaptive;

/// Experimental: FRI and IPA polynomial commitments. FRI does not check
/// folding consistency, so it is not a low-degree test.
#[cfg(feature = "experimental")]
pub mod commitment;

/// Experimental: folding / IVC. The decision predicate trusts a
/// prover-supplied error vector.
#[cfg(feature = "experimental")]
pub mod folding;

/// Experimental: custom gate constraint counts.
#[cfg(feature = "experimental")]
pub mod gates;

/// Experimental: gadget descriptions (ECDSA, EdDSA, Merkle, ...).
#[cfg(feature = "experimental")]
pub mod gadgets;

/// Experimental: Lasso-style sumcheck lookups (verifier sees all queries).
#[cfg(feature = "experimental")]
pub mod lasso;

/// Experimental: Plookup / LogUp reference identities (verifier sees all queries).
#[cfg(feature = "experimental")]
pub mod lookup;

/// Experimental: additive / Shamir witness sharing. Tags are unkeyed.
#[cfg(feature = "experimental")]
pub mod mpc;

/// Experimental: prover-optimization experiments (Dynark FFT, CSR, caches).
#[cfg(feature = "experimental")]
pub mod optimizations;

/// Experimental: Plonkish constraint system lowered to R1CS.
#[cfg(feature = "experimental")]
pub mod plonkish;

/// Experimental: hash-based "inner prover" stubs. **Forgeable; not post-quantum.**
#[cfg(feature = "experimental")]
pub mod pq_inner;

/// Experimental: hash-linked proof log. Does not verify inner proofs.
#[cfg(feature = "experimental")]
pub mod recursion;

/// Experimental: SAP naming wrapper; delegates to the QAP reduction.
#[cfg(feature = "experimental")]
pub mod sap;

/// Experimental: streaming MSM and memory estimates.
#[cfg(feature = "experimental")]
pub mod streaming;

/// Experimental: setup-mode descriptions; no transparent setup is implemented.
#[cfg(feature = "experimental")]
pub mod transparent;

/// Experimental: RISC-V trace-to-constraint scaffolding.
#[cfg(feature = "experimental")]
pub mod zkvm;

#[cfg(test)]
mod test;

pub use self::aggregation::{aggregate_proofs, verify_aggregated, AggregatedProof};
pub use self::auth::{mimc_hash, mimc_round_constants, AuthCircuit, MIMC_ROUNDS};
pub use self::batch::{
    batch_prove, batch_verify, batch_verify_optimized, BatchConfig, BatchProofResult, BatchResult,
};
pub use self::circuit_builder::{BuiltCircuit, CircuitBuilder, CircuitStats, Wire};
pub use self::circuits::{
    poseidon_hash, MerkleProofCircuit, PoseidonHashCircuit, PoseidonParams, RangeCheckCircuit,
};
pub use self::key_compression::{
    compress_vk, compression_stats, create_vk_opening, verify_with_compressed_vk,
    CompressedVerifyingKey, VKOpeningProof,
};
pub use self::kzg::{Commitment, KzgError, Opening, UniversalSRS, KZG};
pub use self::public_input_pok::{prove_public_input_pok, verify_public_input_pok, PublicInputPoK};
pub use self::security::{SecurityParams, SecurityReport};
pub use self::universal_setup::UniversalParams;
pub use self::{data_structures::*, verifier::*};

use ark_ec::pairing::Pairing;
use ark_relations::gr1cs::{ConstraintSynthesizer, SynthesisError};
use ark_snark::*;
use ark_std::{marker::PhantomData, rand::RngCore, vec::Vec};
use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

/// Sample a uniformly random non-zero field element.
///
/// # Panics
/// If `rng` returns zero eight times in a row. A working RNG does that with
/// probability about 2⁻²⁰⁰⁰, so it means the entropy source is broken, and
/// carrying on would produce predictable (and therefore leaked) secrets.
pub(crate) fn nonzero_rand<F: ark_ff::Field, R: RngCore + ?Sized>(rng: &mut R) -> F {
    for _ in 0..8 {
        let x = F::rand(rng);
        if !x.is_zero() {
            return x;
        }
    }
    panic!("RNG returned zero eight times in a row: the entropy source is broken");
}

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing, QAP: R1CSToQAP> SNARK<E::ScalarField> for Groth16<E, QAP> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_random_proof_with_reduction(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &[E::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Self::verify_proof(circuit_pvk, proof, x)
    }
}

impl<E: Pairing, QAP: R1CSToQAP> CircuitSpecificSetupSNARK<E::ScalarField> for Groth16<E, QAP> {}
