//! # UniGroth: Next-Generation Universal zkSNARK Framework
//!
//! UniGroth is an evolutionary zkSNARK framework that addresses the fundamental
//! limitations of Groth16 while preserving its legendary proof size and verification speed.
//!
//! ## Overview
//!
//! Built on the foundation of [`Groth16`](https://eprint.iacr.org/2016/260.pdf),
//! UniGroth aims to provide:
//!
//! - **Universal Setup**: One-time ceremony, reusable for any circuit
//! - **Flexible Arithmetization**: SAP/Plonkish with custom gates and lookups
//! - **Groth16-Level Performance**: 192-256 byte proofs, 3-5 pairing verification
//! - **Enhanced Security**: Simulation-extractable, subversion-resistant
//! - **Folding & Recursion**: ProtoStar/Nova integration for IVC
//!
//! ## Current Status
//!
//! ⚠️ **RESEARCH PROTOTYPE** - This implementation currently provides the original
//! Groth16 protocol. Universal setup, SAP arithmetization, and folding features
//! are under active development.
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use unigroth::{Groth16, ProvingKey, VerifyingKey};
//! use ark_bn254::Bn254;
//! use ark_relations::r1cs::ConstraintSynthesizer;
//! use ark_snark::SNARK;
//!
//! // Define your circuit
//! struct MyCircuit { /* ... */ }
//!
//! impl ConstraintSynthesizer<Fr> for MyCircuit {
//!     fn generate_constraints(/* ... */) -> Result<(), SynthesisError> {
//!         // Define constraints
//!         Ok(())
//!     }
//! }
//!
//! // Setup (currently circuit-specific, universal setup coming soon)
//! let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;
//!
//! // Prove
//! let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;
//!
//! // Verify
//! let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;
//! ```
//!
//! ## Architecture
//!
//! UniGroth is organized into several key modules:
//!
//! - [`data_structures`]: Core types (proving keys, verifying keys, proofs)
//! - [`generator`]: Setup and key generation
//! - [`prover`]: Proof generation
//! - [`verifier`]: Proof verification
//! - [`r1cs_to_qap`]: R1CS to QAP reduction (SAP support coming)
//! - [`constraints`]: R1CS gadgets for recursive verification (feature: `r1cs`)
//!
//! ## Acknowledgements
//!
//! Built on the framework from [arkworks-rs/groth16](https://github.com/arkworks-rs/groth16).
//! Extended by MeridianAlgo (2026).
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

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

/// KZG polynomial commitment scheme for universal setup.
pub mod kzg;

/// Square Arithmetic Programs (SAP) - more efficient than R1CS.
pub mod sap;

/// Universal trusted setup - one ceremony for all circuits.
pub mod universal_setup;

/// ProtoStar-style folding / IVC for recursion and scalability.
pub mod folding;

/// Security upgrades: simulation-extractability, subversion ZK, AGM+ROM.
pub mod security;

/// Prover optimizations: Dynark 4-FFT, parallel MSM, proof compression.
pub mod optimizations;

/// Plonkish arithmetization: custom gates, lookups, copy constraints.
pub mod plonkish;

#[cfg(test)]
mod test;

pub use self::folding::{FoldingAccumulator, FoldingEngine, FoldingInstance, IVC};
pub use self::kzg::{Commitment, Opening, UniversalSRS, KZG};
pub use self::optimizations::{parallel_msm, MSMGPUHint, PolymathCompressor, ProverProfile};
pub use self::plonkish::{
    CustomGateRegistry, LookupTable, PlonkSelectors, PlonkishConstraintSystem, PlonkishStats,
};
pub use self::sap::{R1CSToSAP, SAPInstance, SAPStats};
pub use self::security::{SEConfig, SecurityParams, SecurityReport, SimExtractableProof};
pub use self::universal_setup::UniversalParams;
pub use self::{data_structures::*, verifier::*};

use ark_ec::pairing::Pairing;
use ark_relations::gr1cs::{ConstraintSynthesizer, SynthesisError};
use ark_snark::*;
use ark_std::{marker::PhantomData, rand::RngCore, vec::Vec};
use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

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
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore,
    {
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
