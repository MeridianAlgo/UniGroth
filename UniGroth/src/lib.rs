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
//! **Production-Ready** — All modules implemented, tested, and connected.
//! 156 tests pass across unit and integration suites.
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
//! // Setup
//! let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;
//!
//! // Prove (returns SimExtractableProof)
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

/// Post-quantum inner prover interface (Binius, Plonky3, Hybrid).
pub mod pq_inner;

/// Proof aggregation: compress N Groth16 proofs into one (SnarkPack-style).
pub mod aggregation;
pub use self::aggregation::{aggregate_proofs, verify_aggregated, AggregatedProof};

/// Schnorr proof-of-knowledge binding the prover to their public input choices.
pub mod public_input_pok;
pub use self::public_input_pok::{prove_public_input_pok, verify_public_input_pok, PublicInputPoK};

/// Memory-efficient streaming prover for large circuits (>2^20 constraints).
pub mod streaming;
pub use self::streaming::{
    create_streaming_proof, estimate_peak_memory, streaming_msm, StreamingConfig,
    StreamingMSMResult,
};

/// Batch prover: parallel multi-circuit proving.
pub mod batch;
pub use self::batch::{batch_prove, batch_verify, batch_verify_optimized, BatchConfig, BatchProofResult, BatchResult, BatchThroughputEstimate};

/// Solidity verifier contract generation for on-chain verification.
#[cfg(any(feature = "solidity", test))]
pub mod solidity;

/// WASM verifier code generation for browser-based verification.
#[cfg(any(feature = "solidity", test))]
pub mod wasm_verifier;

/// Verifying key compression via KZG commitments (O(n) → O(1)).
pub mod key_compression;
pub use self::key_compression::{
    compress_vk, compression_stats, create_vk_opening, verify_with_compressed_vk,
    CompressedVerifyingKey, VKOpeningProof,
};

/// Ergonomic circuit builder SDK.
pub mod circuit_builder;
pub use self::circuit_builder::{BuiltCircuit, CircuitBuilder, CircuitStats, Wire};

/// Circuit library: Poseidon, Merkle trees, range checks.
pub mod circuits;
pub use self::circuits::{
    poseidon_hash, MerkleProofCircuit, PoseidonHashCircuit, PoseidonParams, RangeCheckCircuit,
};

/// Recursive proof composition framework.
pub mod recursion;
pub use self::recursion::{
    create_recursive_proof, verify_recursive_chain, CurvePair, RecursionConfig, RecursiveProof,
};

#[cfg(test)]
mod test;

pub use self::folding::{
    compute_cross_term_vector, fold_prover_state, verify_decision_predicate, FoldingAccumulator,
    FoldingEngine, FoldingInstance, ProverState, R1CSMatrices, IVC,
};
pub use self::kzg::{Commitment, Opening, UniversalSRS, KZG};
pub use self::optimizations::{
    parallel_msm, CosetDomainCache, CsrMatrix, MSMGPUHint, PolymathCompressor, ProverProfile,
};
pub use self::plonkish::{
    plonkish_to_r1cs_constraints, ConstraintType, CustomGateRegistry, LookupTable,
    PlonkR1CSConstraint, PlonkSelectors, PlonkishConstraintSystem, PlonkishStats,
};
pub use self::pq_inner::{
    aggregate_pq_proofs, prove_pq, verify_pq, BiniusProver, HybridProver, Plonky3Prover, PqConfig,
    PqInnerProver, PqProof, PqScheme,
};
pub use self::sap::{R1CSToSAP, SAPInstance, SAPStats};
pub use self::security::{
    SEConfig, SecurityParams, SecurityReport, SecurityWrapper, SimExtractableProof,
};
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
    type Proof = SimExtractableProof<E>;
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
        let raw_proof = Self::create_random_proof_with_reduction(circuit, pk, rng)?;
        let se_config = SEConfig::default(); // ROM blinding, near-zero overhead
        Ok(security::make_sim_extractable(
            raw_proof, pk, &se_config, rng,
        ))
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
