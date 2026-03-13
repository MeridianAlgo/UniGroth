//! # Post-Quantum Inner Prover Module
#![allow(missing_docs)]
//!
//! This module provides a stub interface for post-quantum inner provers that can
//! be composed with the outer Groth16 / UniGroth compression layer.
//!
//! ## Supported Schemes
//!
//! - **Binius** – Binary-field-based SNARK (Ulvetanna / Irreducible, 2024).
//!   Achieves PQ security via Reed-Solomon codes over binary towers.
//!
//! - **Plonky3** – Successor to Plonky2 from Polygon / the community (2024).
//!   FRI-based SNARK with configurable arithmetic fields.
//!
//! - **Hybrid** – Wrap a Plonky3 inner proof inside Groth16 for succinct,
//!   PQ-secure outer verification.
//!
//! ## References
//!
//! - Binius: <https://eprint.iacr.org/2023/1784>
//! - Plonky3: <https://github.com/Plonky3/Plonky3>
//! - Hybrid PQ SNARKs: "Lattice-Based Recursive SNARKs" (2025 preprint)

use ark_std::vec::Vec;

// ─── Core Types ─────────────────────────────────────────────────────────────

/// Selects the post-quantum inner proving scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqScheme {
    /// Binius: binary-tower-field SNARK (Reed-Solomon + FRI)
    Binius,
    /// Plonky3: FRI-based SNARK with configurable field
    Plonky3,
    /// Hybrid: Plonky3 inner proof wrapped by Groth16 outer compression
    Hybrid,
}

/// Configuration for a post-quantum inner prover.
#[derive(Clone, Debug)]
pub struct PqConfig {
    /// Which PQ scheme to use
    pub scheme: PqScheme,
    /// Target security level in bits (e.g., 128, 192, 256)
    pub security_bits: usize,
    /// Field size in bits used internally by the scheme
    pub field_size_bits: usize,
}

impl PqConfig {
    /// Create a new config with default security parameters for the given scheme.
    ///
    /// Defaults: 128-bit security, 64-bit field for Binius/Plonky3, 254 bits for Hybrid.
    pub fn new(scheme: PqScheme) -> Self {
        let field_size_bits = match scheme {
            PqScheme::Binius  => 64,
            PqScheme::Plonky3 => 64,
            PqScheme::Hybrid  => 254,
        };
        Self {
            scheme,
            security_bits: 128,
            field_size_bits,
        }
    }
}

/// A post-quantum proof produced by a `PqInnerProver`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqProof {
    /// Serialized proof bytes
    pub bytes: Vec<u8>,
    /// Which scheme produced this proof
    pub scheme: PqScheme,
}

impl PqProof {
    /// Return the size of this proof in bytes.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

// ─── Prover Trait ────────────────────────────────────────────────────────────

/// Trait for post-quantum inner provers.
///
/// Both `BiniusProver` and `Plonky3Prover` implement this interface so that
/// the outer UniGroth layer can swap schemes without code changes.
pub trait PqInnerProver {
    /// Generate a PQ proof for the given witness bytes under `config`.
    fn prove(config: &PqConfig, witness: &[u8]) -> PqProof;

    /// Verify a PQ proof against `public_inputs` under `config`.
    ///
    /// Returns `true` iff the proof is valid.
    fn verify(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool;
}

// ─── Binius Prover (stub) ─────────────────────────────────────────────────────

/// Stub implementation of the Binius binary-tower SNARK prover.
///
/// To integrate the real Binius backend, add the `binius` crate and replace
/// the `todo!()` calls with the appropriate API calls.
pub struct BiniusProver;

impl PqInnerProver for BiniusProver {
    fn prove(config: &PqConfig, _witness: &[u8]) -> PqProof {
        todo!(
            "BiniusProver::prove is not yet implemented. \
             Add the `binius` crate (https://github.com/IrreducibleOSS/binius) \
             and call binius::prove(config, witness). \
             Config: {:?}",
            config
        )
    }

    fn verify(config: &PqConfig, _proof: &PqProof, _public_inputs: &[u8]) -> bool {
        todo!(
            "BiniusProver::verify is not yet implemented. \
             Add the `binius` crate and call binius::verify(config, proof, public_inputs). \
             Config: {:?}",
            config
        )
    }
}

// ─── Plonky3 Prover (stub) ────────────────────────────────────────────────────

/// Stub implementation of the Plonky3 FRI-based SNARK prover.
///
/// To integrate the real Plonky3 backend, add the `p3-*` crates from
/// <https://github.com/Plonky3/Plonky3> and replace the `todo!()` calls.
pub struct Plonky3Prover;

impl PqInnerProver for Plonky3Prover {
    fn prove(config: &PqConfig, _witness: &[u8]) -> PqProof {
        todo!(
            "Plonky3Prover::prove is not yet implemented. \
             Add the `p3-*` crates (https://github.com/Plonky3/Plonky3) \
             and call the Plonky3 prover API. \
             Config: {:?}",
            config
        )
    }

    fn verify(config: &PqConfig, _proof: &PqProof, _public_inputs: &[u8]) -> bool {
        todo!(
            "Plonky3Prover::verify is not yet implemented. \
             Add the `p3-*` crates and call the Plonky3 verifier API. \
             Config: {:?}",
            config
        )
    }
}

// ─── Proof Aggregation ───────────────────────────────────────────────────────

/// Aggregate multiple PQ proofs into a single byte vector suitable for
/// inclusion in an outer Groth16 / UniGroth witness.
///
/// ## Implementation Status
///
/// This is a stub. A full implementation would:
/// 1. Verify each proof independently.
/// 2. Batch-hash all proof transcripts using Poseidon or SHA3-256.
/// 3. Return a succinct commitment to the batch.
///
/// See: "STARK-based Proof Aggregation" and Plonky3 aggregation design docs.
pub fn aggregate_pq_proofs(proofs: &[PqProof], _config: &PqConfig) -> Vec<u8> {
    todo!(
        "aggregate_pq_proofs is not yet implemented. \
         Full aggregation requires a scheme-specific batch verifier. \
         Received {} proof(s). \
         See: Plonky3 aggregation docs or Binius batch-verify API.",
        proofs.len()
    )
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_config_creation() {
        // Binius config
        let binius_cfg = PqConfig::new(PqScheme::Binius);
        assert_eq!(binius_cfg.scheme, PqScheme::Binius);
        assert_eq!(binius_cfg.security_bits, 128);
        assert_eq!(binius_cfg.field_size_bits, 64);

        // Plonky3 config
        let p3_cfg = PqConfig::new(PqScheme::Plonky3);
        assert_eq!(p3_cfg.scheme, PqScheme::Plonky3);
        assert_eq!(p3_cfg.security_bits, 128);
        assert_eq!(p3_cfg.field_size_bits, 64);

        // Hybrid config
        let hybrid_cfg = PqConfig::new(PqScheme::Hybrid);
        assert_eq!(hybrid_cfg.scheme, PqScheme::Hybrid);
        assert_eq!(hybrid_cfg.security_bits, 128);
        assert_eq!(hybrid_cfg.field_size_bits, 254);
    }

    #[test]
    fn test_pq_scheme_enum_matching() {
        let schemes = [PqScheme::Binius, PqScheme::Plonky3, PqScheme::Hybrid];

        for scheme in &schemes {
            let name = match scheme {
                PqScheme::Binius  => "Binius",
                PqScheme::Plonky3 => "Plonky3",
                PqScheme::Hybrid  => "Hybrid",
            };
            println!("PqScheme::{} matched correctly", name);
        }

        // Equality
        assert_eq!(PqScheme::Binius, PqScheme::Binius);
        assert_ne!(PqScheme::Binius, PqScheme::Plonky3);
        assert_ne!(PqScheme::Plonky3, PqScheme::Hybrid);
    }

    #[test]
    fn test_pq_proof_byte_len() {
        let proof = PqProof {
            bytes: ark_std::vec![0u8; 256],
            scheme: PqScheme::Binius,
        };
        assert_eq!(proof.byte_len(), 256);
    }

    #[test]
    fn test_pq_proof_clone_and_equality() {
        let proof = PqProof {
            bytes: ark_std::vec![1, 2, 3, 4],
            scheme: PqScheme::Plonky3,
        };
        let proof2 = proof.clone();
        assert_eq!(proof, proof2);
    }
}
