//! # Verifying Key Compression
#![allow(missing_docs)]
//!
//! Replaces the O(n) `gamma_abc_g1` vector in a stored verifying key with a
//! 32-byte SHA-256 digest, where n is the number of public inputs.
//!
//! ## How it works
//! The verifier keeps only the compressed key. At verification time the IC
//! points are supplied alongside the proof (for example fetched from untrusted
//! storage); the verifier hashes them, rejects them unless the digest matches,
//! and then runs the ordinary Groth16 check with its own input MSM.
//!
//! ## Trade-off
//! - Stored VK size: O(n) → O(1)
//! - Bandwidth per verification: O(n) IC points
//! - Verification cost: unchanged Groth16 check plus one SHA-256
//!
//! Security rests on SHA-256 collision resistance. The public-input
//! combination is always recomputed by the verifier and never taken from the prover.

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::*;
use ark_std::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{Proof, VerifyingKey};

/// A verifying key whose `gamma_abc_g1` vector is replaced by its SHA-256 digest.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedVerifyingKey<E: Pairing> {
    /// alpha * G1
    pub alpha_g1: E::G1Affine,
    /// beta * G2
    pub beta_g2: E::G2Affine,
    /// gamma * G2
    pub gamma_g2: E::G2Affine,
    /// delta * G2
    pub delta_g2: E::G2Affine,
    /// SHA-256 digest of the `gamma_abc_g1` vector
    pub ic_digest: [u8; 32],
    /// Number of public inputs (`gamma_abc_g1.len() - 1`)
    pub num_public_inputs: usize,
}

/// The IC points supplied at verification time; checked against `ic_digest`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VKOpeningProof<E: Pairing> {
    /// The full `gamma_abc_g1` vector of the original verifying key
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

#[cfg(feature = "serde")]
impl<E: Pairing> ::serde::Serialize for CompressedVerifyingKey<E> {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use ::serde::ser::Error as _;
        let mut b = ark_std::vec::Vec::new();
        self.serialize_compressed(&mut b)
            .map_err(S::Error::custom)?;
        ::serde::Serialize::serialize(&b, s)
    }
}
#[cfg(feature = "serde")]
impl<'de, E: Pairing> ::serde::Deserialize<'de> for CompressedVerifyingKey<E> {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use ::serde::de::Error as _;
        let b: ark_std::vec::Vec<u8> = ::serde::Deserialize::deserialize(d)?;
        Self::deserialize_compressed(&b[..]).map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<E: Pairing> ::serde::Serialize for VKOpeningProof<E> {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use ::serde::ser::Error as _;
        let mut b = ark_std::vec::Vec::new();
        self.serialize_compressed(&mut b)
            .map_err(S::Error::custom)?;
        ::serde::Serialize::serialize(&b, s)
    }
}
#[cfg(feature = "serde")]
impl<'de, E: Pairing> ::serde::Deserialize<'de> for VKOpeningProof<E> {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use ::serde::de::Error as _;
        let b: ark_std::vec::Vec<u8> = ::serde::Deserialize::deserialize(d)?;
        Self::deserialize_compressed(&b[..]).map_err(D::Error::custom)
    }
}

/// Compress a verifying key by replacing its IC vector with a digest.
pub fn compress_vk<E: Pairing>(vk: &VerifyingKey<E>) -> CompressedVerifyingKey<E> {
    CompressedVerifyingKey {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        ic_digest: ic_digest::<E>(&vk.gamma_abc_g1),
        num_public_inputs: vk.gamma_abc_g1.len().saturating_sub(1),
    }
}

/// Package the IC points a verifier holding only the compressed key needs.
pub fn create_vk_opening<E: Pairing>(vk: &VerifyingKey<E>) -> VKOpeningProof<E> {
    VKOpeningProof {
        gamma_abc_g1: vk.gamma_abc_g1.clone(),
    }
}

/// Check that the supplied IC points are the ones the compressed key commits to.
pub fn verify_vk_opening<E: Pairing>(
    cvk: &CompressedVerifyingKey<E>,
    opening: &VKOpeningProof<E>,
) -> bool {
    opening.gamma_abc_g1.len() == cvk.num_public_inputs + 1
        && ic_digest::<E>(&opening.gamma_abc_g1) == cvk.ic_digest
}

/// Verify a Groth16 proof using a compressed VK and the supplied IC points.
///
/// The IC points are authenticated against the digest, then the standard
/// verifier recomputes the public-input term itself.
pub fn verify_with_compressed_vk<E: Pairing>(
    cvk: &CompressedVerifyingKey<E>,
    opening: &VKOpeningProof<E>,
    proof: &Proof<E>,
    public_inputs: &[E::ScalarField],
) -> bool {
    if !verify_vk_opening(cvk, opening) {
        return false;
    }
    let vk = VerifyingKey {
        alpha_g1: cvk.alpha_g1,
        beta_g2: cvk.beta_g2,
        gamma_g2: cvk.gamma_g2,
        delta_g2: cvk.delta_g2,
        gamma_abc_g1: opening.gamma_abc_g1.clone(),
    };
    crate::Groth16::<E>::verify_proof(&crate::prepare_verifying_key(&vk), proof, public_inputs)
        .unwrap_or(false)
}

/// Compute size savings from VK compression.
pub fn compression_stats<E: Pairing>(vk: &VerifyingKey<E>) -> CompressionStats {
    let n = vk.gamma_abc_g1.len();
    let g1_size = E::G1Affine::generator().compressed_size();
    let g2_size = E::G2Affine::generator().compressed_size();

    let original_size = g1_size + 3 * g2_size + n * g1_size; // alpha + beta + gamma + delta + IC
    let compressed_size = g1_size + 3 * g2_size + 32; // alpha + beta + gamma + delta + digest

    CompressionStats {
        original_bytes: original_size,
        compressed_bytes: compressed_size,
        savings_bytes: original_size.saturating_sub(compressed_size),
        compression_ratio: original_size as f64 / compressed_size as f64,
        num_ic_points: n,
    }
}

/// Statistics about VK compression.
#[derive(Clone, Debug)]
pub struct CompressionStats {
    /// Size of the original VK in bytes
    pub original_bytes: usize,
    /// Size of the compressed VK in bytes
    pub compressed_bytes: usize,
    /// Bytes saved
    pub savings_bytes: usize,
    /// Compression ratio (original / compressed)
    pub compression_ratio: f64,
    /// Number of IC points in original VK
    pub num_ic_points: usize,
}

/// Domain-separated SHA-256 digest of an IC vector (length-prefixed).
fn ic_digest<E: Pairing>(ic: &[E::G1Affine]) -> [u8; 32] {
    let mut buf = Vec::new();
    ic.serialize_compressed(&mut buf)
        .expect("serializing to a Vec cannot fail");
    Sha256::new()
        .chain_update(crate::config::DOMAIN_VK_COMPRESSION)
        .chain_update(&buf)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    #[derive(Clone)]
    struct TestCircuit {
        x: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let x_sq = cs.new_input_variable(|| {
                let xv = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(xv * xv)
            })?;
            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_sq)
        }
    }

    #[test]
    fn test_vk_compression_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let cvk = compress_vk(&vk);
        assert_eq!(cvk.num_public_inputs, 1);

        // Generate a proof
        let x = Fr::from(7u64);
        let proof = Groth16::<Bn254>::prove(&pk, TestCircuit { x: Some(x) }, &mut rng).unwrap();

        let public_inputs = vec![x * x];

        let opening = create_vk_opening(&vk);

        // Verify with compressed VK
        assert!(
            verify_with_compressed_vk(&cvk, &opening, &proof, &public_inputs),
            "verification with compressed VK must pass"
        );
    }

    #[test]
    fn test_vk_compression_rejects_wrong_inputs() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let cvk = compress_vk(&vk);

        let x = Fr::from(5u64);
        let proof = Groth16::<Bn254>::prove(&pk, TestCircuit { x: Some(x) }, &mut rng).unwrap();

        let correct_inputs = vec![x * x];
        let wrong_inputs = vec![Fr::from(999u64)];

        let opening = create_vk_opening(&vk);
        assert!(verify_with_compressed_vk(
            &cvk,
            &opening,
            &proof,
            &correct_inputs
        ));
        assert!(
            !verify_with_compressed_vk(&cvk, &opening, &proof, &wrong_inputs),
            "wrong public inputs must be rejected"
        );

        // Substituted IC points must not match the digest.
        let mut bad_opening = opening.clone();
        bad_opening.gamma_abc_g1[1] = bad_opening.gamma_abc_g1[0];
        assert!(!verify_with_compressed_vk(
            &cvk,
            &bad_opening,
            &proof,
            &correct_inputs
        ));
    }

    #[test]
    fn test_compression_stats() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let stats = compression_stats::<Bn254>(&vk);
        assert!(stats.compression_ratio >= 1.0);
        assert!(stats.savings_bytes > 0 || stats.num_ic_points <= 2);
        println!(
            "VK compression: {} -> {} bytes ({:.1}x ratio)",
            stats.original_bytes, stats.compressed_bytes, stats.compression_ratio
        );
    }

    #[test]
    fn test_ic_digest_deterministic() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let d1 = ic_digest::<Bn254>(&vk.gamma_abc_g1);
        let d2 = ic_digest::<Bn254>(&vk.gamma_abc_g1);
        assert_eq!(d1, d2, "IC digest must be reproducible");
        assert_ne!(d1, ic_digest::<Bn254>(&vk.gamma_abc_g1[..1]));
    }
}
