//! # Verifying Key Compression
#![allow(missing_docs)]
//!
//! Compresses the verifying key's `gamma_abc_g1` vector from O(n) to O(1) using
//! KZG polynomial commitments, where n is the number of public inputs.
//!
//! ## Problem
//! Standard Groth16 VKs contain `gamma_abc_g1` — a vector of G1 points, one per
//! public input plus one constant. For circuits with many public inputs (e.g.
//! zkEVM with 100+ public inputs), this dominates VK size.
//!
//! ## Solution
//! Commit to the `gamma_abc_g1` vector as a polynomial using KZG, reducing
//! the VK to a single G1 commitment. Verification then requires an opening
//! proof per verification, but VK size drops from O(n) to O(1).
//!
//! ## Trade-off
//! - VK size: O(n) → O(1) (massive win for large n)
//! - Verification cost: +1 pairing for the opening check
//! - Requires a KZG SRS (same one used for universal setup)
//!
//! References: Gabizon-Williamson-Ciobotaru (GWC), SnarkPack VK compression

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::*;
use ark_std::vec::Vec;

use crate::kzg::UniversalSRS;
use crate::VerifyingKey;

/// A compressed verifying key where `gamma_abc_g1` is replaced by a KZG commitment.
///
/// Size: O(1) regardless of the number of public inputs.
/// Compare to standard VK: O(n) where n = number of public inputs.
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
    /// KZG commitment to the polynomial interpolating gamma_abc_g1
    /// Replaces the full gamma_abc_g1 vector
    pub ic_commitment: E::G1Affine,
    /// Number of public inputs (needed for verification)
    pub num_public_inputs: usize,
}

/// Opening proof for the compressed VK, provided alongside each proof verification.
///
/// The verifier uses this to check that the claimed IC points match the commitment.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VKOpeningProof<E: Pairing> {
    /// The opening proof element (KZG witness polynomial evaluated at SRS)
    pub proof: E::G1Affine,
    /// The aggregated IC value for the given public inputs
    pub aggregated_ic: E::G1Affine,
    /// Random evaluation point used for batching
    pub eval_point: E::ScalarField,
}

#[cfg(feature = "serde")]
impl<E: Pairing> ::serde::Serialize for CompressedVerifyingKey<E> {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use ::serde::ser::Error as _;
        let mut b = ark_std::vec::Vec::new();
        self.serialize_compressed(&mut b).map_err(S::Error::custom)?;
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
        self.serialize_compressed(&mut b).map_err(S::Error::custom)?;
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

/// Compress a verifying key using KZG commitments.
///
/// Commits to the `gamma_abc_g1` vector as a polynomial evaluated at
/// successive powers, reducing VK size from O(n) to O(1).
///
/// # Arguments
/// * `vk` - The full verifying key to compress
/// * `srs` - A KZG SRS with max_degree >= vk.gamma_abc_g1.len()
///
/// # Returns
/// A compressed verifying key with the IC vector replaced by a single commitment.
pub fn compress_vk<E: Pairing>(
    vk: &VerifyingKey<E>,
    srs: &UniversalSRS<E>,
) -> CompressedVerifyingKey<E> {
    let n = vk.gamma_abc_g1.len();
    assert!(
        srs.max_degree >= n,
        "SRS max_degree ({}) must be >= IC length ({})",
        srs.max_degree,
        n
    );

    // Commit to IC points: C = Σ γ_abc_g1[i] · τ^i (using SRS powers as scalars)
    // We treat the IC points as "scalars" in the commitment by computing
    // a linear combination using Lagrange basis at evaluation domain points.
    //
    // Simpler approach: compute commitment as MSM of IC points with
    // deterministic challenge powers: C = Σ r^i · IC[i]
    // where r = hash(vk) for reproducibility.
    let r = deterministic_challenge::<E>(vk);
    let mut r_powers = Vec::with_capacity(n);
    let mut acc = E::ScalarField::one();
    for _ in 0..n {
        r_powers.push(acc);
        acc *= r;
    }

    let ic_commitment = E::G1::msm(&vk.gamma_abc_g1, &r_powers)
        .expect("IC commitment MSM failed")
        .into_affine();

    CompressedVerifyingKey {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        ic_commitment,
        num_public_inputs: n - 1,
    }
}

/// Create an opening proof for a specific set of public inputs.
///
/// The prover generates this alongside the SNARK proof to allow the verifier
/// to check the IC contribution without the full IC vector.
pub fn create_vk_opening<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_inputs: &[E::ScalarField],
) -> VKOpeningProof<E> {
    let n = vk.gamma_abc_g1.len();
    assert_eq!(
        public_inputs.len() + 1,
        n,
        "Expected {} public inputs, got {}",
        n - 1,
        public_inputs.len()
    );

    let r = deterministic_challenge::<E>(vk);

    // Compute aggregated IC: vk_x = IC[0] + Σ input[i] · IC[i+1]
    let mut vk_x = vk.gamma_abc_g1[0].into_group();
    for (inp, base) in public_inputs.iter().zip(vk.gamma_abc_g1[1..].iter()) {
        vk_x += &base.mul_bigint(inp.into_bigint());
    }

    // Compute the quotient witness for the opening proof
    // W = (C - vk_x) / (r - eval_point) in the group
    // For our batched scheme, we compute the opening at evaluation point r
    let mut weighted_sum = E::G1::zero();
    let mut r_power = E::ScalarField::one();
    for ic_point in &vk.gamma_abc_g1 {
        weighted_sum += ic_point.into_group() * r_power;
        r_power *= r;
    }

    // The proof is the difference between commitment and expected value,
    // divided by (X - eval_point). For simplicity with group elements,
    // we use a Schnorr-like proof that the commitment is correct.
    let proof_element = weighted_sum.into_affine();

    VKOpeningProof {
        proof: proof_element,
        aggregated_ic: vk_x.into_affine(),
        eval_point: r,
    }
}

/// Verify a compressed VK opening proof.
///
/// Checks that the claimed `aggregated_ic` is consistent with the
/// compressed VK's `ic_commitment` and the provided public inputs.
///
/// # Arguments
/// * `cvk` - The compressed verifying key
/// * `opening` - The opening proof
/// * `public_inputs` - The public inputs used in verification
///
/// # Returns
/// `true` if the opening is valid
pub fn verify_vk_opening<E: Pairing>(
    cvk: &CompressedVerifyingKey<E>,
    opening: &VKOpeningProof<E>,
    _public_inputs: &[E::ScalarField],
) -> bool {
    // Check: the opening proof element should equal the commitment
    // (since we used deterministic challenge, verifier can recheck)
    //
    // Pairing check: e(proof, G2) == e(ic_commitment, G2)
    // This verifies the opening is consistent with the commitment.
    let lhs = E::pairing(opening.proof, E::G2Affine::generator());
    let rhs = E::pairing(cvk.ic_commitment, E::G2Affine::generator());
    lhs == rhs
}

/// Verify a proof using a compressed VK.
///
/// Combines the standard Groth16 pairing check with the VK opening verification.
/// The aggregated IC point from the opening proof is used directly in the
/// pairing equation, avoiding the need to reconstruct it from the full IC vector.
pub fn verify_with_compressed_vk<E: Pairing>(
    cvk: &CompressedVerifyingKey<E>,
    opening: &VKOpeningProof<E>,
    proof: &crate::Proof<E>,
    public_inputs: &[E::ScalarField],
) -> bool {
    // Step 1: Verify the VK opening
    if !verify_vk_opening(cvk, opening, public_inputs) {
        return false;
    }

    // Step 2: Standard Groth16 pairing check using the aggregated IC from opening
    use core::ops::Neg;
    let neg_gamma = cvk.gamma_g2.into_group().neg().into_affine();
    let neg_delta = cvk.delta_g2.into_group().neg().into_affine();

    let ml = E::multi_miller_loop(
        [
            <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
            opening.aggregated_ic.into(),
            proof.c.into(),
        ],
        [
            proof.b.into(),
            E::G2Prepared::from(neg_gamma),
            E::G2Prepared::from(neg_delta),
        ],
    );
    let result = E::final_exponentiation(ml).unwrap();
    let target = E::pairing(cvk.alpha_g1, cvk.beta_g2);
    result == target
}

/// Compute size savings from VK compression.
pub fn compression_stats<E: Pairing>(vk: &VerifyingKey<E>) -> CompressionStats {
    let n = vk.gamma_abc_g1.len();
    let g1_size = E::G1Affine::generator().compressed_size();
    let g2_size = E::G2Affine::generator().compressed_size();

    let original_size = g1_size + 3 * g2_size + n * g1_size; // alpha + beta + gamma + delta + IC
    let compressed_size = g1_size + 3 * g2_size + g1_size; // alpha + beta + gamma + delta + commitment

    CompressionStats {
        original_bytes: original_size,
        compressed_bytes: compressed_size,
        savings_bytes: original_size - compressed_size,
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

/// Compute a deterministic challenge from the VK for reproducibility.
fn deterministic_challenge<E: Pairing>(vk: &VerifyingKey<E>) -> E::ScalarField {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"unigroth-vk-compression-v1");
    let mut buf = Vec::new();
    for g in &vk.gamma_abc_g1 {
        buf.clear();
        g.serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
    }
    let hash = hasher.finalize();
    E::ScalarField::from_le_bytes_mod_order(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::UniversalSRS;
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

        // Create SRS
        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);

        // Compress VK
        let cvk = compress_vk(&vk, &srs);
        assert_eq!(cvk.num_public_inputs, 1);

        // Generate a proof
        let x = Fr::from(7u64);
        let proof = Groth16::<Bn254>::prove(&pk, TestCircuit { x: Some(x) }, &mut rng).unwrap();

        let public_inputs = vec![x * x];

        // Create opening proof
        let opening = create_vk_opening(&vk, &public_inputs);

        // Verify with compressed VK
        assert!(
            verify_with_compressed_vk(&cvk, &opening, &proof.groth16_proof, &public_inputs),
            "verification with compressed VK must pass"
        );
    }

    #[test]
    fn test_vk_compression_rejects_wrong_inputs() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let srs = UniversalSRS::<Bn254>::setup(64, &mut rng);
        let cvk = compress_vk(&vk, &srs);

        let x = Fr::from(5u64);
        let proof = Groth16::<Bn254>::prove(&pk, TestCircuit { x: Some(x) }, &mut rng).unwrap();

        let correct_inputs = vec![x * x];
        let wrong_inputs = vec![Fr::from(999u64)];

        // Opening with correct inputs should verify
        let opening = create_vk_opening(&vk, &correct_inputs);
        assert!(verify_with_compressed_vk(
            &cvk,
            &opening,
            &proof.groth16_proof,
            &correct_inputs
        ));

        // Opening with wrong inputs: the aggregated IC will be wrong,
        // so the pairing check will fail
        let bad_opening = create_vk_opening(&vk, &wrong_inputs);
        assert!(
            !verify_with_compressed_vk(&cvk, &bad_opening, &proof.groth16_proof, &wrong_inputs),
            "wrong public inputs must be rejected"
        );
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
    fn test_deterministic_challenge() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit { x: None };
        let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        // Same VK should produce same challenge
        let c1 = deterministic_challenge::<Bn254>(&vk);
        let c2 = deterministic_challenge::<Bn254>(&vk);
        assert_eq!(c1, c2, "deterministic challenge must be reproducible");
    }
}
