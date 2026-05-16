//! # Proof of Knowledge for Public Inputs
#![allow(missing_docs)]
//!
//! Adds a Schnorr-style PoK alongside the Groth16 proof to bind the prover
//! to their specific public input values at proof-generation time.
//!
//! ## Motivation
//!
//! In vanilla Groth16, the verifier receives the proof and public inputs separately
//! and simply checks the pairing equation. There is no cryptographic guarantee that
//! the *prover* committed to those exact inputs when they computed the proof; an
//! adversary who can influence which inputs the verifier uses could potentially
//! substitute them post-hoc.
//!
//! This module adds a multi-scalar Schnorr PoK that forces the prover to commit
//! to their input vector `{x₁, …, xₙ}` during proving, which the verifier can
//! check alongside the Groth16 verification equation.
//
// Thank you Claude for teaching me ts. Thank you Ajak M., Akshath R., and Eshan K. to make sure the rust is valid and optimized.
//!
//!
//!
//!
//! ## Protocol (Fiat-Shamir)
//!
//! **Statement**: `g_ic = γ₀ + Σ xᵢ · γᵢ` where `{γᵢ}` = `vk.gamma_abc_g1`
//! **Witness**: `{x₁, …, xₙ}` — the public inputs
//!
//! 1. Prover samples random `{rᵢ}`, computes commitment `R = Σ rᵢ · γᵢ₊₁`
//! 2. Challenge `c = H("unigroth-pok-v1" || R || x₁ || … || xₙ || proof.a || proof.b || proof.c)`
//! 3. Responses `sᵢ = rᵢ + c · xᵢ`
//!
//! **Verifier check**: `Σ sᵢ · γᵢ₊₁ == R + c · Σ xᵢ · γᵢ₊₁`
//!
//! Binding the challenge to the proof elements ties the PoK to a specific proof,
//! preventing detachment and reuse with a different Groth16 proof.
//! Imports
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, vec::Vec};
use sha2::{Digest, Sha256};

use crate::{Proof, VerifyingKey};

/// Schnorr proof-of-knowledge binding the prover to their public input choices.
/// Produced by [`prove_public_input_pok`] and checked by [`verify_public_input_pok`].
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicInputPoK<E: Pairing> {
    /// Commitment `R = Σ rᵢ · γᵢ₊₁` (G₁ element, one per public input)
    pub commitment: E::G1Affine,
    /// Fiat-Shamir challenge `c = H(R, x₁…xₙ, proof.a, proof.b, proof.c)`
    pub challenge: E::ScalarField,
    /// Responses `sᵢ = rᵢ + c · xᵢ` for each public input `xᵢ`
    pub responses: Vec<E::ScalarField>,
}

#[cfg(feature = "serde")]
impl<E: Pairing> ::serde::Serialize for PublicInputPoK<E> {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use ::serde::ser::Error as _;
        let mut b = ark_std::vec::Vec::new();
        self.serialize_compressed(&mut b).map_err(S::Error::custom)?;
        ::serde::Serialize::serialize(&b, s)
    }
}
#[cfg(feature = "serde")]
impl<'de, E: Pairing> ::serde::Deserialize<'de> for PublicInputPoK<E> {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use ::serde::de::Error as _;
        let b: ark_std::vec::Vec<u8> = ::serde::Deserialize::deserialize(d)?;
        Self::deserialize_compressed(&b[..]).map_err(D::Error::custom)
    }
}

/// Generate a Schnorr PoK binding the prover to the given public inputs.
/// Call after generating a Groth16 proof. The PoK is sent alongside the proof
/// and allows the verifier to confirm the prover knew the exact public inputs
/// `{xᵢ}` at proving time.
/// # Panics
/// Panics if `public_inputs.len() + 1 != vk.gamma_abc_g1.len()`.
pub fn prove_public_input_pok<E: Pairing, R: Rng>(
    vk: &VerifyingKey<E>,
    public_inputs: &[E::ScalarField],
    proof: &Proof<E>,
    rng: &mut R,
) -> PublicInputPoK<E>
where
    E::ScalarField: PrimeField,
{
    let n = public_inputs.len();
    assert_eq!(
        vk.gamma_abc_g1.len(),
        n + 1,
        "public_inputs length mismatch: got {n}, VK expects {}",
        vk.gamma_abc_g1.len() - 1
    );

    // Step 1: sample random blinding scalars {rᵢ} for i = 1..=n
    let blinding: Vec<E::ScalarField> = (0..n).map(|_| E::ScalarField::rand(rng)).collect();

    // Step 2: commitment R = Σ rᵢ · γᵢ₊₁  (γ₀ = gamma_abc_g1[0] is the constant term)
    let bases = &vk.gamma_abc_g1[1..]; // γ₁ … γₙ
    let commitment = E::G1::msm(bases, &blinding).unwrap().into_affine();

    // Step 3: Fiat-Shamir challenge
    let challenge = fiat_shamir_challenge::<E>(&commitment, public_inputs, proof);

    // Step 4: responses sᵢ = rᵢ + c · xᵢ
    let responses: Vec<E::ScalarField> = blinding
        .iter()
        .zip(public_inputs.iter())
        .map(|(r, x)| *r + challenge * x)
        .collect();

    PublicInputPoK {
        commitment,
        challenge,
        responses,
    }
}

/// Verify a Schnorr PoK alongside a Groth16 proof.
/// Returns `true` iff the PoK is valid, meaning the prover demonstrably knew
/// the exact public inputs `{xᵢ}` at the time the proof was generated.
/// This check is independent of — and should be used *in addition to* —
/// the standard Groth16 verification equation.
pub fn verify_public_input_pok<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_inputs: &[E::ScalarField],
    proof: &Proof<E>,
    pok: &PublicInputPoK<E>,
) -> bool
where
    E::ScalarField: PrimeField,
{
    let n = public_inputs.len();
    if vk.gamma_abc_g1.len() != n + 1 || pok.responses.len() != n {
        return false;
    }

    // Recompute challenge and reject immediately if it doesn't match.
    let expected_challenge = fiat_shamir_challenge::<E>(&pok.commitment, public_inputs, proof);
    if expected_challenge != pok.challenge {
        return false;
    }

    let bases = &vk.gamma_abc_g1[1..]; // γ₁ … γₙ

    // LHS: Σ sᵢ · γᵢ₊₁
    let lhs = E::G1::msm(bases, &pok.responses).unwrap();

    // RHS: R + c · Σ xᵢ · γᵢ₊₁
    let xi_combination = E::G1::msm(bases, public_inputs).unwrap();
    let rhs = pok.commitment.into_group() + xi_combination * pok.challenge;

    lhs == rhs
}

/// Compute the Fiat-Shamir challenge.
///
/// `H("unigroth-pok-v1" || R || x₁ || … || xₙ || proof.a || proof.b || proof.c)`
fn fiat_shamir_challenge<E: Pairing>(
    commitment: &E::G1Affine,
    public_inputs: &[E::ScalarField],
    proof: &Proof<E>,
) -> E::ScalarField
where
    E::ScalarField: PrimeField,
{
    let mut hasher = Sha256::new();
    hasher.update(b"unigroth-pok-v1");

    let mut buf = Vec::new();

    // Commitment R
    commitment.serialize_compressed(&mut buf).unwrap();
    hasher.update(&buf);

    // Public inputs x₁ … xₙ
    for x in public_inputs {
        buf.clear();
        x.serialize_uncompressed(&mut buf).unwrap();
        hasher.update(&buf);
    }

    // Proof elements — binds PoK to this specific proof
    buf.clear();
    proof.a.serialize_compressed(&mut buf).unwrap();
    hasher.update(&buf);

    buf.clear();
    proof.b.serialize_compressed(&mut buf).unwrap();
    hasher.update(&buf);

    buf.clear();
    proof.c.serialize_compressed(&mut buf).unwrap();
    hasher.update(&buf);

    let hash = hasher.finalize();
    E::ScalarField::from_le_bytes_mod_order(&hash)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs_to_qap::LibsnarkReduction;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_std::rand::SeedableRng;

    #[derive(Clone)]
    struct SquareCircuit {
        x: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for SquareCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let x_sq = cs.new_input_variable(|| {
                let xv = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(xv * xv)
            })?;
            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_sq)
        }
    }

    fn setup_prove(
        x_val: u64,
    ) -> (
        ark_std::rand::rngs::StdRng,
        crate::VerifyingKey<Bn254>,
        crate::Proof<Bn254>,
        Vec<Fr>,
    ) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(
            x_val.wrapping_mul(0xdeadbeef_u64).wrapping_add(1),
        );
        let x = Fr::from(x_val);
        let (pk, vk) = crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
            SquareCircuit { x: None },
            &mut rng,
        )
        .unwrap();
        let se_proof = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            SquareCircuit { x: Some(x) },
            &mut rng,
        )
        .unwrap();
        let public_inputs = vec![x * x];
        (rng, vk, se_proof.groth16_proof, public_inputs)
    }

    #[test]
    fn test_pok_valid_proof_accepted() {
        let (mut rng, vk, proof, public_inputs) = setup_prove(5);
        let pok = prove_public_input_pok::<Bn254, _>(&vk, &public_inputs, &proof, &mut rng);
        assert!(
            verify_public_input_pok::<Bn254>(&vk, &public_inputs, &proof, &pok),
            "valid PoK should be accepted"
        );
    }

    #[test]
    fn test_pok_wrong_public_input_rejected() {
        let (mut rng, vk, proof, public_inputs) = setup_prove(5);
        let pok = prove_public_input_pok::<Bn254, _>(&vk, &public_inputs, &proof, &mut rng);

        // Verifier uses a tampered public input value
        let wrong_inputs = vec![Fr::from(999u64)];
        assert!(
            !verify_public_input_pok::<Bn254>(&vk, &wrong_inputs, &proof, &pok),
            "wrong public input should be rejected"
        );
    }

    #[test]
    fn test_pok_tampered_response_rejected() {
        let (mut rng, vk, proof, public_inputs) = setup_prove(7);
        let mut pok = prove_public_input_pok::<Bn254, _>(&vk, &public_inputs, &proof, &mut rng);

        // Adversary modifies a response scalar
        pok.responses[0] = Fr::from(0xdeadbeef_u64);
        assert!(
            !verify_public_input_pok::<Bn254>(&vk, &public_inputs, &proof, &pok),
            "tampered response should be rejected"
        );
    }

    #[test]
    fn test_pok_tampered_commitment_rejected() {
        let (mut rng, vk, proof, public_inputs) = setup_prove(11);
        let mut pok = prove_public_input_pok::<Bn254, _>(&vk, &public_inputs, &proof, &mut rng);

        // Adversary substitutes a random commitment
        use ark_ec::{AffineRepr, CurveGroup};
        pok.commitment =
            (ark_bn254::G1Affine::generator().into_group() * Fr::from(42u64)).into_affine();
        assert!(
            !verify_public_input_pok::<Bn254>(&vk, &public_inputs, &proof, &pok),
            "tampered commitment should be rejected (challenge mismatch)"
        );
    }

    #[test]
    fn test_pok_different_proof_rejected() {
        // A PoK generated for one proof must not be valid against a different proof for the
        // same statement.  The Fiat-Shamir challenge binds the PoK to specific proof elements
        // (A, B, C), so a different proof gives a different challenge and the check fails.
        let x = Fr::from(5u64);

        // Two different rngs → two different proofs for the same statement
        let mut rng1 = ark_std::rand::rngs::StdRng::seed_from_u64(0x11111111_u64);
        let mut rng2 = ark_std::rand::rngs::StdRng::seed_from_u64(0x22222222_u64);

        let (pk, vk) = crate::Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
            SquareCircuit { x: None },
            &mut rng1,
        )
        .unwrap();

        let se_proof1 = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            SquareCircuit { x: Some(x) },
            &mut rng1,
        )
        .unwrap();
        let se_proof2 = crate::Groth16::<Bn254, LibsnarkReduction>::prove(
            &pk,
            SquareCircuit { x: Some(x) },
            &mut rng2,
        )
        .unwrap();

        let proof1 = se_proof1.groth16_proof;
        let proof2 = se_proof2.groth16_proof;
        let public_inputs = vec![x * x];

        // Sanity: different randomness → different proof elements
        assert_ne!(
            proof1.a, proof2.a,
            "two proofs with different rng must differ"
        );

        let pok = prove_public_input_pok::<Bn254, _>(&vk, &public_inputs, &proof1, &mut rng1);
        assert!(
            !verify_public_input_pok::<Bn254>(&vk, &public_inputs, &proof2, &pok),
            "PoK tied to proof1 must not verify against proof2"
        );
    }
}
