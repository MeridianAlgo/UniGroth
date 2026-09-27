//! # KZG Polynomial Commitment Scheme
//!
//! Implementation of the Kate-Zaverucha-Goldberg (KZG) polynomial commitment scheme
//! for universal setup. This enables one-time trusted setup that works for any circuit.
//!
//! ## Overview
//!
//! KZG commitments allow us to:
//! - Commit to polynomials of bounded degree
//! - Open commitments at specific points with short proofs
//! - Batch multiple openings efficiently
//!
//! This is the foundation for UniGroth's universal setup.

use ark_ec::{
    pairing::Pairing, scalar_mul::BatchMulPreprocessing, AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::*;
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use zeroize::Zeroize;

/// Universal Structured Reference String (SRS) for KZG commitments.
/// This is generated once and can be reused for any circuit up to `max_degree`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniversalSRS<E: Pairing> {
    /// Powers of tau in G1: [G, τG, τ²G, ..., τⁿG]
    pub powers_of_g: Vec<E::G1Affine>,
    /// Powers of tau in G2: [H, τH, τ²H, ..., τⁿH]
    pub powers_of_h: Vec<E::G2Affine>,
    /// Maximum degree of polynomials this SRS supports
    pub max_degree: usize,
}

impl<E: Pairing> UniversalSRS<E> {
    /// Generate a new universal SRS with toxic waste.
    ///
    /// # Security Warning
    /// The toxic waste `tau` must be securely destroyed after generation.
    /// In production, use a multi-party computation ceremony (Powers of Tau).
    pub fn setup<R: RngCore + CryptoRng>(max_degree: usize, rng: &mut R) -> Self {
        let setup_time = start_timer!(|| format!("KZG Universal Setup (degree {})", max_degree));

        // Generate toxic waste
        let mut tau = E::ScalarField::rand(rng);
        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        // Compute powers of tau
        let powers_time = start_timer!(|| "Computing powers of tau");
        let mut powers_of_tau = Vec::with_capacity(max_degree + 1);
        let mut current = E::ScalarField::one();
        for _ in 0..=max_degree {
            powers_of_tau.push(current);
            current *= tau;
        }
        end_timer!(powers_time);

        // Fixed-base windowed multiplication: [τⁱG] and [τⁱH] for i = 0..max_degree
        let g1_time = start_timer!(|| "Computing G1 powers");
        let powers_of_g =
            BatchMulPreprocessing::new(g, powers_of_tau.len()).batch_mul(&powers_of_tau);
        end_timer!(g1_time);

        let g2_time = start_timer!(|| "Computing G2 powers");
        let powers_of_h =
            BatchMulPreprocessing::new(h, powers_of_tau.len()).batch_mul(&powers_of_tau);
        end_timer!(g2_time);

        // Destroy the toxic waste.
        tau.zeroize();
        current.zeroize();
        powers_of_tau.iter_mut().for_each(Zeroize::zeroize);

        end_timer!(setup_time);

        Self {
            powers_of_g,
            powers_of_h,
            max_degree,
        }
    }

    /// Load from an existing Powers of Tau ceremony transcript.
    ///
    /// This allows reusing existing trusted setup ceremonies like
    /// the Perpetual Powers of Tau.
    pub fn from_powers_of_tau(
        powers_of_g: Vec<E::G1Affine>,
        powers_of_h: Vec<E::G2Affine>,
    ) -> Self {
        let max_degree = powers_of_g.len() - 1;
        assert_eq!(
            powers_of_h.len(),
            powers_of_g.len(),
            "G1 and G2 powers must have same length"
        );

        Self {
            powers_of_g,
            powers_of_h,
            max_degree,
        }
    }

    /// Trim the SRS to a smaller degree.
    /// Useful for deriving circuit-specific parameters.
    pub fn trim(&self, degree: usize) -> Self {
        assert!(
            degree <= self.max_degree,
            "Cannot trim to degree larger than max_degree"
        );

        Self {
            powers_of_g: self.powers_of_g[..=degree].to_vec(),
            powers_of_h: self.powers_of_h[..=degree].to_vec(),
            max_degree: degree,
        }
    }

    /// Update the SRS with additional randomness (for updatable setup).
    ///
    /// This allows anyone to contribute additional entropy to the setup,
    /// making it more secure without requiring trust in any single party.
    pub fn update<R: RngCore + CryptoRng>(&mut self, rng: &mut R) {
        let update_time = start_timer!(|| "Updating SRS");

        // Generate new randomness
        let mut delta = E::ScalarField::rand(rng);

        // Update powers: [τⁱG] -> [δⁱτⁱG]
        let mut delta_power = E::ScalarField::one();
        for g in &mut self.powers_of_g {
            *g = (g.into_group() * delta_power).into_affine();
            delta_power *= delta;
        }

        // Update powers: [τⁱH] -> [δⁱτⁱH]
        let mut delta_power = E::ScalarField::one();
        for h in &mut self.powers_of_h {
            *h = (h.into_group() * delta_power).into_affine();
            delta_power *= delta;
        }

        delta.zeroize();
        delta_power.zeroize();

        end_timer!(update_time);
    }
}

/// A KZG commitment to a polynomial.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<E: Pairing> {
    /// The commitment value in G1
    pub value: E::G1Affine,
}

/// A KZG opening proof for a polynomial evaluation.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Opening<E: Pairing> {
    /// The proof value in G1
    pub proof: E::G1Affine,
}

/// KZG polynomial commitment operations.
pub struct KZG<E: Pairing> {
    _phantom: core::marker::PhantomData<E>,
}

impl<E: Pairing> KZG<E> {
    /// Commit to a polynomial using the universal SRS.
    ///
    /// Given polynomial p(X) = Σ aᵢXⁱ, computes commitment C = Σ aᵢ[τⁱG]
    pub fn commit(
        srs: &UniversalSRS<E>,
        polynomial: &DensePolynomial<E::ScalarField>,
    ) -> Commitment<E> {
        let commit_time = start_timer!(|| "KZG Commit");

        assert!(
            polynomial.degree() <= srs.max_degree,
            "Polynomial degree exceeds SRS max degree"
        );

        // Compute C = Σ aᵢ[τⁱG] with a single MSM
        let commitment = E::G1::msm_unchecked(&srs.powers_of_g, polynomial.coeffs());

        end_timer!(commit_time);

        Commitment {
            value: commitment.into_affine(),
        }
    }

    /// Create an opening proof for polynomial p at point z.
    ///
    /// Computes witness polynomial w(X) = (p(X) - p(z)) / (X - z)
    /// and returns proof π = w(τ)G
    pub fn open(
        srs: &UniversalSRS<E>,
        polynomial: &DensePolynomial<E::ScalarField>,
        point: &E::ScalarField,
    ) -> (E::ScalarField, Opening<E>) {
        let open_time = start_timer!(|| "KZG Open");

        // Evaluate p(z)
        let value = polynomial.evaluate(point);

        // Compute witness polynomial w(X) = (p(X) - p(z)) / (X - z)
        let numerator = polynomial - &DensePolynomial::from_coefficients_vec(vec![value]);
        let denominator =
            DensePolynomial::from_coefficients_vec(vec![-*point, E::ScalarField::one()]);

        // Perform polynomial division
        let witness = &numerator / &denominator;

        // Compute proof π = w(τ)G with a single MSM
        let proof = E::G1::msm_unchecked(&srs.powers_of_g, witness.coeffs());

        end_timer!(open_time);

        (
            value,
            Opening {
                proof: proof.into_affine(),
            },
        )
    }

    /// Verify a KZG opening proof.
    ///
    /// Checks that e(C - vG, H) = e(π, τH - zH)
    /// which is equivalent to checking p(z) = v
    pub fn verify(
        srs: &UniversalSRS<E>,
        commitment: &Commitment<E>,
        point: &E::ScalarField,
        value: &E::ScalarField,
        proof: &Opening<E>,
    ) -> bool {
        let verify_time = start_timer!(|| "KZG Verify");
        let ok = Self::check(
            srs,
            commitment.value.into_group(),
            point,
            *value,
            proof.proof,
        );
        end_timer!(verify_time);
        ok
    }

    /// e(C - vG, H) · e(-π, τH - zH) == 1, as one multi-pairing.
    fn check(
        srs: &UniversalSRS<E>,
        commitment: E::G1,
        point: &E::ScalarField,
        value: E::ScalarField,
        proof: E::G1Affine,
    ) -> bool {
        if srs.powers_of_g.is_empty() || srs.powers_of_h.len() < 2 {
            return false;
        }
        let c_minus_v = commitment - srs.powers_of_g[0] * value;
        let tau_h_minus_z = srs.powers_of_h[1].into_group() - srs.powers_of_h[0] * point;
        let g1 = E::G1::normalize_batch(&[c_minus_v, -proof.into_group()]);
        let g2 = E::G2::normalize_batch(&[srs.powers_of_h[0].into_group(), tau_h_minus_z]);
        E::multi_pairing(g1, g2).is_zero()
    }

    /// Batch verify multiple openings at the same point.
    ///
    /// The openings are combined with powers of a Fiat-Shamir challenge derived
    /// from every commitment, value and proof, so a prover cannot pick wrong
    /// values whose errors cancel out.
    pub fn batch_verify(
        srs: &UniversalSRS<E>,
        commitments: &[Commitment<E>],
        point: &E::ScalarField,
        values: &[E::ScalarField],
        proofs: &[Opening<E>],
    ) -> bool {
        let n = commitments.len();
        if n == 0 || values.len() != n || proofs.len() != n {
            return false;
        }

        let verify_time = start_timer!(|| format!("KZG Batch Verify ({})", n));

        let r = Self::batch_challenge(commitments, point, values, proofs);
        let mut challenges = Vec::with_capacity(n);
        let mut acc = E::ScalarField::one();
        for _ in 0..n {
            challenges.push(acc);
            acc *= r;
        }

        let c_bases: Vec<E::G1Affine> = commitments.iter().map(|c| c.value).collect();
        let p_bases: Vec<E::G1Affine> = proofs.iter().map(|p| p.proof).collect();
        let batched_commitment = E::G1::msm_unchecked(&c_bases, &challenges);
        let batched_proof = E::G1::msm_unchecked(&p_bases, &challenges).into_affine();
        let batched_value: E::ScalarField =
            values.iter().zip(&challenges).map(|(v, c)| *v * c).sum();

        let ok = Self::check(srs, batched_commitment, point, batched_value, batched_proof);

        end_timer!(verify_time);

        ok
    }

    /// SHA-256 Fiat-Shamir challenge over the whole batch statement.
    fn batch_challenge(
        commitments: &[Commitment<E>],
        point: &E::ScalarField,
        values: &[E::ScalarField],
        proofs: &[Opening<E>],
    ) -> E::ScalarField {
        use sha2::{Digest, Sha256};
        let mut buf = Vec::new();
        commitments
            .serialize_compressed(&mut buf)
            .expect("serializing to a Vec cannot fail");
        point
            .serialize_compressed(&mut buf)
            .expect("serializing to a Vec cannot fail");
        values
            .serialize_compressed(&mut buf)
            .expect("serializing to a Vec cannot fail");
        proofs
            .serialize_compressed(&mut buf)
            .expect("serializing to a Vec cannot fail");
        let digest = Sha256::new()
            .chain_update(crate::config::DOMAIN_KZG_BATCH)
            .chain_update(&buf)
            .finalize();
        E::ScalarField::from_le_bytes_mod_order(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, test_rng};

    type Fr = <Bn254 as Pairing>::ScalarField;

    #[test]
    fn test_kzg_commit_and_open() {
        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let max_degree = 10;

        // Setup
        let srs = UniversalSRS::<Bn254>::setup(max_degree, &mut rng);

        // Create a random polynomial
        let poly = DensePolynomial::rand(5, &mut rng);

        // Commit
        let commitment = KZG::commit(&srs, &poly);

        // Open at a random point
        let point = Fr::rand(&mut rng);
        let (value, proof) = KZG::open(&srs, &poly, &point);

        // Verify
        assert!(KZG::verify(&srs, &commitment, &point, &value, &proof));

        // Verify with wrong value should fail
        let wrong_value = value + Fr::from(1u64);
        assert!(!KZG::verify(
            &srs,
            &commitment,
            &point,
            &wrong_value,
            &proof
        ));
    }

    #[test]
    fn test_kzg_batch_verify() {
        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let max_degree = 10;

        let srs = UniversalSRS::<Bn254>::setup(max_degree, &mut rng);

        // Create multiple polynomials
        let polys = vec![
            DensePolynomial::rand(5, &mut rng),
            DensePolynomial::rand(7, &mut rng),
            DensePolynomial::rand(3, &mut rng),
        ];

        // Commit to all
        let commitments: Vec<_> = polys.iter().map(|p| KZG::commit(&srs, p)).collect();

        // Open all at the same point
        let point = Fr::rand(&mut rng);
        let openings: Vec<_> = polys.iter().map(|p| KZG::open(&srs, p, &point)).collect();

        let values: Vec<_> = openings.iter().map(|(v, _)| *v).collect();
        let proofs: Vec<_> = openings.iter().map(|(_, p)| p.clone()).collect();

        // Batch verify
        assert!(KZG::batch_verify(
            &srs,
            &commitments,
            &point,
            &values,
            &proofs
        ));

        // Errors that cancel under fixed weights (1, 2) must still be caught.
        let mut bad = values.clone();
        bad[0] += Fr::from(2u64);
        bad[1] -= Fr::from(1u64);
        assert!(!KZG::batch_verify(
            &srs,
            &commitments,
            &point,
            &bad,
            &proofs
        ));
    }

    #[test]
    fn test_srs_update() {
        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let max_degree = 5;

        let mut srs = UniversalSRS::<Bn254>::setup(max_degree, &mut rng);
        let original_srs = srs.clone();

        // Update SRS
        srs.update(&mut rng);

        // SRS should be different after update
        assert_ne!(srs.powers_of_g, original_srs.powers_of_g);
        assert_ne!(srs.powers_of_h, original_srs.powers_of_h);

        // But should still work for commitments
        let poly = DensePolynomial::rand(3, &mut rng);
        let commitment = KZG::commit(&srs, &poly);
        let point = Fr::rand(&mut rng);
        let (value, proof) = KZG::open(&srs, &poly, &point);
        assert!(KZG::verify(&srs, &commitment, &point, &value, &proof));
    }
}
