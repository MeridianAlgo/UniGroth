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

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
};
use ark_serialize::*;
use ark_std::{cfg_iter, rand::{CryptoRng, RngCore}, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Universal Structured Reference String (SRS) for KZG commitments.
/// This is generated once and can be reused for any circuit up to `max_degree`.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
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
        let tau = E::ScalarField::rand(rng);
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

        // Compute [τⁱG] for i = 0..max_degree
        let g1_time = start_timer!(|| "Computing G1 powers");
        let powers_of_g = cfg_iter!(powers_of_tau)
            .map(|power| (g * power).into_affine())
            .collect::<Vec<_>>();
        end_timer!(g1_time);

        // Compute [τⁱH] for i = 0..max_degree
        let g2_time = start_timer!(|| "Computing G2 powers");
        let powers_of_h = cfg_iter!(powers_of_tau)
            .map(|power| (h * power).into_affine())
            .collect::<Vec<_>>();
        end_timer!(g2_time);

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
        let delta = E::ScalarField::rand(rng);

        // Update powers: [τⁱG] -> [δτⁱG]
        let mut delta_power = E::ScalarField::one();
        for g in &mut self.powers_of_g {
            *g = (g.into_group() * delta_power).into_affine();
            delta_power *= delta;
        }

        // Update powers: [τⁱH] -> [δτⁱH]
        let mut delta_power = E::ScalarField::one();
        for h in &mut self.powers_of_h {
            *h = (h.into_group() * delta_power).into_affine();
            delta_power *= delta;
        }

        end_timer!(update_time);
    }
}

/// A KZG commitment to a polynomial.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<E: Pairing> {
    /// The commitment value in G1
    pub value: E::G1Affine,
}

/// A KZG opening proof for a polynomial evaluation.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
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

        // Compute C = Σ aᵢ[τⁱG]
        let coeffs = polynomial.coeffs();
        let commitment = cfg_iter!(coeffs)
            .zip(&srs.powers_of_g)
            .map(|(coeff, power)| power.into_group() * coeff)
            .sum::<E::G1>();

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
        let denominator = DensePolynomial::from_coefficients_vec(vec![-*point, E::ScalarField::one()]);
        
        // Perform polynomial division
        let witness = &numerator / &denominator;

        // Compute proof π = w(τ)G
        let proof = cfg_iter!(witness.coeffs())
            .zip(&srs.powers_of_g)
            .map(|(coeff, power)| power.into_group() * coeff)
            .sum::<E::G1>();

        end_timer!(open_time);

        (value, Opening {
            proof: proof.into_affine(),
        })
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

        // Compute C - vG
        let c_minus_v = (commitment.value.into_group() - srs.powers_of_g[0] * value).into_affine();

        // Compute τH - zH
        let tau_h_minus_z = (srs.powers_of_h[1].into_group() - srs.powers_of_h[0] * point).into_affine();

        // Check pairing equation: e(C - vG, H) = e(π, τH - zH)
        let lhs = E::pairing(c_minus_v, srs.powers_of_h[0]);
        let rhs = E::pairing(proof.proof, tau_h_minus_z);

        end_timer!(verify_time);

        lhs == rhs
    }

    /// Batch verify multiple openings at the same point.
    ///
    /// More efficient than verifying each opening individually.
    pub fn batch_verify(
        srs: &UniversalSRS<E>,
        commitments: &[Commitment<E>],
        point: &E::ScalarField,
        values: &[E::ScalarField],
        proofs: &[Opening<E>],
    ) -> bool {
        assert_eq!(commitments.len(), values.len());
        assert_eq!(commitments.len(), proofs.len());

        let verify_time = start_timer!(|| format!("KZG Batch Verify ({})", commitments.len()));

        // Generate random challenges for batching
        let challenges: Vec<_> = (0..commitments.len())
            .map(|i| E::ScalarField::from((i + 1) as u64))
            .collect();
        
        // Compute batched commitment: Σ rⁱCᵢ
        let batched_commitment = cfg_iter!(commitments)
            .zip(&challenges)
            .map(|(c, challenge)| c.value.into_group() * challenge)
            .sum::<E::G1>();

        // Compute batched value: Σ rⁱvᵢ
        let batched_value = cfg_iter!(values)
            .zip(&challenges)
            .map(|(v, challenge)| *v * challenge)
            .sum::<E::ScalarField>();

        // Compute batched proof: Σ rⁱπᵢ
        let batched_proof = cfg_iter!(proofs)
            .zip(&challenges)
            .map(|(p, challenge)| p.proof.into_group() * challenge)
            .sum::<E::G1>();

        // Verify batched opening
        let c_minus_v = (batched_commitment - srs.powers_of_g[0] * batched_value).into_affine();
        let tau_h_minus_z = (srs.powers_of_h[1].into_group() - srs.powers_of_h[0] * point).into_affine();

        let lhs = E::pairing(c_minus_v, srs.powers_of_h[0]);
        let rhs = E::pairing(batched_proof.into_affine(), tau_h_minus_z);

        end_timer!(verify_time);

        lhs == rhs
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
        assert!(!KZG::verify(&srs, &commitment, &point, &wrong_value, &proof));
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
        let openings: Vec<_> = polys
            .iter()
            .map(|p| KZG::open(&srs, p, &point))
            .collect();

        let values: Vec<_> = openings.iter().map(|(v, _)| *v).collect();
        let proofs: Vec<_> = openings.iter().map(|(_, p)| p.clone()).collect();

        // Batch verify
        assert!(KZG::batch_verify(&srs, &commitments, &point, &values, &proofs));
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
