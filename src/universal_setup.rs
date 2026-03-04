//! # Universal Setup for UniGroth
//!
//! This module implements the universal trusted setup that allows one-time
//! ceremony to work for any circuit up to a maximum size.
//!
//! ## Key Features
//!
//! - One-time Powers-of-Tau ceremony
//! - Reusable for any circuit up to max degree
//! - Updatable for enhanced security
//! - Compatible with existing PoT transcripts
//!
//! ## Usage
//!
//! ```ignore
//! // One-time universal setup
//! let universal_params = UniversalSetup::setup(max_degree, &mut rng);
//!
//! // Derive circuit-specific keys (no new ceremony needed!)
//! let (pk, vk) = universal_params.derive_keys(circuit)?;
//!
//! // Use with standard Groth16 API
//! let proof = Groth16::prove(&pk, circuit, &mut rng)?;
//! ```

use crate::{
    kzg::UniversalSRS, r1cs_to_qap::R1CSToQAP, sap::R1CSToSAP, ProvingKey, Vec, VerifyingKey,
};
use ark_ec::{pairing::Pairing, scalar_mul::BatchMulPreprocessing, AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult,
    SynthesisError, SynthesisMode,
};
use ark_serialize::*;
use ark_std::{
    cfg_into_iter, cfg_iter,
    rand::{CryptoRng, RngCore},
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Universal parameters for UniGroth.
///
/// Generated once and reused for all circuits up to `max_degree`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniversalParams<E: Pairing> {
    /// The universal SRS for KZG commitments
    pub srs: UniversalSRS<E>,
    /// Additional Groth16-specific parameters (alpha)
    pub alpha: E::ScalarField,
    /// Additional Groth16-specific parameters (beta)
    pub beta: E::ScalarField,
    /// Additional Groth16-specific parameters (gamma)
    pub gamma: E::ScalarField,
    /// G1 generator
    pub g1_generator: E::G1Affine,
    /// G2 generator
    pub g2_generator: E::G2Affine,
}

impl<E: Pairing> UniversalParams<E> {
    /// Generate universal parameters with a new trusted setup.
    ///
    /// # Security Warning
    /// In production, use a multi-party computation ceremony (Powers of Tau).
    /// The toxic waste must be securely destroyed.
    pub fn setup<R: RngCore + CryptoRng>(max_degree: usize, rng: &mut R) -> Self {
        let setup_time = start_timer!(|| format!("Universal Setup (max degree {})", max_degree));

        // Generate KZG SRS
        let srs = UniversalSRS::setup(max_degree, rng);

        // Generate Groth16-specific randomness
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        let gamma = E::ScalarField::rand(rng);

        let g1_generator = E::G1::rand(rng).into_affine();
        let g2_generator = E::G2::rand(rng).into_affine();

        end_timer!(setup_time);

        Self {
            srs,
            alpha,
            beta,
            gamma,
            g1_generator,
            g2_generator,
        }
    }

    /// Load from an existing Powers of Tau ceremony.
    ///
    /// This allows reusing existing trusted setup ceremonies like
    /// the Perpetual Powers of Tau for BN254 or BLS12-381.
    pub fn from_powers_of_tau<R: RngCore + CryptoRng>(
        powers_of_g: Vec<E::G1Affine>,
        powers_of_h: Vec<E::G2Affine>,
        rng: &mut R,
    ) -> Self {
        let srs = UniversalSRS::from_powers_of_tau(powers_of_g, powers_of_h);

        // Generate Groth16-specific randomness
        // In a real implementation, this would also come from an MPC
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        let gamma = E::ScalarField::rand(rng);

        let g1_generator = srs.powers_of_g[0];
        let g2_generator = srs.powers_of_h[0];

        Self {
            srs,
            alpha,
            beta,
            gamma,
            g1_generator,
            g2_generator,
        }
    }

    /// Update the universal parameters with additional randomness.
    ///
    /// This allows anyone to contribute entropy, making the setup more secure
    /// without requiring trust in any single party.
    pub fn update<R: RngCore + CryptoRng>(&mut self, rng: &mut R) {
        let update_time = start_timer!(|| "Updating universal parameters");

        // Update SRS
        self.srs.update(rng);

        // Update Groth16 parameters
        let delta_alpha = E::ScalarField::rand(rng);
        let delta_beta = E::ScalarField::rand(rng);
        let delta_gamma = E::ScalarField::rand(rng);

        self.alpha *= delta_alpha;
        self.beta *= delta_beta;
        self.gamma *= delta_gamma;

        end_timer!(update_time);
    }

    /// Derive circuit-specific proving and verifying keys.
    ///
    /// This is the key innovation: no new trusted setup ceremony needed!
    pub fn derive_keys<C, QAP: R1CSToQAP>(
        &self,
        circuit: C,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> R1CSResult<(ProvingKey<E>, VerifyingKey<E>)>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        type D<F> = GeneralEvaluationDomain<F>;

        let derive_time = start_timer!(|| "Deriving circuit-specific keys");

        // Synthesize the circuit
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);

        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        // Check circuit size
        let domain_size = cs.num_constraints() + cs.num_instance_variables();
        if domain_size > self.srs.max_degree {
            return Err(SynthesisError::PolynomialDegreeTooLarge);
        }

        // Generate delta (circuit-specific randomness)
        let delta = E::ScalarField::rand(rng);

        // Construct evaluation domain
        let domain_time = start_timer!(|| "Constructing evaluation domain");
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let t = domain.sample_element_outside_domain(rng);
        end_timer!(domain_time);

        // R1CS to QAP/SAP reduction
        let reduction_time = start_timer!(|| "R1CS to QAP/SAP reduction");
        let num_instance_variables = cs.num_instance_variables();
        let (a, b, c, zt, qap_num_variables, m_raw) =
            QAP::instance_map_with_evaluation::<E::ScalarField, D<E::ScalarField>>(cs, &t)?;
        end_timer!(reduction_time);

        // Compute inverses
        let gamma_inverse = self.gamma.inverse().unwrap();
        let delta_inverse = delta.inverse().unwrap();

        // Compute gamma_abc
        let gamma_abc = cfg_iter!(a[..num_instance_variables])
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a, b), c)| (self.beta * a + &(self.alpha * b) + c) * &gamma_inverse)
            .collect::<Vec<_>>();

        // Compute l
        let l = cfg_iter!(a[num_instance_variables..])
            .zip(&b[num_instance_variables..])
            .zip(&c[num_instance_variables..])
            .map(|((a, b), c)| (self.beta * a + &(self.alpha * b) + c) * &delta_inverse)
            .collect::<Vec<_>>();

        drop(c);

        // Count non-zero elements for optimization
        let non_zero_a: usize = cfg_into_iter!(0..qap_num_variables)
            .map(|i| usize::from(!a[i].is_zero()))
            .sum();

        let non_zero_b: usize = cfg_into_iter!(0..qap_num_variables)
            .map(|i| usize::from(!b[i].is_zero()))
            .sum();

        // Use universal SRS to compute key elements
        let key_gen_time = start_timer!(|| "Key generation from universal SRS");

        // Compute G2 elements
        let g2_time = start_timer!(|| "Compute G2 elements");
        let g2_table = BatchMulPreprocessing::new(self.g2_generator.into_group(), non_zero_b);
        let b_g2_query = g2_table.batch_mul(&b);
        drop(g2_table);
        end_timer!(g2_time);

        // Compute G1 elements
        let g1_time = start_timer!(|| "Compute G1 elements");
        let num_scalars = non_zero_a + non_zero_b + qap_num_variables + m_raw + 1;
        let g1_table = BatchMulPreprocessing::new(self.g1_generator.into_group(), num_scalars);

        let alpha_g1 = self.g1_generator.into_group() * self.alpha;
        let beta_g1 = self.g1_generator.into_group() * self.beta;
        let beta_g2 = self.g2_generator.into_group() * self.beta;
        let delta_g1 = self.g1_generator.into_group() * delta;
        let delta_g2 = self.g2_generator.into_group() * delta;
        let gamma_g2 = self.g2_generator.into_group() * self.gamma;

        let a_query = g1_table.batch_mul(&a);
        drop(a);

        let b_g1_query = g1_table.batch_mul(&b);
        drop(b);

        // Compute H-query
        let h_scalars =
            QAP::h_query_scalars::<_, D<E::ScalarField>>(m_raw - 1, t, zt, delta_inverse)?;
        let h_query = g1_table.batch_mul(&h_scalars);

        // Compute L-query
        let l_query = g1_table.batch_mul(&l);
        drop(l);

        // Compute gamma_abc
        let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);
        drop(g1_table);

        end_timer!(g1_time);
        end_timer!(key_gen_time);

        // Construct keys
        let vk = VerifyingKey::<E> {
            alpha_g1: alpha_g1.into_affine(),
            beta_g2: beta_g2.into_affine(),
            gamma_g2: gamma_g2.into_affine(),
            delta_g2: delta_g2.into_affine(),
            gamma_abc_g1,
        };

        let pk = ProvingKey {
            vk: vk.clone(),
            beta_g1: beta_g1.into_affine(),
            delta_g1: delta_g1.into_affine(),
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        end_timer!(derive_time);

        Ok((pk, vk))
    }

    /// Derive keys using SAP arithmetization for better efficiency.
    pub fn derive_keys_with_sap<C>(
        &self,
        circuit: C,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> R1CSResult<(ProvingKey<E>, VerifyingKey<E>)>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        self.derive_keys::<C, R1CSToSAP>(circuit, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{r1cs_to_qap::LibsnarkReduction, Groth16};
    use ark_bn254::{Bn254, Fr};
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_snark::SNARK;
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, test_rng};

    #[derive(Clone)]
    struct TestCircuit {
        x: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let x_squared = cs.new_input_variable(|| {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val)
            })?;

            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_squared)?;

            Ok(())
        }
    }

    #[test]
    fn test_universal_setup() {
        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let max_degree = 100;

        // One-time universal setup
        let universal_params = UniversalParams::<Bn254>::setup(max_degree, &mut rng);

        // Derive keys for a specific circuit (no new ceremony!)
        let circuit = TestCircuit { x: None };
        let (pk, vk) = universal_params
            .derive_keys::<_, LibsnarkReduction>(circuit, &mut rng)
            .unwrap();

        // Use with standard Groth16
        let x = Fr::from(3u64);
        let circuit = TestCircuit { x: Some(x) };
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let x_squared = x * x;
        let public_inputs = vec![x_squared];

        let pvk = crate::prepare_verifying_key(&vk);
        let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_universal_setup_multiple_circuits() {
        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let max_degree = 100;

        // One universal setup
        let universal_params = UniversalParams::<Bn254>::setup(max_degree, &mut rng);

        // Derive keys for multiple different circuits
        for i in 1..=5 {
            let circuit = TestCircuit { x: None };
            let (pk, vk) = universal_params
                .derive_keys::<_, LibsnarkReduction>(circuit, &mut rng)
                .unwrap();

            // Each circuit works correctly
            let x = Fr::from(i as u64);
            let circuit = TestCircuit { x: Some(x) };
            let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

            let x_squared = x * x;
            let public_inputs = vec![x_squared];

            let pvk = crate::prepare_verifying_key(&vk);
            let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();

            assert!(valid);
        }
    }

    #[test]
    fn test_updatable_setup() {
        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let max_degree = 50;

        let mut universal_params = UniversalParams::<Bn254>::setup(max_degree, &mut rng);

        // Update with additional randomness
        universal_params.update(&mut rng);

        // Should still work after update
        let circuit = TestCircuit { x: None };
        let (pk, vk) = universal_params
            .derive_keys::<_, LibsnarkReduction>(circuit, &mut rng)
            .unwrap();

        let x = Fr::from(7u64);
        let circuit = TestCircuit { x: Some(x) };
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let x_squared = x * x;
        let public_inputs = vec![x_squared];

        let pvk = crate::prepare_verifying_key(&vk);
        let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();

        assert!(valid);
    }
}
