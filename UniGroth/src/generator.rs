use crate::{r1cs_to_qap::R1CSToQAP, Groth16, ProvingKey, Vec, VerifyingKey};
use ark_ec::{pairing::Pairing, scalar_mul::BatchMulPreprocessing, CurveGroup};
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult,
    SynthesisError, SynthesisMode,
};
use ark_std::{cfg_into_iter, cfg_iter, rand::Rng};
use zeroize::Zeroize;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Generates a random common reference string for
    /// a circuit using the provided R1CS-to-QAP reduction.
    #[inline]
    pub fn generate_random_parameters_with_reduction<C>(
        circuit: C,
        rng: &mut impl Rng,
    ) -> R1CSResult<ProvingKey<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        let gamma = E::ScalarField::rand(rng);
        let delta = E::ScalarField::rand(rng);

        let g1_generator = E::G1::rand(rng);
        let g2_generator = E::G2::rand(rng);

        Self::generate_parameters_with_qap(
            circuit,
            alpha,
            beta,
            gamma,
            delta,
            g1_generator,
            g2_generator,
            rng,
        )
    }

    /// Create parameters for a circuit, given some toxic waste, R1CS to QAP
    /// calculator and group generators
    pub fn generate_parameters_with_qap<C>(
        circuit: C,
        mut alpha: E::ScalarField,
        mut beta: E::ScalarField,
        mut gamma: E::ScalarField,
        mut delta: E::ScalarField,
        g1_generator: E::G1,
        g2_generator: E::G2,
        rng: &mut impl Rng,
    ) -> R1CSResult<ProvingKey<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        type D<F> = GeneralEvaluationDomain<F>;

        let setup_time = start_timer!(|| "Groth16::Generator");
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        // Following is the mapping of symbols from the Groth16 paper to this
        // implementation l -> num_instance_variables
        // m -> qap_num_variables
        // x -> t
        // t(x) - zt
        // u_i(x) -> a
        // v_i(x) -> b
        // w_i(x) -> c

        ///////////////////////////////////////////////////////////////////////////
        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let domain_size = cs.num_constraints() + cs.num_instance_variables();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let t = domain.sample_element_outside_domain(rng);

        end_timer!(domain_time);
        ///////////////////////////////////////////////////////////////////////////

        let reduction_time = start_timer!(|| "R1CS to QAP Instance Map with Evaluation");
        let num_instance_variables = cs.num_instance_variables();
        let (a, b, c, zt, qap_num_variables, m_raw) =
            QAP::instance_map_with_evaluation::<E::ScalarField, D<E::ScalarField>>(cs, &t)?;
        end_timer!(reduction_time);

        // Compute query densities
        let non_zero_a: usize = cfg_into_iter!(0..qap_num_variables)
            .map(|i| usize::from(!a[i].is_zero()))
            .sum();

        let non_zero_b: usize = cfg_into_iter!(0..qap_num_variables)
            .map(|i| usize::from(!b[i].is_zero()))
            .sum();

        let mut gamma_inverse = gamma.inverse().unwrap();
        let mut delta_inverse = delta.inverse().unwrap();

        let gamma_abc = cfg_iter!(a[..num_instance_variables])
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &gamma_inverse)
            .collect::<Vec<_>>();

        let l = cfg_iter!(a[num_instance_variables..])
            .zip(&b[num_instance_variables..])
            .zip(&c[num_instance_variables..])
            .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &delta_inverse)
            .collect::<Vec<_>>();

        drop(c);

        // gamma_inverse is no longer needed after gamma_abc is collected.
        // Zero it immediately. (delta_inverse is still needed for h_query_scalars.)
        gamma_inverse.zeroize();

        // Compute B window table
        let g2_time = start_timer!(|| "Compute G2 table");
        let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);
        end_timer!(g2_time);

        // Compute the B-query in G2
        let b_g2_time = start_timer!(|| format!("Calculate B G2 of size {}", b.len()));
        let b_g2_query = g2_table.batch_mul(&b);
        drop(g2_table);
        end_timer!(b_g2_time);

        // Compute G window table
        let g1_window_time = start_timer!(|| "Compute G1 window table");
        let num_scalars = non_zero_a + non_zero_b + qap_num_variables + m_raw + 1;
        let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);
        end_timer!(g1_window_time);

        // Generate the R1CS proving key
        let proving_key_time = start_timer!(|| "Generate the R1CS proving key");

        let alpha_g1 = g1_generator * &alpha;
        let beta_g1 = g1_generator * &beta;
        let beta_g2 = g2_generator * &beta;
        let delta_g1 = g1_generator * &delta;
        let delta_g2 = g2_generator * &delta;

        // alpha, beta, delta no longer needed as scalars after this point.
        // Zero them to prevent toxic waste lingering in stack memory.
        alpha.zeroize();
        beta.zeroize();
        delta.zeroize();

        // Compute the A-query
        let a_time = start_timer!(|| "Calculate A");
        let a_query = g1_table.batch_mul(&a);
        drop(a);
        end_timer!(a_time);

        // Compute the B-query in G1
        let b_g1_time = start_timer!(|| "Calculate B G1");
        let b_g1_query = g1_table.batch_mul(&b);
        drop(b);
        end_timer!(b_g1_time);

        // Compute the H-query
        let h_time = start_timer!(|| "Calculate H");
        let h_scalars =
            QAP::h_query_scalars::<_, D<E::ScalarField>>(m_raw - 1, t, zt, delta_inverse)?;
        let h_query = g1_table.batch_mul(&h_scalars);
        end_timer!(h_time);

        // delta_inverse last used above; zero it now.
        delta_inverse.zeroize();

        // Compute the L-query
        let l_time = start_timer!(|| "Calculate L");
        let l_query = g1_table.batch_mul(&l);
        drop(l);
        end_timer!(l_time);

        end_timer!(proving_key_time);

        // Generate R1CS verification key
        let verifying_key_time = start_timer!(|| "Generate the R1CS verification key");
        let gamma_g2 = g2_generator * &gamma;
        let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);
        drop(g1_table);

        // gamma last used above; zero it now.
        gamma.zeroize();

        end_timer!(verifying_key_time);

        let vk = VerifyingKey::<E> {
            alpha_g1: alpha_g1.into_affine(),
            beta_g2: beta_g2.into_affine(),
            gamma_g2: gamma_g2.into_affine(),
            delta_g2: delta_g2.into_affine(),
            gamma_abc_g1,
        };

        end_timer!(setup_time);

        Ok(ProvingKey {
            vk,
            beta_g1: beta_g1.into_affine(),
            delta_g1: delta_g1.into_affine(),
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_serialize::CanonicalSerialize;
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::rand::SeedableRng;

    struct TestCircuit {
        a: Fr,
        b: Fr,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(self.a))?;
            let b = cs.new_witness_variable(|| Ok(self.b))?;
            let c = cs.new_input_variable(|| Ok(self.a * self.b))?;
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn test_circuit_specific_setup() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(1u64);
        let result = Groth16::<Bn254>::setup(
            TestCircuit {
                a: Fr::from(1u64),
                b: Fr::from(1u64),
            },
            &mut rng,
        );
        assert!(result.is_ok(), "Setup must succeed for a valid circuit");
        let (pk, vk) = result.unwrap();
        assert!(
            !pk.a_query.is_empty(),
            "ProvingKey a_query must be non-empty after setup"
        );
        assert!(
            vk.gamma_abc_g1.len() >= 2,
            "VerifyingKey must hold at least 2 gamma_abc_g1 elements for TestCircuit"
        );
    }

    #[test]
    fn test_proving_key_has_correct_sizes() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(2u64);
        let (pk, _vk) = Groth16::<Bn254>::setup(
            TestCircuit {
                a: Fr::from(3u64),
                b: Fr::from(4u64),
            },
            &mut rng,
        )
        .unwrap();
        assert!(
            !pk.a_query.is_empty(),
            "a_query must be non-empty: got {}",
            pk.a_query.len()
        );
        assert!(
            !pk.l_query.is_empty(),
            "l_query must be non-empty: got {}",
            pk.l_query.len()
        );
        assert!(
            !pk.h_query.is_empty(),
            "h_query must be non-empty: got {}",
            pk.h_query.len()
        );
    }

    #[test]
    fn test_zeroized_toxic_waste() {
        use ark_ff::UniformRand;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(3u64);
        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);
        let delta = Fr::rand(&mut rng);
        let g1 = ark_bn254::G1Projective::rand(&mut rng);
        let g2 = ark_bn254::G2Projective::rand(&mut rng);
        let pk_res = Groth16::<Bn254>::generate_parameters_with_qap(
            TestCircuit {
                a: Fr::from(5u64),
                b: Fr::from(7u64),
            },
            alpha,
            beta,
            gamma,
            delta,
            g1,
            g2,
            &mut rng,
        );
        assert!(
            pk_res.is_ok(),
            "generate_parameters_with_qap must succeed: {:?}",
            pk_res.err()
        );
        let pk = pk_res.unwrap();
        let vk = pk.vk.clone();
        let proof = Groth16::<Bn254>::prove(
            &pk,
            TestCircuit {
                a: Fr::from(5u64),
                b: Fr::from(7u64),
            },
            &mut rng,
        )
        .unwrap();
        let pvk = crate::prepare_verifying_key(&vk);
        let inputs = vec![Fr::from(5u64) * Fr::from(7u64)];
        let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
        assert!(ok, "Proof under explicit toxic waste must verify");
    }

    #[test]
    fn test_setup_determinism_with_seed() {
        let seed = 99u64;
        let mut rng1 = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        let (_pk1, vk1) = Groth16::<Bn254>::setup(
            TestCircuit {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
            },
            &mut rng1,
        )
        .unwrap();
        let mut rng2 = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        let (_pk2, vk2) = Groth16::<Bn254>::setup(
            TestCircuit {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
            },
            &mut rng2,
        )
        .unwrap();
        let mut bytes1 = Vec::new();
        let mut bytes2 = Vec::new();
        vk1.serialize_uncompressed(&mut bytes1).unwrap();
        vk2.serialize_uncompressed(&mut bytes2).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "Setup with identical seeds must produce identical verifying keys"
        );
    }
}
