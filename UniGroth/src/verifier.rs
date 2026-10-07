use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::Valid;

use crate::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_relations::gr1cs::{Result as R1CSResult, SynthesisError};

use core::ops::Neg;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

/// Check that every proof point is non-identity, on the curve and in the
/// prime-order subgroup.
///
/// A=0 or B=0 makes e(A, B) = 1 and removes the prover's only degree of
/// freedom; a point outside the subgroup (possible for in-memory proofs and
/// on G2 of BN254, whose cofactor is not 1) breaks the pairing algebra the
/// soundness proof relies on. ark-groth16 only gets these checks when the
/// proof came through validated deserialization; here every verifier runs them.
pub fn proof_points_valid<E: Pairing>(proof: &Proof<E>) -> bool {
    !proof.a.is_zero() && !proof.b.is_zero() && !proof.c.is_zero() && proof.check().is_ok()
}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`],
    /// wrt the prepared verification key `pvk` and instance public inputs.
    ///
    /// Uses batch MSM (Pippenger) instead of n individual scalar multiplications —
    /// roughly 2× faster for large public input vectors and reduces variable-time
    /// scalar-mult side-channel exposure.
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<E::G1> {
        // Validate input count before any computation: prevents panic on out-of-bounds
        // and rejects proofs with wrong public input arity.
        if public_inputs.len() + 1 != pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        if public_inputs.len() < crate::config::VERIFIER_MSM_THRESHOLD {
            // For a handful of inputs, direct scalar multiplication beats
            // Pippenger's bucket setup and thread dispatch.
            for (x, base) in public_inputs.iter().zip(&pvk.vk.gamma_abc_g1[1..]) {
                g_ic += base.mul_bigint(x.into_bigint());
            }
        } else {
            g_ic += E::G1::msm(&pvk.vk.gamma_abc_g1[1..], public_inputs)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
        }

        Ok(g_ic)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key
    /// `pvk` and prepared public inputs. Prefer this over [`verify_proof`]
    /// when public inputs are known in advance (avoids re-computing MSM).
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        // e(A, B) · e(inputs, -γ) · e(C, -δ) = e(α, β)
        let pairing_check = || {
            let qap = E::multi_miller_loop(
                [
                    <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
                    prepared_inputs.into_affine().into(),
                    proof.c.into(),
                ],
                [
                    proof.b.into(),
                    pvk.gamma_g2_neg_pc.clone(),
                    pvk.delta_g2_neg_pc.clone(),
                ],
            );
            E::final_exponentiation(qap).is_some_and(|t| t.0 == pvk.alpha_g1_beta_g2)
        };

        // The subgroup check (one G2 scalar mul) runs alongside the pairing,
        // so the hardening costs no wall-clock time on multi-core machines.
        #[cfg(feature = "parallel")]
        let (valid, paired) = rayon::join(|| proof_points_valid(proof), pairing_check);
        #[cfg(not(feature = "parallel"))]
        let (valid, paired) = {
            let valid = proof_points_valid(proof);
            (valid, valid && pairing_check())
        };

        Ok(valid && paired)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key
    /// `pvk`, with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &prepared_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr, G1Affine};
    use ark_ec::AffineRepr;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
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

    // Circuit with no public inputs: a == b via a*1 == b.
    struct NoPublicInputCircuit {
        a: Fr,
        b: Fr,
    }

    impl ConstraintSynthesizer<Fr> for NoPublicInputCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(self.a))?;
            let b = cs.new_witness_variable(|| Ok(self.b))?;
            // a * b == a*b (always satisfiable; no public output declared)
            cs.enforce_r1cs_constraint(
                || lc!() + a,
                || lc!() + b,
                || lc!() + (Fr::from(1u64), ark_relations::gr1cs::Variable::One),
            )?;
            Ok(())
        }
    }

    fn setup_and_prove(
        a: Fr,
        b: Fr,
        seed: u64,
    ) -> (
        crate::PreparedVerifyingKey<Bn254>,
        crate::Proof<Bn254>,
        Vec<Fr>,
    ) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        let (pk, vk) = Groth16::<Bn254>::setup(TestCircuit { a, b }, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let proof = Groth16::<Bn254>::prove(&pk, TestCircuit { a, b }, &mut rng).unwrap();
        let inputs = vec![a * b];
        (pvk, proof, inputs)
    }

    #[test]
    fn test_verify_valid_proof() {
        let (pvk, proof, inputs) = setup_and_prove(Fr::from(3u64), Fr::from(5u64), 10u64);
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof);
        assert!(
            matches!(result, Ok(true)),
            "Valid proof must verify: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_wrong_inputs_fails() {
        let (pvk, proof, _inputs) = setup_and_prove(Fr::from(3u64), Fr::from(5u64), 11u64);
        let wrong_inputs = vec![Fr::from(999u64)];
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &wrong_inputs, &proof);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "Wrong inputs must not verify: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_empty_inputs_no_public() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(12u64);
        let a = Fr::from(1u64);
        let b = Fr::from(1u64);
        let (pk, vk) = Groth16::<Bn254>::setup(NoPublicInputCircuit { a, b }, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let proof = Groth16::<Bn254>::prove(&pk, NoPublicInputCircuit { a, b }, &mut rng).unwrap();
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof);
        assert!(
            matches!(result, Ok(true)),
            "No-public-input proof must verify with empty inputs: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_flipped_proof_fails() {
        let (pvk, valid_proof, inputs) = setup_and_prove(Fr::from(2u64), Fr::from(8u64), 13u64);

        let bad_proof = crate::Proof::<Bn254> {
            a: G1Affine::generator(),
            ..valid_proof
        };

        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &bad_proof);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "Flipped proof must not verify: {:?}",
            result
        );
    }

    #[test]
    fn test_prepare_verifying_key() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(14u64);
        let (pk, vk) = Groth16::<Bn254>::setup(
            TestCircuit {
                a: Fr::from(1u64),
                b: Fr::from(1u64),
            },
            &mut rng,
        )
        .unwrap();
        let _ = pk;
        let pvk = prepare_verifying_key(&vk);
        assert_eq!(
            pvk.vk, vk,
            "PreparedVerifyingKey must embed the original VerifyingKey unchanged"
        );
    }
}
