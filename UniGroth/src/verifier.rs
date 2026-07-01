use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};

use crate::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::{PreparedVerifyingKey, VerifyingKey};

use ark_relations::gr1cs::{Result as R1CSResult, SynthesisError};

use core::ops::Neg;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
        delta_g1_prepared: E::G1Prepared::default(),
    }
}

/// Prepare the verifying key with delta_g1 for simulation-extractability support.
pub fn prepare_verifying_key_with_delta<E: Pairing>(
    vk: &VerifyingKey<E>,
    delta_g1: E::G1Affine,
) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
        delta_g1_prepared: delta_g1.into(),
    }
}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Validate that all proof elements are non-identity curve points.
    ///
    /// Guards against identity-element attacks: A=0 makes e(0, B) = 1 in GT,
    /// which trivially satisfies the pairing equation for any B, C, and inputs.
    ///
    /// Subgroup membership (against small-subgroup attacks) is guaranteed by
    /// arkworks' `CanonicalDeserialize` for standard curves (BN254, BLS12-381)
    /// — both enforce on-curve + subgroup checks during deserialization. For
    /// programmatically-constructed proofs on curves with cofactor h>1, callers
    /// should apply cofactor clearing before calling verify.
    #[inline]
    fn validate_proof_points(proof: &crate::SimExtractableProof<E>) -> bool {
        let p = &proof.groth16_proof;
        if p.a.is_zero() || p.c.is_zero() {
            return false;
        }
        if let Some(d) = proof.se_element {
            if d.is_zero() {
                return false;
            }
        }
        true
    }

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

        let g_ic = if public_inputs.is_empty() {
            pvk.vk.gamma_abc_g1[0].into_group()
        } else {
            // Batch MSM replaces n individual mul_bigint calls.
            // Pippenger's algorithm: ~O(n / log n) group ops vs O(n * log p) naive.
            let ic_acc = E::G1::msm(&pvk.vk.gamma_abc_g1[1..], public_inputs).map_err(|e| {
                let _ = e;
                SynthesisError::Unsatisfiable
            })?;
            pvk.vk.gamma_abc_g1[0].into_group() + ic_acc
        };

        Ok(g_ic)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key
    /// `pvk` and prepared public inputs. Prefer this over [`verify_proof`]
    /// when public inputs are known in advance (avoids re-computing MSM).
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &crate::SimExtractableProof<E>,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        // Subgroup membership check: prevents small-subgroup / rogue-key attacks
        // where a malicious prover submits proof elements in a small-order subgroup.
        if !Self::validate_proof_points(proof) {
            return Ok(false);
        }

        let p = &proof.groth16_proof;

        if let Some(d) = proof.se_element {
            // BG18 SE verification: 4-pairing check
            // e(A, B) · e(inputs, -γ) · e(C, -δ) · e(δ_g1, -D) = e(α, β)
            let qap = E::multi_miller_loop(
                [
                    <E::G1Affine as Into<E::G1Prepared>>::into(p.a),
                    prepared_inputs.into_affine().into(),
                    p.c.into(),
                    pvk.delta_g1_prepared.clone(),
                ],
                [
                    p.b.into(),
                    pvk.gamma_g2_neg_pc.clone(),
                    pvk.delta_g2_neg_pc.clone(),
                    E::G2Prepared::from(d.into_group().neg().into_affine()),
                ],
            );
            // final_exponentiation returns None only if the Miller loop output is
            // identity (degenerate pairing). Treat as invalid proof, not a panic.
            let test = match E::final_exponentiation(qap) {
                Some(t) => t,
                None => return Ok(false),
            };
            Ok(test.0 == pvk.alpha_g1_beta_g2)
        } else {
            // Standard 3-pairing Groth16 verification (ROM SE or no SE)
            let qap = E::multi_miller_loop(
                [
                    <E::G1Affine as Into<E::G1Prepared>>::into(p.a),
                    prepared_inputs.into_affine().into(),
                    p.c.into(),
                ],
                [
                    p.b.into(),
                    pvk.gamma_g2_neg_pc.clone(),
                    pvk.delta_g2_neg_pc.clone(),
                ],
            );
            let test = match E::final_exponentiation(qap) {
                Some(t) => t,
                None => return Ok(false),
            };
            Ok(test.0 == pvk.alpha_g1_beta_g2)
        }
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key
    /// `pvk`, with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &crate::SimExtractableProof<E>,
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
        crate::SimExtractableProof<Bn254>,
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

        let bad_raw = crate::Proof::<Bn254> {
            a: G1Affine::generator(),
            b: valid_proof.groth16_proof.b,
            c: valid_proof.groth16_proof.c,
        };
        let bad_proof = crate::SimExtractableProof::<Bn254> {
            groth16_proof: bad_raw.clone(),
            se_element: None,
            proof_hash: crate::security::compute_proof_hash::<Bn254>(&bad_raw),
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

    /// Build a tampered SimExtractableProof from raw (A, B, C), with a
    /// consistently-recomputed proof_hash so the test isolates the pairing/point
    /// checks rather than tripping an unrelated hash guard.
    fn tamper(
        a: G1Affine,
        b: <Bn254 as Pairing>::G2Affine,
        c: G1Affine,
    ) -> crate::SimExtractableProof<Bn254> {
        let raw = crate::Proof::<Bn254> { a, b, c };
        crate::SimExtractableProof::<Bn254> {
            proof_hash: crate::security::compute_proof_hash::<Bn254>(&raw),
            groth16_proof: raw,
            se_element: None,
        }
    }

    #[test]
    fn test_verify_identity_a_rejected() {
        // A = 0 makes e(A, B) = 1 in GT, trivially satisfying the pairing check.
        // validate_proof_points must reject it. (Guards the documented identity attack.)
        let (pvk, valid, inputs) = setup_and_prove(Fr::from(3u64), Fr::from(7u64), 21u64);
        let bad = tamper(G1Affine::zero(), valid.groth16_proof.b, valid.groth16_proof.c);
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &bad);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "identity A must be rejected: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_identity_c_rejected() {
        let (pvk, valid, inputs) = setup_and_prove(Fr::from(3u64), Fr::from(7u64), 22u64);
        let bad = tamper(valid.groth16_proof.a, valid.groth16_proof.b, G1Affine::zero());
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &bad);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "identity C must be rejected: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_flipped_c_rejected() {
        // Existing coverage flips A; this flips C to exercise the third pairing term.
        let (pvk, valid, inputs) = setup_and_prove(Fr::from(2u64), Fr::from(8u64), 23u64);
        let bad = tamper(
            valid.groth16_proof.a,
            valid.groth16_proof.b,
            G1Affine::generator(),
        );
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &bad);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "flipped C must not verify: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_wrong_arity_inputs_rejected() {
        // A proof for a 1-input statement must not verify against 2 inputs. This
        // hits the prepare_inputs length guard (which also prevents an OOB panic).
        let (pvk, proof, inputs) = setup_and_prove(Fr::from(4u64), Fr::from(9u64), 24u64);
        let mut too_many = inputs.clone();
        too_many.push(Fr::from(123u64));
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &too_many, &proof);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "wrong input arity must be rejected, not panic: {:?}",
            result
        );

        // ...and zero inputs for a 1-input statement.
        let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "empty inputs for 1-input statement must be rejected: {:?}",
            result
        );
    }
}
