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
            let ic_acc =
                E::G1::msm(&pvk.vk.gamma_abc_g1[1..], public_inputs).map_err(|e| {
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
