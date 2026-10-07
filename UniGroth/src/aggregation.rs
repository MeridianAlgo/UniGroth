//! # Proof Aggregation
#![allow(missing_docs)]
//!
//! Batches N Groth16 proofs for the same verifying key into one object that is
//! checked with a single multi-pairing and one final exponentiation.
//!
//! ## Verification identity
//!
//! Each proof satisfies (GT, additive notation):
//!   e(Aᵢ, Bᵢ) = e(α, β) + e(PIᵢ, γ) + e(Cᵢ, δ)
//!
//! The verifier derives r = H(vk, inputs, proofs) by Fiat-Shamir *after* all
//! proofs and statements are fixed, and checks the random linear combination
//!   Σᵢ e(rⁱ·Aᵢ, Bᵢ) = e(Σrⁱ·α, β) + e(Σrⁱ·PIᵢ, γ) + e(Σrⁱ·Cᵢ, δ)
//!
//! A batch containing any invalid proof passes with probability at most
//! N/|F| per hash query. Everything the check depends on (r, the public inputs,
//! the aggregated terms) is recomputed by the verifier; nothing is trusted from
//! the prover.
//!
//! ## Size
//!
//! The aggregate stores all N proofs, so it is O(N). A logarithmic-size
//! SnarkPack aggregate needs a committed inner-pairing-product argument, which
//! is not implemented here.

use crate::{Proof, VerifyingKey};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, vec::Vec};
use sha2::{Digest, Sha256};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// N Groth16 proofs for one verifying key, verified together by [`verify_aggregated`].
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregatedProof<E: Pairing> {
    /// The proofs, in the same order as the public-input vectors given to the verifier.
    pub proofs: Vec<Proof<E>>,
}

#[cfg(feature = "serde")]
impl<E: Pairing> ::serde::Serialize for AggregatedProof<E> {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use ::serde::ser::Error as _;
        let mut b = ark_std::vec::Vec::new();
        self.serialize_compressed(&mut b)
            .map_err(S::Error::custom)?;
        ::serde::Serialize::serialize(&b, s)
    }
}
#[cfg(feature = "serde")]
impl<'de, E: Pairing> ::serde::Deserialize<'de> for AggregatedProof<E> {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use ::serde::de::Error as _;
        let b: ark_std::vec::Vec<u8> = ::serde::Deserialize::deserialize(d)?;
        Self::deserialize_compressed(&b[..]).map_err(D::Error::custom)
    }
}

/// Bundle Groth16 proofs for batch verification with [`verify_aggregated`].
pub fn aggregate_proofs<E: Pairing>(proofs: &[Proof<E>]) -> AggregatedProof<E> {
    AggregatedProof {
        proofs: proofs.to_vec(),
    }
}

/// Fiat-Shamir challenge binding the verifying key, every statement, every
/// proof and any caller-supplied `entropy`.
fn batch_challenge<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_inputs: &[Vec<E::ScalarField>],
    proofs: &[Proof<E>],
    entropy: &[u8],
) -> E::ScalarField {
    let mut buf = Vec::new();
    (vk, public_inputs, proofs)
        .serialize_compressed(&mut buf)
        .expect("serializing to a Vec cannot fail");
    let digest = Sha256::new()
        .chain_update(crate::config::DOMAIN_AGGREGATE)
        .chain_update(&buf)
        .chain_update(entropy)
        .finalize();
    E::ScalarField::from_le_bytes_mod_order(&digest)
}

/// Verify an [`AggregatedProof`] against `vk` and the public inputs of every proof.
///
/// Returns `true` iff every proof in the batch is a valid Groth16 proof for its
/// statement (up to the negligible batching error described in the module docs).
pub fn verify_aggregated<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_inputs: &[Vec<E::ScalarField>],
    agg: &AggregatedProof<E>,
) -> bool {
    verify_batch(vk, public_inputs, &agg.proofs, &[])
}

/// Batch-verify Groth16 proofs for one verifying key with a single multi-pairing.
///
/// The challenge is derived from the whole batch plus `entropy`, so a weak or
/// predictable `entropy` source cannot help a cheater: the proofs are fixed
/// before the challenge exists. Cost: k+3 Miller loops, one final
/// exponentiation, and one MSM of size ℓ+1 for all public inputs combined.
pub fn verify_batch<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_inputs: &[Vec<E::ScalarField>],
    proofs: &[Proof<E>],
    entropy: &[u8],
) -> bool {
    let n = proofs.len();
    if n == 0 || public_inputs.len() != n {
        return false;
    }
    if public_inputs
        .iter()
        .any(|x| x.len() + 1 != vk.gamma_abc_g1.len())
    {
        return false;
    }
    if !cfg_iter!(proofs).all(crate::proof_points_valid) {
        return false;
    }

    let r = batch_challenge(vk, public_inputs, proofs, entropy);
    if r.is_zero() {
        return false;
    }

    let mut powers = Vec::with_capacity(n);
    let mut acc = E::ScalarField::one();
    for _ in 0..n {
        powers.push(acc);
        acc *= r;
    }
    let pow_sum: E::ScalarField = powers.iter().sum();

    // Σᵢ rⁱ·PIᵢ = pow_sum·γ₀ + Σⱼ (Σᵢ rⁱ·xᵢⱼ)·γⱼ₊₁
    let mut pi_scalars = vec![E::ScalarField::zero(); vk.gamma_abc_g1.len()];
    pi_scalars[0] = pow_sum;
    for (inputs, ri) in public_inputs.iter().zip(&powers) {
        for (s, x) in pi_scalars[1..].iter_mut().zip(inputs) {
            *s += *ri * x;
        }
    }
    let Ok(pi_agg) = E::G1::msm(&vk.gamma_abc_g1, &pi_scalars) else {
        return false;
    };

    let c_bases: Vec<E::G1Affine> = proofs.iter().map(|p| p.c).collect();
    let Ok(c_agg) = E::G1::msm(&c_bases, &powers) else {
        return false;
    };

    // Σᵢ e(rⁱAᵢ, Bᵢ) − e(pow_sum·α, β) − e(PI_agg, γ) − e(C_agg, δ) == 0
    let mut g1: Vec<E::G1> = cfg_iter!(proofs)
        .zip(&powers)
        .map(|(p, ri)| p.a * ri)
        .collect();
    g1.push(-(vk.alpha_g1 * pow_sum));
    g1.push(-pi_agg);
    g1.push(-c_agg);
    let g1 = E::G1::normalize_batch(&g1);

    let mut g2: Vec<E::G2Affine> = proofs.iter().map(|p| p.b).collect();
    g2.push(vk.beta_g2);
    g2.push(vk.gamma_g2);
    g2.push(vk.delta_g2);

    E::multi_pairing(g1, g2).is_zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    // Simple circuit: prove knowledge of x such that x * x = y (public)
    struct SquareCircuit {
        x: Fr, // witness
        y: Fr, // public input
    }

    impl ConstraintSynthesizer<Fr> for SquareCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x_var = cs.new_witness_variable(|| Ok(self.x))?;
            let y_var = cs.new_input_variable(|| Ok(self.y))?;
            cs.enforce_r1cs_constraint(
                || ark_relations::lc!() + x_var,
                || ark_relations::lc!() + x_var,
                || ark_relations::lc!() + y_var,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_aggregate_single_proof() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let x = Fr::from(5u64);
        let y = x * x;

        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(SquareCircuit { x, y }, &mut rng).unwrap();

        let se_proof = Groth16::<Bn254>::prove(&pk, SquareCircuit { x, y }, &mut rng).unwrap();

        let agg = aggregate_proofs::<Bn254>(&[se_proof]);
        assert_eq!(agg.proofs.len(), 1);
        assert!(
            verify_aggregated(&vk, &[vec![y]], &agg),
            "single-proof aggregation must verify"
        );
    }

    #[test]
    fn test_aggregate_multiple_proofs() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let pairs: Vec<(Fr, Fr)> = (1u64..=4)
            .map(|i| {
                let x = Fr::from(i);
                (x, x * x)
            })
            .collect();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            SquareCircuit {
                x: pairs[0].0,
                y: pairs[0].1,
            },
            &mut rng,
        )
        .unwrap();

        let mut proofs = Vec::new();
        let mut inputs = Vec::new();
        for (x, y) in &pairs {
            let se_proof =
                Groth16::<Bn254>::prove(&pk, SquareCircuit { x: *x, y: *y }, &mut rng).unwrap();
            proofs.push(se_proof);
            inputs.push(vec![*y]);
        }

        let agg = aggregate_proofs::<Bn254>(&proofs);
        assert_eq!(agg.proofs.len(), 4);
        assert!(
            verify_aggregated(&vk, &inputs, &agg),
            "4-proof aggregation must verify"
        );

        // A wrong statement for any one proof must fail the whole batch.
        let mut bad_inputs = inputs.clone();
        bad_inputs[2] = vec![Fr::from(1234u64)];
        assert!(!verify_aggregated(&vk, &bad_inputs, &agg));
    }

    #[test]
    fn test_forged_aggregate_rejected() {
        // The previous format trusted prover-supplied sums, so an all-identity
        // aggregate verified for any statement. It must be rejected now.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let x = Fr::from(5u64);
        let (_pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(SquareCircuit { x, y: x * x }, &mut rng)
                .unwrap();
        let forged = AggregatedProof::<Bn254> {
            proofs: vec![Proof::default()],
        };
        assert!(!verify_aggregated(&vk, &[vec![Fr::from(7u64)]], &forged));
        assert!(!verify_aggregated(
            &vk,
            &[],
            &aggregate_proofs::<Bn254>(&[])
        ));
    }
}
