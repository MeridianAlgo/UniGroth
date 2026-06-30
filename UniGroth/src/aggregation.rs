//! # Proof Aggregation
#![allow(missing_docs)]
//!
//! Simplified SnarkPack-style aggregation for N Groth16 proofs into a single
//! aggregate proof. Based on Bunz et al. inner-product argument approach used
//! in production by PLONKY2, Polygon, and SnarkPack.
//!
//! ## Approach
//!
//! Given N valid Groth16 proofs (Aᵢ, Bᵢ, Cᵢ) with a random challenge r:
//!
//!   scaled_a_vec = [r⁰·A₀, r¹·A₁, ...]  (G₁, for multi-pairing LHS)
//!   C_agg        = Σᵢ rⁱ · Cᵢ            (G₁ MSM)
//!   b_vec        = [B₀, B₁, ...]          (G₂, individual, for multi-pairing LHS)
//!   inputs_agg   = Σᵢ rⁱ · inputsᵢ       (scalar, for prepared_inputs partial sum)
//!   pow_sum      = Σᵢ rⁱ                  (scalar, for γ_abc[0] scaling and α·β term)
//!
//! ## Verification identity
//!
//! Each individual Groth16 proof satisfies (in GT, additive notation):
//!   e(Aᵢ, Bᵢ) = e(α, β) + e(PIᵢ, γ) + e(Cᵢ, δ)
//!
//! where PIᵢ = γ_abc[0] + Σⱼ inputsᵢ[j] · γ_abc[j+1].
//!
//! Multiplying by rⁱ (scaling in GT) and summing:
//!   Σᵢ e(rⁱ·Aᵢ, Bᵢ) = pow_sum·e(α,β) + e(PI_agg, γ) + e(C_agg, δ)
//!
//! where PI_agg = pow_sum·γ_abc[0] + Σⱼ inputs_agg[j]·γ_abc[j+1].
//!
//! This reduces N independent Groth16 checks to a single multi-pairing equation.
//!
//! ## Status
//!
//! Research prototype. Full SnarkPack security requires a committed vector
//! argument for B_vec (see SnarkPack, EuroCrypt 2022). This implementation
//! stores the B and scaled-A vectors explicitly to demonstrate correctness.
//!
//! References:
//! - [SnarkPack] Gabizon & Williamson, "SnarkPack: Practical SNARK Aggregation", EuroCrypt 2022
//! - [Bunz et al.] "Proofs for Inner Pairing Products and Applications", ASIACRYPT 2021

use crate::{Proof, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, vec::Vec, One, Zero};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// An aggregated proof for N individual Groth16 proofs.
///
/// Stores the data needed to evaluate the multi-pairing batch identity:
///   Σᵢ e(rⁱ·Aᵢ, Bᵢ) = pow_sum·e(α, β) + e(PI_agg, γ) + e(C_agg, δ)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregatedProof<E: Pairing> {
    /// Scaled G₁ elements: scaled_a_vec[i] = rⁱ · Aᵢ  (for multi-pairing LHS)
    pub scaled_a_vec: Vec<E::G1Affine>,
    /// Individual G₂ proof elements: b_vec[i] = Bᵢ  (for multi-pairing LHS)
    pub b_vec: Vec<E::G2Affine>,
    /// Weighted G₁ sum C_agg = Σᵢ rⁱ · Cᵢ  (for RHS δ-pairing)
    pub c_agg: E::G1Affine,
    /// Partial aggregated public inputs: inputs_agg[j] = Σᵢ rⁱ · inputs[i][j]
    /// (Note: PI_agg = pow_sum·γ_abc[0] + Σⱼ inputs_agg[j]·γ_abc[j+1])
    pub inputs_agg: Vec<E::ScalarField>,
    /// Sum of challenge powers: pow_sum = Σᵢ rⁱ  (scales γ_abc[0] and the α·β term)
    pub pow_sum: E::ScalarField,
    /// Number of proofs aggregated.
    pub n: usize,
    /// The random challenge used for aggregation (r).
    pub challenge: E::ScalarField,
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

/// Aggregate N Groth16 proofs into a single `AggregatedProof`.
///
/// Samples a random challenge `r` and computes:
/// - `scaled_a_vec[i] = rⁱ · Aᵢ` (for multi-pairing LHS)
/// - `C_agg = Σᵢ rⁱ·Cᵢ` via MSM
/// - `inputs_agg[j] = Σᵢ rⁱ · inputs[i][j]`
/// - `pow_sum = Σᵢ rⁱ`
///
/// The result can be verified with `verify_aggregated`.
///
/// # Panics
/// Panics if `proofs` is empty or `proofs.len() != public_inputs.len()`.
pub fn aggregate_proofs<E: Pairing, R: Rng>(
    proofs: &[Proof<E>],
    public_inputs: &[Vec<E::ScalarField>],
    rng: &mut R,
) -> AggregatedProof<E> {
    assert!(!proofs.is_empty(), "Cannot aggregate zero proofs");
    assert_eq!(
        proofs.len(),
        public_inputs.len(),
        "proofs and public_inputs must have the same length"
    );
    let n = proofs.len();

    // Sample random challenge r ∈ F*
    let mut r = E::ScalarField::zero();
    while r.is_zero() {
        r = E::ScalarField::rand(rng);
    }

    // Compute powers r⁰, r¹, ..., r^(n-1) and their sum
    let mut powers: Vec<E::ScalarField> = Vec::with_capacity(n);
    let mut acc = E::ScalarField::one();
    let mut pow_sum = E::ScalarField::zero();
    for _ in 0..n {
        powers.push(acc);
        pow_sum += acc;
        acc *= r;
    }

    // scaled_a_vec[i] = rⁱ · Aᵢ  (G₁ scalar multiplications, batch-normalized)
    // Parallel: each scalar multiplication is independent.
    #[cfg(feature = "parallel")]
    let scaled_a_proj: Vec<E::G1> = proofs
        .par_iter()
        .zip(powers.par_iter())
        .map(|(p, ri)| p.a.into_group() * ri)
        .collect();
    #[cfg(not(feature = "parallel"))]
    let scaled_a_proj: Vec<E::G1> = proofs
        .iter()
        .zip(powers.iter())
        .map(|(p, ri)| p.a.into_group() * ri)
        .collect();
    let scaled_a_vec = E::G1::normalize_batch(&scaled_a_proj);

    // b_vec: individual B (G₂) elements, kept for multi-pairing
    let b_vec: Vec<E::G2Affine> = proofs.iter().map(|p| p.b).collect();

    // C_agg = Σᵢ rⁱ · Cᵢ  via MSM
    let c_bases: Vec<E::G1Affine> = proofs.iter().map(|p| p.c).collect();
    let c_agg = E::G1::msm(&c_bases, &powers)
        .expect("G1 MSM failed")
        .into_affine();

    // inputs_agg[j] = Σᵢ rⁱ · inputs[i][j]  (partial sum, γ_abc[0] handled in verify)
    let num_inputs = public_inputs[0].len();
    for inputs_i in public_inputs.iter() {
        assert_eq!(
            inputs_i.len(),
            num_inputs,
            "All public input vectors must have the same length"
        );
    }
    // Parallel over output index j: each column is an independent dot product.
    #[cfg(feature = "parallel")]
    let inputs_agg: Vec<E::ScalarField> = (0..num_inputs)
        .into_par_iter()
        .map(|j| {
            public_inputs
                .iter()
                .zip(powers.iter())
                .map(|(inputs_i, &ri)| ri * inputs_i[j])
                .fold(E::ScalarField::zero(), |acc, x| acc + x)
        })
        .collect();
    #[cfg(not(feature = "parallel"))]
    let inputs_agg: Vec<E::ScalarField> = {
        let mut agg = vec![E::ScalarField::zero(); num_inputs];
        for (i, inputs_i) in public_inputs.iter().enumerate() {
            for (j, &inp) in inputs_i.iter().enumerate() {
                agg[j] += powers[i] * inp;
            }
        }
        agg
    };

    AggregatedProof {
        scaled_a_vec,
        b_vec,
        c_agg,
        inputs_agg,
        pow_sum,
        n,
        challenge: r,
    }
}

/// Verify an `AggregatedProof` against a verifying key.
///
/// Checks the multi-pairing identity:
///   Σᵢ e(rⁱ·Aᵢ, Bᵢ)  ==  pow_sum·e(α, β) + e(PI_agg, γ) + e(C_agg, δ)
///
/// where PI_agg = pow_sum·γ_abc[0] + Σⱼ inputs_agg[j]·γ_abc[j+1].
///
/// Returns `true` iff the aggregated proof is valid.
pub fn verify_aggregated<E: Pairing>(vk: &VerifyingKey<E>, agg: &AggregatedProof<E>) -> bool {
    use ark_ec::pairing::PairingOutput;

    if agg.inputs_agg.len() + 1 != vk.gamma_abc_g1.len() {
        return false;
    }
    if agg.scaled_a_vec.len() != agg.n || agg.b_vec.len() != agg.n {
        return false;
    }

    // --- RHS ---

    // pow_sum·e(α, β) = e(pow_sum·α, β)  via bilinearity
    let alpha_scaled = (vk.alpha_g1.into_group() * agg.pow_sum).into_affine();

    // PI_agg = pow_sum · γ_abc[0] + Σⱼ inputs_agg[j] · γ_abc[j+1]
    //
    // This is derived from: Σᵢ rⁱ · PI_i
    //   = Σᵢ rⁱ · (γ_abc[0] + Σⱼ inputs[i][j] · γ_abc[j+1])
    //   = (Σᵢ rⁱ)·γ_abc[0] + Σⱼ (Σᵢ rⁱ·inputs[i][j])·γ_abc[j+1]
    //   = pow_sum·γ_abc[0] + Σⱼ inputs_agg[j]·γ_abc[j+1]
    let gamma_abc_0_scaled = (vk.gamma_abc_g1[0].into_group() * agg.pow_sum).into_affine();
    let scalars: Vec<E::ScalarField> = agg.inputs_agg.clone();
    let bases: Vec<E::G1Affine> = vk.gamma_abc_g1[1..].to_vec();
    let inputs_sum_proj = match E::G1::msm(&bases, &scalars) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pi_agg = (gamma_abc_0_scaled.into_group() + inputs_sum_proj).into_affine();

    let rhs = E::pairing(alpha_scaled, vk.beta_g2)
        + E::pairing(pi_agg, vk.gamma_g2)
        + E::pairing(agg.c_agg, vk.delta_g2);

    // --- LHS: Σᵢ e(rⁱ·Aᵢ, Bᵢ) ---
    // Parallel: each individual pairing is independent.
    #[cfg(feature = "parallel")]
    let lhs = agg
        .scaled_a_vec
        .par_iter()
        .zip(agg.b_vec.par_iter())
        .map(|(&sa, &b)| E::pairing(sa, b))
        .reduce(PairingOutput::zero, |a, b| a + b);
    #[cfg(not(feature = "parallel"))]
    let lhs = agg
        .scaled_a_vec
        .iter()
        .zip(agg.b_vec.iter())
        .map(|(&sa, &b)| E::pairing(sa, b))
        .fold(PairingOutput::zero(), |acc, x| acc + x);

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_ff::Zero;
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
        let raw_proof = se_proof.groth16_proof;

        let agg = aggregate_proofs::<Bn254, _>(&[raw_proof], &[vec![y]], &mut rng);
        assert_eq!(agg.n, 1);
        assert!(
            verify_aggregated(&vk, &agg),
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
            proofs.push(se_proof.groth16_proof);
            inputs.push(vec![*y]);
        }

        let agg = aggregate_proofs::<Bn254, _>(&proofs, &inputs, &mut rng);
        assert_eq!(agg.n, 4);
        assert!(
            verify_aggregated(&vk, &agg),
            "4-proof aggregation must verify"
        );
    }

    #[test]
    fn test_aggregated_proof_fields() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let x = Fr::from(3u64);
        let y = x * x;

        let (pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(SquareCircuit { x, y }, &mut rng).unwrap();

        let se_proof = Groth16::<Bn254>::prove(&pk, SquareCircuit { x, y }, &mut rng).unwrap();

        let agg = aggregate_proofs::<Bn254, _>(&[se_proof.groth16_proof], &[vec![y]], &mut rng);

        assert!(!agg.challenge.is_zero());
        assert_eq!(agg.inputs_agg.len(), 1);
    }
}
