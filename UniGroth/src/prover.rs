//! Groth16 prover implementation.
//! Imports
use crate::{r1cs_to_qap::R1CSToQAP, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult,
        SynthesisMode,
    },
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    ops::{AddAssign, Mul},
    rand::Rng,
    vec::Vec,
};
use sha2::{Digest, Sha256};


impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction, using the provided
    /// R1CS constraint matrices.
    #[inline]
    pub fn create_proof_with_reduction_and_matrices(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        // In Groth16, we compute several MSMs over the proving key queries.
        // We use rayon::join to parallelize these independent MSMs.
        
        #[cfg(feature = "parallel")]
        let ((h_acc, l_aux_acc), (g_a, g1_b, g2_b)) = rayon::join(
            || rayon::join(
                || E::G1::msm(&pk.h_query, h).unwrap(),
                || E::G1::msm(&pk.l_query, aux_assignment).unwrap(),
            ),
            || {
                let r_g1 = pk.delta_g1.mul(r);
                let s_g1 = pk.delta_g1.mul(s);
                let s_g2 = pk.vk.delta_g2.mul(s);
                
                let ((g_a, g1_b), g2_b) = rayon::join(
                    || rayon::join(
                        || Self::calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, input_assignment, aux_assignment),
                        || {
                            if !r.is_zero() {
                                Self::calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, input_assignment, aux_assignment)
                            } else {
                                E::G1::zero()
                            }
                        }
                    ),
                    || Self::calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, input_assignment, aux_assignment)
                );
                (g_a, g1_b, g2_b)
            }
        );

        #[cfg(not(feature = "parallel"))]
        let (h_acc, l_aux_acc, g_a, g1_b, g2_b) = {
            let r_g1 = pk.delta_g1.mul(r);
            let s_g1 = pk.delta_g1.mul(s);
            let s_g2 = pk.vk.delta_g2.mul(s);
            
            (
                E::G1::msm(&pk.h_query, h).unwrap(),
                E::G1::msm(&pk.l_query, aux_assignment).unwrap(),
                Self::calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, input_assignment, aux_assignment),
                if !r.is_zero() {
                    Self::calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, input_assignment, aux_assignment)
                } else {
                    E::G1::zero()
                },
                Self::calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, input_assignment, aux_assignment)
            )
        };

        let r_s_delta_g1 = pk.delta_g1 * (r * s);
        let s_g_a = g_a * &s;

        let r_g1_b = g1_b * &r;

        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;

        // Batch-convert both G1 projective points (Montgomery's batch inversion trick)
        // Reduces 2 independent field inversions to 1 batch inversion (~3N field mults total)
        let g1_affines = E::G1::normalize_batch(&[g_a, g_c]);
        Ok(Proof {
            a: g1_affines[0],
            b: g2_b.into_affine(),
            c: g1_affines[1],
        })
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    /// Randomness `r` and `s` are derived via circuit binding: they incorporate
    /// a SHA-256 fingerprint of `pk.vk.gamma_abc_g1`, binding proving randomness
    /// to this specific circuit. This prevents proof replay across circuits with
    /// colliding verifying keys (circuit binding / domain separation).
    #[inline]
    pub fn create_random_proof_with_reduction<C: ConstraintSynthesizer<E::ScalarField>, R: Rng>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut R,
    ) -> R1CSResult<Proof<E>> {
        // Domain-separate randomness by circuit VK fingerprint.
        // Prevents proof replay across circuits with colliding VKs.
        let r = Self::circuit_bound_rand(&pk.vk, rng);
        let s = Self::circuit_bound_rand(&pk.vk, rng);

        Self::create_proof_with_reduction(circuit, pk, r, s)
    }

    /// Derive proving randomness bound to a specific circuit's verifying key.
    /// Computes `H(SHA-256(vk.gamma_abc_g1) || fresh_random)` and maps it to
    /// a scalar field element. This ensures that even if two circuits share the
    /// same toxic waste values, their proving randomness is circuit-specific.
    fn circuit_bound_rand<R: Rng>(vk: &VerifyingKey<E>, rng: &mut R) -> E::ScalarField {
        // Step 1: circuit fingerprint = SHA-256 of gamma_abc_g1 elements
        let mut hasher = Sha256::new();
        hasher.update(b"unigroth-circuit-bound-rand-v1");
        let mut buf = Vec::new();
        for g in &vk.gamma_abc_g1 {
            buf.clear();
            g.serialize_compressed(&mut buf).unwrap();
            hasher.update(&buf);
        }
        let circuit_tag = hasher.finalize();

        // Step 2: H(circuit_tag || fresh_random) → field element
        let fresh = E::ScalarField::rand(rng);
        buf.clear();
        fresh.serialize_uncompressed(&mut buf).unwrap();

        let mut hasher2 = Sha256::new();
        hasher2.update(&circuit_tag);
        hasher2.update(&buf);
        let combined = hasher2.finalize();

        E::ScalarField::from_le_bytes_mod_order(&combined)
    }

    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> R1CSResult<Proof<E>> {
        let prover = ConstraintSystem::new_ref();
        prover.set_optimization_goal(OptimizationGoal::Constraints);
        prover.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: true,
        });
        circuit.generate_constraints(prover.clone())?;

        prover.finalize();

        let h = QAP::witness_map::<E::ScalarField, GeneralEvaluationDomain<E::ScalarField>>(prover.clone())?;
        
        let cs = prover.borrow().unwrap();
        let input_assignment = cs.instance_assignment().unwrap();
        let aux_assignment = cs.witness_assignment().unwrap();

        Self::create_proof_with_reduction_and_matrices(
            pk,
            r,
            s,
            &h,
            &input_assignment,
            &aux_assignment,
        )
    }

    /// rerandomize_proof refreshes the components of a proof based on a given
    /// verifying key and an existing valid proof. This method can also be used as
    /// a way to transform a malleable Groth16 proof into one that is S-ZK.
    /// Implementation is based on [\[BKSV20\]](https://eprint.iacr.org/2020/811)
    /// which builds on [\[BGM17\]](https://eprint.iacr.org/2017/632)
    ///
    /// # Rerandomization Scheme
    /// Let S = (A, B, C) be a valid Groth16 proof.
    /// Sample nonzero r₁, r₂ ∈ F uniformly at random.
    /// Return the proof S' = (A', B', C') such that:
    ///   A' = r₁⁻¹A
    ///   B' = r₁B + r₁r₂δ
    ///   C' = C + r₂A
    ///
    /// By taking S' = (A', B', C'), where S' is a proof for the same instance as S,
    /// we can show that S' is S-ZK, as its components are identically distributed
    /// as those of an honest proof produced with fresh randomness. More specifically,
    /// for any instance x and proof S = pk(x), the distribution of S' is independent
    /// from a fresh honest proof of S. For more info, see theorem 3 of [\[BKSV20\]](https://eprint.iacr.org/2020/811)
    pub fn rerandomize_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        rng: &mut impl Rng,
    ) -> Proof<E> {
        // These are our rerandomization factors. They must be nonzero and uniformly
        // sampled.
        let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
        while r1.is_zero() || r2.is_zero() {
            r1 = E::ScalarField::rand(rng);
            r2 = E::ScalarField::rand(rng);
        }

        // See figure 1 in the paper referenced above:
        //   A' = (1/r₁)A
        //   B' = r₁B + r₁r₂(δG₂)
        //   C' = C + r₂A

        // We can unwrap() this because r₁ is guaranteed to be nonzero
        let new_a = proof.a.mul(r1.inverse().unwrap());
        let new_b = proof.b.mul(r1) + &vk.delta_g2.mul(r1 * &r2);
        let new_c = proof.c.into_group() + proof.a.mul(r2);

        Proof {
            a: new_a.into_affine(),
            b: new_b.into_affine(),
            c: new_c.into_affine(),
        }
    }

    fn calculate_coeff<G: AffineRepr>(
        initial: G::Group,
        query: &[G],
        vk_param: G,
        input_assignment: &[G::ScalarField],
        aux_assignment: &[G::ScalarField],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let el = query[0];
        
        // Combined MSMs without concat: 
        // query[0] matches input_assignment[0] (constant 1)
        // query[1..input_assignment.len()] matches input_assignment[1..]
        // query[input_assignment.len()..] matches aux_assignment
        let acc = G::Group::msm(&query[1..input_assignment.len()], &input_assignment[1..]).unwrap()
                + G::Group::msm(&query[input_assignment.len()..], aux_assignment).unwrap();

        let mut res = initial;
        res.add_assign(&el);
        res += &acc;
        res.add_assign(&vk_param);

        res
    }
}
