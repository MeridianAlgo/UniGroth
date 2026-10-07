//! Adversarial tests: each one plays the attacker and expects the verifier to hold.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use unigroth::{
    aggregate_proofs, batch::batch_verify_optimized, prepare_verifying_key, verify_aggregated,
    Groth16, Proof,
};

#[derive(Clone)]
struct Square(Option<Fr>);

impl ConstraintSynthesizer<Fr> for Square {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.0.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| {
            let v = self.0.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v * v)
        })?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + y)
    }
}

#[test]
fn degenerate_and_replayed_proofs_are_rejected() {
    let mut rng = StdRng::seed_from_u64(7);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Square(None), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&vk);
    let x = Fr::from(9u64);
    let proof = Groth16::<Bn254>::prove(&pk, Square(Some(x)), &mut rng).unwrap();
    let ok = [x * x];
    assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &ok).unwrap());

    // wrong statement, and statement + r (non-canonical aliasing is impossible: inputs are Fr)
    assert!(!Groth16::<Bn254>::verify_proof(&pvk, &proof, &[x * x + Fr::from(1u64)]).unwrap());
    assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &[]).is_err());

    // identity points in any slot
    for slot in 0..3 {
        let mut p = proof.clone();
        match slot {
            0 => p.a = G1Affine::zero(),
            1 => p.b = G2Affine::zero(),
            _ => p.c = G1Affine::zero(),
        }
        assert!(
            !Groth16::<Bn254>::verify_proof(&pvk, &p, &ok).unwrap_or(false),
            "slot {slot}"
        );
        let batch = batch_verify_optimized(&pvk, &[(p, ok.to_vec())], &mut rng);
        assert!(!batch.unwrap_or(false), "batch slot {slot}");
    }

    // a proof for one key must not verify under an unrelated key
    let (_, vk2) = Groth16::<Bn254>::circuit_specific_setup(Square(None), &mut rng).unwrap();
    assert!(!Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk2), &proof, &ok).unwrap());

    // random group elements never verify
    let mut junk = proof.clone();
    junk.a = G1Affine::rand(&mut rng);
    junk.b = G2Affine::rand(&mut rng);
    junk.c = G1Affine::rand(&mut rng);
    assert!(!Groth16::<Bn254>::verify_proof(&pvk, &junk, &ok).unwrap());
}

#[test]
fn batch_verifier_rejects_one_bad_proof_among_good() {
    let mut rng = StdRng::seed_from_u64(11);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Square(None), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&vk);
    let mut items: Vec<_> = (2..10u64)
        .map(|i| {
            let x = Fr::from(i);
            (
                Groth16::<Bn254>::prove(&pk, Square(Some(x)), &mut rng).unwrap(),
                vec![x * x],
            )
        })
        .collect();
    assert!(batch_verify_optimized(&pvk, &items, &mut rng).unwrap());
    items[3].1[0] += Fr::from(1u64);
    assert!(!batch_verify_optimized(&pvk, &items, &mut rng).unwrap());
}

fn setup_square(
    seed: u64,
) -> (
    StdRng,
    unigroth::ProvingKey<Bn254>,
    unigroth::PreparedVerifyingKey<Bn254>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Square(None), &mut rng).unwrap();
    (rng, pk, prepare_verifying_key(&vk))
}

/// A G2 point that is on the curve but outside the prime-order subgroup
/// (BN254 G2 has a large cofactor).
fn g2_off_subgroup(rng: &mut StdRng) -> G2Affine {
    loop {
        if let Some(p) = G2Affine::get_point_from_x_unchecked(Fq2::rand(rng), false) {
            if p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve() {
                return p;
            }
        }
    }
}

#[test]
fn off_curve_and_off_subgroup_points_are_rejected() {
    let (mut rng, pk, pvk) = setup_square(21);
    let x = Fr::from(4u64);
    let proof = Groth16::<Bn254>::prove(&pk, Square(Some(x)), &mut rng).unwrap();
    let ok = [x * x];
    assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &ok).unwrap());

    let bad_b = Proof {
        b: g2_off_subgroup(&mut rng),
        ..proof.clone()
    };
    let bad_a = Proof {
        a: G1Affine::new_unchecked(Fq::from(1u64), Fq::from(1u64)),
        ..proof.clone()
    };
    for bad in [bad_b, bad_a] {
        assert!(!Groth16::<Bn254>::verify_proof(&pvk, &bad, &ok).unwrap());
        let items = vec![(proof.clone(), ok.to_vec()), (bad.clone(), ok.to_vec())];
        assert!(!batch_verify_optimized(&pvk, &items, &mut rng).unwrap());
        assert!(!verify_aggregated(
            &pvk.vk,
            &[ok.to_vec()],
            &aggregate_proofs(&[bad])
        ));
    }
}

/// Attack on a batch verifier whose weights come only from the caller's RNG:
/// if the attacker can predict r₁, r₂ they shift C₁ by r₂·Δ and C₂ by −r₁·Δ,
/// which cancels in Σ rᵢ·Cᵢ while both proofs are individually invalid.
/// Binding the weights to the proofs (Fiat-Shamir) defeats this.
#[test]
fn batch_weights_cannot_be_predicted_from_a_weak_rng() {
    let (mut rng, pk, pvk) = setup_square(31);
    let xs = [Fr::from(3u64), Fr::from(5u64)];
    let mut items: Vec<_> = xs
        .iter()
        .map(|&x| {
            (
                Groth16::<Bn254>::prove(&pk, Square(Some(x)), &mut rng).unwrap(),
                vec![x * x],
            )
        })
        .collect();

    // The verifier's RNG is seeded with a value the attacker knows.
    let mut predicted = StdRng::seed_from_u64(99);
    let r1 = Fr::rand(&mut predicted);
    let r2 = Fr::rand(&mut predicted);
    let delta = (G1Affine::generator() * Fr::from(1234u64)).into_affine();
    let honest_sum = items[0].0.c * r1 + items[1].0.c * r2;
    items[0].0.c = (items[0].0.c + delta * r2).into_affine();
    items[1].0.c = (items[1].0.c - delta * r1).into_affine();
    // Under rng-only weights the shifts cancel exactly, so that batch would accept.
    assert_eq!(items[0].0.c * r1 + items[1].0.c * r2, honest_sum);

    for (p, x) in &items {
        assert!(!Groth16::<Bn254>::verify_proof(&pvk, p, x).unwrap());
    }
    let mut verifier_rng = StdRng::seed_from_u64(99);
    assert!(!batch_verify_optimized(&pvk, &items, &mut verifier_rng).unwrap());
}
