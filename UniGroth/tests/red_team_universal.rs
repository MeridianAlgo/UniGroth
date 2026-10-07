//! Adversarial tests for the universal setup: accuracy against the trusted
//! generator, Phase 1 / Phase 2 tampering, cross-circuit forgery, and KZG SRS
//! validation. Each test plays the attacker and expects the checks to hold.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
    lc,
};
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use unigroth::{
    kzg::UniversalSRS,
    prepare_verifying_key,
    universal_setup::{
        circuit_digest, contribute_delta, contribute_delta_from_beacon, verify_delta_beacon,
        verify_delta_chain, DlogProof,
    },
    Groth16, Proof, ProvingKey, UniversalParams,
};

// ─── Circuits ────────────────────────────────────────────────────────────────

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

/// x³ + x + 5 = y
#[derive(Clone)]
struct Cubic(Option<Fr>);
impl ConstraintSynthesizer<Fr> for Cubic {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let xv = self.0;
        let x = cs.new_witness_variable(|| xv.ok_or(SynthesisError::AssignmentMissing))?;
        let x2 =
            cs.new_witness_variable(|| xv.map(|v| v * v).ok_or(SynthesisError::AssignmentMissing))?;
        let x3 = cs.new_witness_variable(|| {
            xv.map(|v| v * v * v)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = cs.new_input_variable(|| {
            xv.map(|v| v * v * v + v + Fr::from(5u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x2)?;
        cs.enforce_r1cs_constraint(|| lc!() + x2, || lc!() + x, || lc!() + x3)?;
        cs.enforce_r1cs_constraint(
            || lc!() + x3 + x + (Fr::from(5u64), Variable::One),
            || lc!() + Variable::One,
            || lc!() + y,
        )
    }
}

/// Random R1CS: `inputs` public inputs, `steps` constraints, each multiplying
/// two random linear combinations (with constants) of earlier variables.
#[derive(Clone)]
struct RandomCircuit {
    seed: u64,
    inputs: usize,
    steps: usize,
    witness: bool,
}

impl RandomCircuit {
    /// Public input values the circuit uses (they are a function of the seed).
    fn public_values(&self) -> Vec<Fr> {
        let mut rng = StdRng::seed_from_u64(self.seed);
        (0..self.inputs).map(|_| Fr::rand(&mut rng)).collect()
    }
}

impl ConstraintSynthesizer<Fr> for RandomCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut rng = StdRng::seed_from_u64(self.seed);
        let inputs: Vec<Fr> = (0..self.inputs).map(|_| Fr::rand(&mut rng)).collect();
        let mut vars: Vec<(Variable, Fr)> = Vec::new();
        for v in &inputs {
            let val = *v;
            vars.push((cs.new_input_variable(|| Ok(val))?, val));
        }
        let w0 = Fr::rand(&mut rng);
        let ok = self.witness;
        vars.push((
            cs.new_witness_variable(|| {
                if ok {
                    Ok(w0)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            })?,
            w0,
        ));

        for _ in 0..self.steps {
            let pick = |rng: &mut StdRng| -> (LinearCombination<Fr>, Fr) {
                let mut lc = lc!();
                let mut val = Fr::zero();
                for _ in 0..rng.gen_range(1..4) {
                    let (v, x) = vars[rng.gen_range(0..vars.len())];
                    let c = Fr::from(rng.gen_range(1u64..1000));
                    lc += (c, v);
                    val += c * x;
                }
                let k = Fr::from(rng.gen_range(0u64..3));
                (lc + (k, Variable::One), val + k)
            };
            let (a, av) = pick(&mut rng);
            let (b, bv) = pick(&mut rng);
            let out = av * bv;
            let o = cs.new_witness_variable(|| {
                if ok {
                    Ok(out)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            })?;
            cs.enforce_r1cs_constraint(|| a, || b, || lc!() + o)?;
            vars.push((o, out));
        }
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Phase 1 parameters for known secrets (test-only: real setups never see them).
fn params_from_secrets(n: usize, tau: Fr, alpha: Fr, beta: Fr) -> UniversalParams<Bn254> {
    let g = G1Projective::generator();
    let h = G2Projective::generator();
    let pw = |i: usize| tau.pow([i as u64]);
    UniversalParams {
        tau_g1: G1Projective::normalize_batch(
            &(0..2 * n - 1).map(|i| g * pw(i)).collect::<Vec<_>>(),
        ),
        tau_g2: G2Projective::normalize_batch(&(0..n).map(|i| h * pw(i)).collect::<Vec<_>>()),
        alpha_tau_g1: G1Projective::normalize_batch(
            &(0..n).map(|i| g * (alpha * pw(i))).collect::<Vec<_>>(),
        ),
        beta_tau_g1: G1Projective::normalize_batch(
            &(0..n).map(|i| g * (beta * pw(i))).collect::<Vec<_>>(),
        ),
        beta_g2: (h * beta).into_affine(),
    }
}

fn verifies<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bn254>,
    c: C,
    inputs: &[Fr],
    rng: &mut StdRng,
) -> bool {
    let proof = Groth16::<Bn254>::prove(pk, c, rng).unwrap();
    Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &proof, inputs).unwrap()
}

/// With known δ (here δ = 1 before any contribution) and γ = 1, anyone can
/// forge: A = αG, B = βH + sH, C = (s·αG − IC)/δ.
fn forge_with_known_delta(pk: &ProvingKey<Bn254>, inputs: &[Fr], delta: Fr) -> Proof<Bn254> {
    let vk = &pk.vk;
    let mut ic = vk.gamma_abc_g1[0].into_group();
    for (x, b) in inputs.iter().zip(&vk.gamma_abc_g1[1..]) {
        ic += *b * x;
    }
    let s = Fr::from(424242u64);
    let a = vk.alpha_g1;
    let b = (vk.beta_g2.into_group() + G2Projective::generator() * s).into_affine();
    let c = ((vk.alpha_g1 * s - ic) * delta.inverse().unwrap()).into_affine();
    Proof { a, b, c }
}

// ─── Accuracy ────────────────────────────────────────────────────────────────

/// Keys derived from public Phase 1 data must be *identical* to keys from the
/// trusted generator run with the same τ, α, β and γ = δ = 1.
#[test]
fn derived_keys_match_trusted_generator_exactly() {
    for (seed, circuit_inputs, steps) in [(1u64, 1usize, 5usize), (2, 3, 13), (3, 0, 30), (4, 6, 1)]
    {
        let mut rng = StdRng::seed_from_u64(seed);
        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);
        let gen_seed = rng.gen::<u64>();
        // generate_parameters_with_qap draws t first, via one Fr::rand.
        let tau = Fr::rand(&mut StdRng::seed_from_u64(gen_seed));

        let circuit = RandomCircuit {
            seed,
            inputs: circuit_inputs,
            steps,
            witness: false,
        };
        let params = params_from_secrets(64, tau, alpha, beta);
        assert!(params.is_well_formed());
        let derived = params.derive_unblinded_keys(circuit.clone()).unwrap();
        let trusted = Groth16::<Bn254>::generate_parameters_with_qap(
            circuit,
            alpha,
            beta,
            Fr::one(),
            Fr::one(),
            G1Projective::generator(),
            G2Projective::generator(),
            &mut StdRng::seed_from_u64(gen_seed),
        )
        .unwrap();
        assert_eq!(
            derived, trusted,
            "seed {seed}: derived keys differ from trusted generator"
        );
    }
}

#[test]
fn random_circuits_prove_and_reject_wrong_inputs() {
    let mut rng = StdRng::seed_from_u64(10);
    let params = UniversalParams::<Bn254>::setup(128, &mut rng);
    for seed in 0..6u64 {
        let c = RandomCircuit {
            seed,
            inputs: (seed % 4) as usize,
            steps: 5 + 9 * seed as usize,
            witness: true,
        };
        let (pk, _) = params
            .derive_keys(
                RandomCircuit {
                    witness: false,
                    ..c.clone()
                },
                &mut rng,
            )
            .unwrap();
        let x = c.public_values();
        assert!(verifies(&pk, c.clone(), &x, &mut rng), "seed {seed}");
        if !x.is_empty() {
            let mut bad = x.clone();
            bad[0] += Fr::one();
            assert!(
                !verifies(&pk, c, &bad, &mut rng),
                "seed {seed} accepted wrong input"
            );
        }
    }
}

#[test]
fn domain_boundary_is_exact() {
    let mut rng = StdRng::seed_from_u64(11);
    // 3 constraints + 2 instance variables = 5 → domain 8.
    let params8 = UniversalParams::<Bn254>::setup(8, &mut rng);
    let (pk, _) = params8.derive_keys(Cubic(None), &mut rng).unwrap();
    let x = Fr::from(2u64);
    assert!(verifies(
        &pk,
        Cubic(Some(x)),
        &[x * x * x + x + Fr::from(5u64)],
        &mut rng
    ));
    let params4 = UniversalParams::<Bn254>::setup(4, &mut rng);
    assert!(params4.derive_keys(Cubic(None), &mut rng).is_err());
}

// ─── Forgery ─────────────────────────────────────────────────────────────────

#[test]
fn unblinded_keys_are_forgeable_until_delta_is_contributed() {
    let mut rng = StdRng::seed_from_u64(12);
    let params = UniversalParams::<Bn254>::setup(16, &mut rng);
    let mut pk = params.derive_unblinded_keys(Square(None)).unwrap();
    let lie = [Fr::from(5u64)]; // 5 is not checked against any witness
    let forged = forge_with_known_delta(&pk, &lie, Fr::one());
    let pvk = prepare_verifying_key(&pk.vk);
    assert!(
        Groth16::<Bn254>::verify_proof(&pvk, &forged, &lie).unwrap(),
        "δ=1 must be forgeable (documents why Phase 2 is required)"
    );

    contribute_delta(&mut pk, &mut rng);
    let forged = forge_with_known_delta(&pk, &lie, Fr::one());
    let pvk = prepare_verifying_key(&pk.vk);
    assert!(!Groth16::<Bn254>::verify_proof(&pvk, &forged, &lie).unwrap());
}

#[test]
fn proofs_do_not_cross_circuits_or_derivations() {
    let mut rng = StdRng::seed_from_u64(13);
    let params = UniversalParams::<Bn254>::setup(16, &mut rng);
    let (sq_pk, _) = params.derive_keys(Square(None), &mut rng).unwrap();
    let (sq_pk2, _) = params.derive_keys(Square(None), &mut rng).unwrap();
    let (cu_pk, _) = params.derive_keys(Cubic(None), &mut rng).unwrap();
    let x = Fr::from(3u64);
    let p = Groth16::<Bn254>::prove(&sq_pk, Square(Some(x)), &mut rng).unwrap();
    // Same arity, different circuit / different δ: must not verify.
    assert!(
        !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&cu_pk.vk), &p, &[x * x]).unwrap()
    );
    assert!(
        !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&sq_pk2.vk), &p, &[x * x]).unwrap()
    );
}

// ─── Phase 1 tampering ───────────────────────────────────────────────────────

#[test]
fn phase1_rejects_every_single_point_tamper() {
    let mut rng = StdRng::seed_from_u64(14);
    let params = UniversalParams::<Bn254>::setup(8, &mut rng);
    assert!(params.is_well_formed());
    let bump1 = |p: &mut G1Affine| *p = (*p + G1Affine::generator()).into_affine();
    let bump2 = |p: &mut G2Affine| *p = (*p + G2Affine::generator()).into_affine();
    for i in 0..params.tau_g1.len() {
        let mut t = params.clone();
        bump1(&mut t.tau_g1[i]);
        assert!(!t.is_well_formed(), "tau_g1[{i}]");
    }
    for i in 0..params.tau_g2.len() {
        let mut t = params.clone();
        bump2(&mut t.tau_g2[i]);
        assert!(!t.is_well_formed(), "tau_g2[{i}]");
    }
    for i in 0..params.alpha_tau_g1.len() {
        let mut t = params.clone();
        bump1(&mut t.alpha_tau_g1[i]);
        assert!(!t.is_well_formed(), "alpha_tau_g1[{i}]");
        let mut t = params.clone();
        bump1(&mut t.beta_tau_g1[i]);
        assert!(!t.is_well_formed(), "beta_tau_g1[{i}]");
    }
    let mut t = params.clone();
    bump2(&mut t.beta_g2);
    assert!(!t.is_well_formed(), "beta_g2");

    // Consistent but re-anchored to a different generator: rejected.
    let mut t = params.clone();
    let k = Fr::from(7u64);
    for p in t
        .tau_g1
        .iter_mut()
        .chain(&mut t.alpha_tau_g1)
        .chain(&mut t.beta_tau_g1)
    {
        *p = (*p * k).into_affine();
    }
    assert!(!t.is_well_formed(), "re-anchored G1");

    // Wrong lengths / empty transcripts.
    assert!(UniversalParams::<Bn254>::from_transcript(
        vec![],
        vec![],
        vec![],
        vec![],
        G2Affine::generator()
    )
    .is_none());
    let mut t = params.clone();
    t.tau_g1.pop();
    assert!(!t.is_well_formed());
    let p = params.clone();
    assert!(UniversalParams::<Bn254>::from_transcript(
        p.tau_g1,
        p.tau_g2,
        p.alpha_tau_g1,
        p.beta_tau_g1,
        p.beta_g2
    )
    .is_some());
}

#[test]
fn phase1_rejects_replaced_or_replayed_contributions() {
    let mut rng = StdRng::seed_from_u64(15);
    let prev = UniversalParams::<Bn254>::setup(8, &mut rng);

    // Attacker throws prev away and starts over (so they know every secret).
    let mut fake = UniversalParams::<Bn254>::identity(8);
    let fake_proof = fake.contribute(&mut rng);
    assert!(fake.is_well_formed());
    assert!(!UniversalParams::verify_contribution(
        &prev,
        &fake,
        &fake_proof
    ));

    // Replaying an honest proof on different parameters.
    let mut honest = prev.clone();
    let proof = honest.contribute(&mut rng);
    assert!(UniversalParams::verify_contribution(&prev, &honest, &proof));
    assert!(!UniversalParams::verify_contribution(&prev, &fake, &proof));
    let mut other = prev.clone();
    other.contribute(&mut rng);
    assert!(!UniversalParams::verify_contribution(&prev, &other, &proof));

    // Mismatched sizes.
    let mut big = UniversalParams::<Bn254>::setup(16, &mut rng);
    let p = big.contribute(&mut rng);
    assert!(!UniversalParams::verify_contribution(&prev, &big, &p));
}

// ─── Phase 2 tampering ───────────────────────────────────────────────────────

#[test]
fn phase2_rejects_tampered_keys_and_transcripts() {
    let mut rng = StdRng::seed_from_u64(16);
    let params = UniversalParams::<Bn254>::setup(16, &mut rng);
    let base = params.derive_unblinded_keys(Cubic(None)).unwrap();
    let mut pk = base.clone();
    let c1 = contribute_delta(&mut pk, &mut rng);
    let c2 = contribute_delta(&mut pk, &mut rng);
    let t = vec![c1.clone(), c2.clone()];
    assert!(verify_delta_chain(&base, &pk, &t));
    assert!(params.verify_keys(Cubic(None), &pk, &t).unwrap());

    let g = G1Affine::generator();
    let mut bad = pk.clone();
    bad.l_query[0] = (bad.l_query[0] + g).into_affine();
    assert!(!verify_delta_chain(&base, &bad, &t), "L tamper");
    let mut bad = pk.clone();
    let last = bad.h_query.len() - 1;
    bad.h_query[last] = (bad.h_query[last] + g).into_affine();
    assert!(!verify_delta_chain(&base, &bad, &t), "H tamper");
    let mut bad = pk.clone();
    bad.vk.delta_g2 = (bad.vk.delta_g2 + G2Affine::generator()).into_affine();
    assert!(!verify_delta_chain(&base, &bad, &t), "δH tamper");
    let mut bad = pk.clone();
    bad.a_query[1] = (bad.a_query[1] + g).into_affine();
    assert!(!verify_delta_chain(&base, &bad, &t), "A tamper");
    let mut bad = pk.clone();
    bad.vk.gamma_abc_g1[1] = (bad.vk.gamma_abc_g1[1] + g).into_affine();
    assert!(!verify_delta_chain(&base, &bad, &t), "IC tamper");

    // Reordered, truncated or empty transcripts.
    assert!(!verify_delta_chain(&base, &pk, &[c2.clone(), c1.clone()]));
    assert!(!verify_delta_chain(&base, &pk, std::slice::from_ref(&c2)));
    assert!(!verify_delta_chain(&base, &base, &[]));

    // Attacker drops the honest contributions and substitutes their own δ.
    let mut evil = base.clone();
    let ce = contribute_delta(&mut evil, &mut rng);
    assert!(
        verify_delta_chain(&base, &evil, std::slice::from_ref(&ce)),
        "a lone chain is valid by itself"
    );
    assert!(
        !verify_delta_chain(&base, &evil, &[c1.clone(), ce.clone()]),
        "cannot splice onto c1"
    );

    // Keys checked against a different circuit or different Phase 1 params.
    assert!(!params.verify_keys(Square(None), &pk, &t).unwrap_or(false));
    let other = UniversalParams::<Bn254>::setup(16, &mut rng);
    assert!(!other.verify_keys(Cubic(None), &pk, &t).unwrap());

    // A proof of knowledge for one step does not verify another step, and a
    // step only verifies in the context of its own circuit.
    let ctx = |pk: &ProvingKey<Bn254>| [b"phase2/".as_slice(), &circuit_digest(pk)].concat();
    assert!(c1.proof.verify(&base.delta_g1, &c1.delta_g1, &ctx(&base)));
    assert!(!c1.proof.verify(&base.delta_g1, &c2.delta_g1, &ctx(&base)));
    let square_base = params.derive_unblinded_keys(Square(None)).unwrap();
    assert!(!c1
        .proof
        .verify(&base.delta_g1, &c1.delta_g1, &ctx(&square_base)));
}

/// An RNG that always returns zeros, standing in for a broken entropy source.
struct BrokenRng;
impl ark_std::rand::RngCore for BrokenRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        dest.fill(0);
        Ok(())
    }
}

/// With a plain random nonce, a stuck RNG gives two proofs the same R, and
/// then x = (z₁ − z₂)/(c₁ − c₂) leaks the contributor's toxic waste. The
/// hedged nonce depends on x and the statement, so R differs and nothing leaks.
#[test]
fn proof_of_knowledge_survives_a_broken_rng() {
    let g = G1Affine::generator();
    let (x1, x2) = (Fr::from(1111u64), Fr::from(2222u64));
    let t1 = (g * x1).into_affine();
    let t2 = (g * x2).into_affine();
    let p1 = DlogProof::<Bn254>::prove(&g, &t1, &x1, b"ctx", &mut BrokenRng);
    let p2 = DlogProof::<Bn254>::prove(&g, &t2, &x2, b"ctx", &mut BrokenRng);
    assert!(p1.verify(&g, &t1, b"ctx") && p2.verify(&g, &t2, b"ctx"));
    assert_ne!(p1.r, p2.r, "nonce reuse would leak x");
    assert!(!p1.verify(&g, &t1, b"other"), "context is bound");
}

/// A contribution with a dead RNG must stop loudly, not hang or carry on with
/// predictable (zero) secrets.
#[test]
#[should_panic(expected = "entropy source is broken")]
fn contribution_refuses_a_broken_rng() {
    let mut params = UniversalParams::<Bn254>::identity(4);
    params.contribute(&mut BrokenRng);
}

// ─── KZG SRS ─────────────────────────────────────────────────────────────────

#[test]
fn kzg_srs_transcripts_are_validated() {
    let mut rng = StdRng::seed_from_u64(17);
    assert!(
        UniversalSRS::<Bn254>::from_powers_of_tau(vec![], vec![]).is_none(),
        "empty"
    );
    let srs = UniversalSRS::<Bn254>::setup(8, &mut rng);
    let ok =
        UniversalSRS::<Bn254>::from_powers_of_tau(srs.powers_of_g.clone(), srs.powers_of_h.clone());
    assert!(ok.is_some());

    // Random (unstructured) G1 powers: commitments would not be binding.
    let random_g: Vec<G1Affine> = (0..srs.powers_of_g.len())
        .map(|_| G1Affine::rand(&mut rng))
        .collect();
    assert!(UniversalSRS::<Bn254>::from_powers_of_tau(random_g, srs.powers_of_h.clone()).is_none());
    // One wrong G2 power.
    let mut h = srs.powers_of_h.clone();
    h[3] = (h[3] + G2Affine::generator()).into_affine();
    assert!(UniversalSRS::<Bn254>::from_powers_of_tau(srs.powers_of_g.clone(), h).is_none());
    // Identity anchors.
    let zeros = vec![G1Affine::zero(); 4];
    assert!(UniversalSRS::<Bn254>::from_powers_of_tau(zeros, vec![G2Affine::zero(); 4]).is_none());

    // An update that swaps in a fresh SRS (attacker knows its τ) is rejected.
    let mut fresh = UniversalSRS::<Bn254>::setup(8, &mut rng);
    let proof = fresh.update(&mut rng);
    assert!(!UniversalSRS::verify_update(&srs, &fresh, &proof));
}

// ─── Full ceremony transcripts and cached Lagrange bases ────────────────────

#[test]
fn phase1_transcript_from_identity_is_checkable_end_to_end() {
    let mut rng = StdRng::seed_from_u64(18);
    let mut params = UniversalParams::<Bn254>::identity(8);
    assert!(
        !params.verify_transcript(&[]),
        "identity params have known trapdoors"
    );
    let t: Vec<_> = (0..3).map(|_| params.contribute(&mut rng)).collect();
    assert!(params.verify_transcript(&t));

    // Dropped, reordered or truncated steps break the chain.
    assert!(!params.verify_transcript(&[t[0].clone(), t[2].clone()]));
    assert!(!params.verify_transcript(&[t[1].clone(), t[0].clone(), t[2].clone()]));
    assert!(!params.verify_transcript(&t[..2]));

    // An attacker restarting from identity cannot splice onto honest steps.
    let mut evil = UniversalParams::<Bn254>::identity(8);
    let e = evil.contribute(&mut rng);
    assert!(
        evil.verify_transcript(std::slice::from_ref(&e)),
        "a lone chain is valid on its own"
    );
    assert!(!evil.verify_transcript(&[t[0].clone(), e.clone()]));

    // Final parameters that do not match the transcript's last anchors.
    assert!(!evil.verify_transcript(&t));
}

#[test]
fn cached_lagrange_bases_are_checked() {
    let mut rng = StdRng::seed_from_u64(19);
    let params = UniversalParams::<Bn254>::setup(16, &mut rng);
    let bases = params.lagrange_bases(8).unwrap();
    assert!(bases.is_consistent_with(&params));
    assert_eq!(
        params
            .derive_unblinded_keys_with(&bases, Cubic(None))
            .unwrap(),
        params.derive_unblinded_keys(Cubic(None)).unwrap()
    );
    assert!(params.lagrange_bases(6).is_none(), "not a power of two");
    assert!(params.lagrange_bases(32).is_none(), "larger than the setup");

    let g = G1Affine::generator();
    let mut poisoned = bases.clone();
    poisoned.alpha_g1[3] = (poisoned.alpha_g1[3] + g).into_affine();
    assert!(params
        .derive_unblinded_keys_with(&poisoned, Cubic(None))
        .is_err());
    let mut poisoned = bases.clone();
    poisoned.g2[0] = (poisoned.g2[0] + G2Affine::generator()).into_affine();
    assert!(params
        .derive_unblinded_keys_with(&poisoned, Cubic(None))
        .is_err());

    // Bases from other parameters, or for the wrong domain size.
    let other = UniversalParams::<Bn254>::setup(16, &mut rng);
    assert!(other
        .derive_unblinded_keys_with(&bases, Cubic(None))
        .is_err());
    let small = params.lagrange_bases(4).unwrap();
    assert!(params
        .derive_unblinded_keys_with(&small, Cubic(None))
        .is_err());

    // verify_keys_with matches verify_keys.
    let mut pk = params
        .derive_unblinded_keys_with(&bases, Cubic(None))
        .unwrap();
    let c = contribute_delta(&mut pk, &mut rng);
    assert!(params
        .verify_keys_with(&bases, Cubic(None), &pk, std::slice::from_ref(&c))
        .unwrap());
    assert!(params.verify_keys(Cubic(None), &pk, &[c]).unwrap());
}

// ─── Random beacon final steps ───────────────────────────────────────────────

#[test]
fn beacon_steps_are_reproducible_and_checked() {
    let mut rng = StdRng::seed_from_u64(20);
    let beacon = b"block 21000000 hash: 9f86d081884c7d659a2feaa0c55ad015";

    // Phase 1: two human contributions, then the beacon.
    let mut params = UniversalParams::<Bn254>::identity(8);
    let mut t: Vec<_> = (0..2).map(|_| params.contribute(&mut rng)).collect();
    let before = params.clone();
    let b = params.contribute_from_beacon(beacon, 1000);
    t.push(b.clone());
    assert!(
        params.verify_transcript(&t),
        "a beacon step is a normal contribution"
    );
    assert!(UniversalParams::verify_beacon_contribution(
        &before, &params, &b, beacon, 1000
    ));
    assert!(!UniversalParams::verify_beacon_contribution(
        &before, &params, &b, beacon, 999
    ));
    assert!(!UniversalParams::verify_beacon_contribution(
        &before, &params, &b, b"other", 1000
    ));

    // The last human contributor cannot swap in an output of their choosing.
    let mut chosen = before.clone();
    let c = chosen.contribute(&mut rng);
    assert!(UniversalParams::verify_contribution(&before, &chosen, &c));
    assert!(!UniversalParams::verify_beacon_contribution(
        &before, &chosen, &c, beacon, 1000
    ));

    // Deterministic: recomputing gives identical bytes.
    let mut again = before.clone();
    assert_eq!(again.contribute_from_beacon(beacon, 1000), b);
    assert_eq!(again, params);

    // Phase 2: one human δ step, then the beacon; keys still prove and verify.
    let base = params.derive_unblinded_keys(Cubic(None)).unwrap();
    let mut pk = base.clone();
    let c1 = contribute_delta(&mut pk, &mut rng);
    let before_pk = pk.clone();
    let cb = contribute_delta_from_beacon(&mut pk, beacon, 1000);
    assert!(verify_delta_chain(&base, &pk, &[c1, cb.clone()]));
    assert!(verify_delta_beacon(&before_pk, &pk, &cb, beacon, 1000));
    assert!(!verify_delta_beacon(&before_pk, &pk, &cb, b"other", 1000));
    let x = Fr::from(6u64);
    assert!(verifies(
        &pk,
        Cubic(Some(x)),
        &[x * x * x + x + Fr::from(5u64)],
        &mut rng
    ));
}
