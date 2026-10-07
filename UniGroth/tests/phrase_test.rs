use ark_bls12_377::{Bls12_377, Fr};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;
use std::time::Instant;
use unigroth::{
    prepare_verifying_key, r1cs_to_qap::LibsnarkReduction, security::apply_subversion_zk, Groth16,
};

/// SecretPhrase circuit: proves knowledge of `secret` such that Poseidon(secret) == `expected_hash`
struct SecretPhraseCircuit<F: PrimeField> {
    secret: Option<F>,
    expected_hash: Option<F>,
    config: PoseidonConfig<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SecretPhraseCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let expected_hash_var = FpVar::new_input(cs.clone(), || {
            self.expected_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Poseidon Gadget
        use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
        use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;

        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.config);
        sponge.absorb(&vec![secret_var])?;
        let hash_var = sponge.squeeze_field_elements(1)?[0].clone();

        hash_var.enforce_equal(&expected_hash_var)?;

        Ok(())
    }
}

// Helper to generate Poseidon config (standard parameters)
fn get_poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    use ark_std::vec;
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5;
    let mds = vec![
        vec![F::from(1u128), F::from(0u128), F::from(0u128)],
        vec![F::from(0u128), F::from(1u128), F::from(0u128)],
        vec![F::from(0u128), F::from(0u128), F::from(1u128)],
    ];
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let round_constants = (0..(full_rounds + partial_rounds))
        .map(|_| vec![F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng)])
        .collect();
    PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        round_constants,
        2,
        1,
    )
}

#[test]
fn test_unigroth_advanced_features() {
    let mut test_rng = test_rng();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng.next_u64());
    let config = get_poseidon_config::<Fr>();

    println!("--- UniGroth Advanced Features Benchmark ---");

    // 1. Circuit size
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    let circuit_stats = SecretPhraseCircuit {
        secret: None,
        expected_hash: None,
        config: config.clone(),
    };
    circuit_stats.generate_constraints(cs.clone()).unwrap();
    cs.finalize();

    assert!(cs.num_constraints() > 0);
    println!("R1CS constraints: {}", cs.num_constraints());

    // 2. Setup and proving time
    let setup_start = Instant::now();
    let circuit_setup = SecretPhraseCircuit {
        secret: None,
        expected_hash: None,
        config: config.clone(),
    };
    let (pk, vk) = Groth16::<Bls12_377, LibsnarkReduction>::setup(circuit_setup, &mut rng).unwrap();
    println!("Setup time: {:?}", setup_start.elapsed());

    let secret = Fr::rand(&mut rng);
    let mut sponge = PoseidonSponge::new(&config);
    sponge.absorb(&secret);
    let expected_hash = sponge.squeeze_field_elements(1)[0];

    let circuit_prove = SecretPhraseCircuit {
        secret: Some(secret),
        expected_hash: Some(expected_hash),
        config: config.clone(),
    };

    let prove_start = Instant::now();
    let proof =
        Groth16::<Bls12_377, LibsnarkReduction>::prove(&pk, circuit_prove, &mut rng).unwrap();
    println!("Proving time: {:?}", prove_start.elapsed());

    // 3. Security: Subversion-ZK rerandomization
    println!("\n[Security: S-ZK]");
    let secure_proof = apply_subversion_zk(&proof, &vk, &mut rng);

    let pvk = prepare_verifying_key(&vk);
    let verify_start = Instant::now();
    let is_valid =
        Groth16::<Bls12_377>::verify_proof(&pvk, &secure_proof, &[expected_hash]).unwrap();
    println!("Verification time: {:?}", verify_start.elapsed());
    assert!(is_valid);
}
