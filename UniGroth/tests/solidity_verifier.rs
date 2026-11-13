//! The generated Solidity verifier, checked end to end.
//!
//! This test proves a statement, generates the contracts and checks the proofs
//! natively. With `UNIGROTH_EVM_FIXTURE_DIR` set it also writes the two
//! contracts and matching calldata (`fixture.json`: `a`, `b`, `c`, `input` as
//! `verifyProof` takes them) to that directory, and `tests/evm/run.mjs`
//! compiles them with solc and runs them in an EVM:
//!
//! ```text
//! UNIGROTH_EVM_FIXTURE_DIR=tests/evm/fixture \
//!     cargo test --features solidity --test solidity_verifier
//! cd tests/evm && npm ci && node run.mjs fixture
//! ```
#![cfg(feature = "solidity")]

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use unigroth::{solidity::generate_solidity_verifier, Groth16, Proof};

/// Public inputs `[x·y, x + y]` for private `x, y`.
#[derive(Clone)]
struct ProductAndSum(Option<(Fr, Fr)>);

impl ConstraintSynthesizer<Fr> for ProductAndSum {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let get = |f: fn((Fr, Fr)) -> Fr| self.0.map(f).ok_or(SynthesisError::AssignmentMissing);
        let x = cs.new_witness_variable(|| get(|w| w.0))?;
        let y = cs.new_witness_variable(|| get(|w| w.1))?;
        let product = cs.new_input_variable(|| get(|w| w.0 * w.1))?;
        let sum = cs.new_input_variable(|| get(|w| w.0 + w.1))?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + y, || lc!() + product)?;
        cs.enforce_r1cs_constraint(
            || lc!() + x + y,
            || lc!() + ark_relations::gr1cs::Variable::One,
            || lc!() + sum,
        )
    }
}

/// No public inputs: the contract's `verifyProof` then has no `input` argument.
#[derive(Clone)]
struct NoInputs(Option<Fr>);

impl ConstraintSynthesizer<Fr> for NoInputs {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.0.ok_or(SynthesisError::AssignmentMissing))?;
        let x2 = cs.new_witness_variable(|| {
            self.0
                .map(|v| v * v)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x2)
    }
}

fn hex<F: PrimeField>(x: &F) -> String {
    let digits: String = x
        .into_bigint()
        .to_bytes_be()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("\"0x{digits}\"")
}

fn g1_json(p: &G1Affine) -> String {
    format!("[{}, {}]", hex::<Fq>(&p.x), hex::<Fq>(&p.y))
}

/// EIP-197 order: imaginary part first.
fn g2_json(p: &G2Affine) -> String {
    format!(
        "[[{}, {}], [{}, {}]]",
        hex(&p.x.c1),
        hex(&p.x.c0),
        hex(&p.y.c1),
        hex(&p.y.c0)
    )
}

fn proof_json(proof: &Proof<Bn254>, inputs: &[Fr]) -> String {
    let inputs: Vec<String> = inputs.iter().map(hex).collect();
    format!(
        "{{\"a\": {}, \"b\": {}, \"c\": {}, \"input\": [{}]}}",
        g1_json(&proof.a),
        g2_json(&proof.b),
        g1_json(&proof.c),
        inputs.join(", ")
    )
}

#[test]
fn generated_contract_matches_native_verification() {
    let mut rng = StdRng::seed_from_u64(2026);

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(ProductAndSum(None), &mut rng).unwrap();
    let (x, y) = (Fr::from(6u64), Fr::from(7u64));
    let inputs = [x * y, x + y];
    // Several proofs so the fixture covers both signs of every y coordinate.
    let proofs: Vec<Proof<Bn254>> = (0..4)
        .map(|_| Groth16::<Bn254>::prove(&pk, ProductAndSum(Some((x, y))), &mut rng).unwrap())
        .collect();
    for proof in &proofs {
        assert!(Groth16::<Bn254>::verify(&vk, &inputs, proof).unwrap());
    }
    let contract = generate_solidity_verifier(&vk, "ProductAndSumVerifier");
    assert!(contract.contains("uint256[2] memory input"));

    let (pk0, vk0) = Groth16::<Bn254>::circuit_specific_setup(NoInputs(None), &mut rng).unwrap();
    let proof0 = Groth16::<Bn254>::prove(&pk0, NoInputs(Some(Fr::from(3u64))), &mut rng).unwrap();
    assert!(Groth16::<Bn254>::verify(&vk0, &[], &proof0).unwrap());
    let contract0 = generate_solidity_verifier(&vk0, "NoInputsVerifier");
    assert!(
        !contract0.contains("uint256[0]"),
        "zero-length fixed arrays do not compile"
    );

    let Ok(dir) = std::env::var("UNIGROTH_EVM_FIXTURE_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("ProductAndSumVerifier.sol"), contract).unwrap();
    std::fs::write(dir.join("NoInputsVerifier.sol"), contract0).unwrap();
    let cases: Vec<String> = proofs.iter().map(|p| proof_json(p, &inputs)).collect();
    // On the curve but outside the prime-order subgroup: only the pairing
    // precompile can reject this one.
    let off_subgroup = loop {
        use ark_ff::UniformRand;
        let x = ark_bn254::Fq2::rand(&mut rng);
        if let Some(p) = G2Affine::get_point_from_x_unchecked(x, false) {
            if p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve() {
                break p;
            }
        }
    };
    let fixture = format!(
        "{{\n  \"proofs\": [\n    {}\n  ],\n  \"noInputs\": {},\n  \"offSubgroupB\": {}\n}}\n",
        cases.join(",\n    "),
        proof_json(&proof0, &[]),
        g2_json(&off_subgroup)
    );
    std::fs::write(dir.join("fixture.json"), fixture).unwrap();
}
