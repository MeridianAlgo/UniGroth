//! # Authentication Circuit — Credential Proof with Replay-Resistant Nullifier
//!
//! Production-ready zk circuit for secure sharing / authentication platforms.
//!
//! Proves knowledge of a secret `s` such that:
//!   * `commitment = H(s, 0)`     — stable per-user identifier (stored at registration)
//!   * `nullifier  = H(s, nonce)` — fresh per-upload tag (prevents proof replay)
//!
//! The secret `s` is a private witness — never leaves the prover (browser).
//! `commitment`, `nullifier`, and `nonce` are public inputs.
//!
//! ## Hash function
//!
//! Uses MiMC `LongsightF322p3` — algebraic, R1CS-native, sound by construction
//! (each round adds 2 constraints binding output as a *function* of inputs).
//!
//! ## Soundness
//!
//! Unlike the simplified Poseidon gadget in [`crate::circuits`], every round of
//! the MiMC permutation here is fully constrained. There is no unconstrained
//! "difference witness" that an adversary could pick freely.
//!
//! ## Public input ordering
//!
//! `[commitment, nullifier, nonce]`
//!
//! The verifier MUST pass them in that exact order.

#![allow(missing_docs)]

use ark_ff::PrimeField;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use ark_std::{vec, vec::Vec};

/// Number of MiMC rounds (matches `LongsightF322p3`).
pub const MIMC_ROUNDS: usize = 322;

/// Deterministic round-constant generator. Public, fixed across all parties.
///
/// Constants are derived from `MiMC-c_{i} = F::from(i * 2654435761 + 1)` —
/// a Knuth-multiplicative spread that never collides modulo the prime.
pub fn mimc_round_constants<F: PrimeField>() -> Vec<F> {
    (0..MIMC_ROUNDS)
        .map(|i| F::from((i as u64).wrapping_mul(2_654_435_761).wrapping_add(1)))
        .collect()
}

/// Native MiMC sponge: `H(xl, xr) -> F`.
///
/// Identical evaluation to the in-circuit constraints below — use this in
/// the browser/host to compute commitments / nullifiers off-circuit.
pub fn mimc_hash<F: PrimeField>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);
    for c in constants.iter().take(MIMC_ROUNDS) {
        let t = xl + *c;
        let t3 = t * t * t;
        let new_xl = t3 + xr;
        xr = xl;
        xl = new_xl;
    }
    xl
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Allocate a witness wire holding a `F::from(0)` value.
fn alloc_zero<F: PrimeField>(cs: &ConstraintSystemRef<F>) -> Result<Variable, SynthesisError> {
    cs.new_witness_variable(|| Ok(F::zero()))
}

/// MiMC round in-circuit. Given (xl, xr) wires + their values + round constant,
/// returns (new_xl, new_xr) wires + values, after enforcing two R1CS constraints.
///
///   t   = xl + c          (linear, free)
///   sq  = t * t           (constraint 1)
///   t3  = sq * t          (constraint 2)
///   new_xl = t3 + xr      (linear, free)
///   new_xr = xl           (wire rename)
#[allow(clippy::type_complexity)]
fn mimc_round<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    xl_var: Variable,
    xl_val: Option<F>,
    xr_var: Variable,
    xr_val: Option<F>,
    c: F,
) -> Result<(Variable, Option<F>, Variable, Option<F>), SynthesisError> {
    let t_val = xl_val.map(|v| v + c);
    let sq_val = t_val.map(|v| v * v);
    let t3_val = match (t_val, sq_val) {
        (Some(t), Some(sq)) => Some(sq * t),
        _ => None,
    };
    let new_xl_val = match (t3_val, xr_val) {
        (Some(t3), Some(xr)) => Some(t3 + xr),
        _ => None,
    };

    // sq = (xl + c) * (xl + c)
    let sq_var = cs.new_witness_variable(|| sq_val.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce_r1cs_constraint(
        || lc!() + xl_var + (c, Variable::One),
        || lc!() + xl_var + (c, Variable::One),
        || lc!() + sq_var,
    )?;

    // t3 = sq * (xl + c)
    let t3_var = cs.new_witness_variable(|| t3_val.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce_r1cs_constraint(
        || lc!() + sq_var,
        || lc!() + xl_var + (c, Variable::One),
        || lc!() + t3_var,
    )?;

    // new_xl = t3 + xr  (free linear combination, expose as fresh wire for the next round)
    let new_xl_var =
        cs.new_witness_variable(|| new_xl_val.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce_r1cs_constraint(
        || lc!() + t3_var + xr_var,
        || lc!() + Variable::One,
        || lc!() + new_xl_var,
    )?;

    Ok((new_xl_var, new_xl_val, xl_var, xl_val))
}

/// Constrain `out_var == MiMC(xl_var, xr_var)` over the round constants.
/// Returns the final-round witness wire holding the hash output.
fn mimc_gadget<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    xl_var: Variable,
    xl_val: Option<F>,
    xr_var: Variable,
    xr_val: Option<F>,
    constants: &[F],
) -> Result<(Variable, Option<F>), SynthesisError> {
    let mut cur_xl_var = xl_var;
    let mut cur_xl_val = xl_val;
    let mut cur_xr_var = xr_var;
    let mut cur_xr_val = xr_val;

    for c in constants.iter().take(MIMC_ROUNDS) {
        let (nxl, nxl_v, nxr, nxr_v) =
            mimc_round(cs, cur_xl_var, cur_xl_val, cur_xr_var, cur_xr_val, *c)?;
        cur_xl_var = nxl;
        cur_xl_val = nxl_v;
        cur_xr_var = nxr;
        cur_xr_val = nxr_v;
    }

    Ok((cur_xl_var, cur_xl_val))
}

// ─── AuthCircuit ────────────────────────────────────────────────────────────

/// Auth circuit — proves `commitment = H(s, 0)` ∧ `nullifier = H(s, nonce)`.
///
/// Public inputs (order matters): `[commitment, nullifier, nonce]`.
#[derive(Clone)]
pub struct AuthCircuit<F: PrimeField> {
    /// Private credential. `None` during setup.
    pub secret: Option<F>,
    /// Public stable identifier — `H(secret, 0)`.
    pub commitment: Option<F>,
    /// Public per-use tag — `H(secret, nonce)`.
    pub nullifier: Option<F>,
    /// Public server-issued challenge nonce.
    pub nonce: Option<F>,
    /// MiMC round constants (must match across setup / prove / verify).
    pub constants: Vec<F>,
}

impl<F: PrimeField> AuthCircuit<F> {
    /// Build an empty circuit (for trusted setup — no witness values).
    pub fn empty(constants: Vec<F>) -> Self {
        Self {
            secret: None,
            commitment: None,
            nullifier: None,
            nonce: None,
            constants,
        }
    }

    /// Build a circuit with full witness for proving.
    pub fn new(secret: F, nonce: F, constants: Vec<F>) -> Self {
        let commitment = mimc_hash(secret, F::zero(), &constants);
        let nullifier = mimc_hash(secret, nonce, &constants);
        Self {
            secret: Some(secret),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            nonce: Some(nonce),
            constants,
        }
    }

    /// Compute the public inputs vector in canonical order.
    pub fn public_inputs(&self) -> Option<Vec<F>> {
        Some(vec![self.commitment?, self.nullifier?, self.nonce?])
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AuthCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert_eq!(
            self.constants.len(),
            MIMC_ROUNDS,
            "auth circuit requires exactly MIMC_ROUNDS constants"
        );

        // ── Public inputs ────────────────────────────────────────────────
        let commitment_var = cs
            .new_input_variable(|| self.commitment.ok_or(SynthesisError::AssignmentMissing))?;
        let nullifier_var =
            cs.new_input_variable(|| self.nullifier.ok_or(SynthesisError::AssignmentMissing))?;
        let nonce_var =
            cs.new_input_variable(|| self.nonce.ok_or(SynthesisError::AssignmentMissing))?;

        // ── Private witness ─────────────────────────────────────────────
        let secret_var =
            cs.new_witness_variable(|| self.secret.ok_or(SynthesisError::AssignmentMissing))?;

        // ── Branch 1: commitment = MiMC(secret, 0) ──────────────────────
        let zero_var = alloc_zero(&cs)?;
        // enforce zero_var == 0 (zero * 1 = zero is already implied by alloc; we add an explicit binding)
        cs.enforce_r1cs_constraint(
            || lc!() + zero_var,
            || lc!() + Variable::One,
            || lc!(),
        )?;

        let (computed_commitment_var, _computed_commitment_val) = mimc_gadget(
            &cs,
            secret_var,
            self.secret,
            zero_var,
            Some(F::zero()),
            &self.constants,
        )?;

        // Bind: computed_commitment == public commitment
        cs.enforce_r1cs_constraint(
            || lc!() + computed_commitment_var - commitment_var,
            || lc!() + Variable::One,
            || lc!(),
        )?;

        // ── Branch 2: nullifier = MiMC(secret, nonce) ───────────────────
        let (computed_nullifier_var, _computed_nullifier_val) = mimc_gadget(
            &cs,
            secret_var,
            self.secret,
            nonce_var,
            self.nonce,
            &self.constants,
        )?;

        // Bind: computed_nullifier == public nullifier
        cs.enforce_r1cs_constraint(
            || lc!() + computed_nullifier_var - nullifier_var,
            || lc!() + Variable::One,
            || lc!(),
        )?;

        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_ff::Zero;
    use ark_snark::SNARK;
    use ark_std::rand::{RngCore, SeedableRng};

    fn rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64())
    }

    #[test]
    fn mimc_deterministic() {
        let c = mimc_round_constants::<Fr>();
        let a = mimc_hash(Fr::from(7u64), Fr::from(11u64), &c);
        let b = mimc_hash(Fr::from(7u64), Fr::from(11u64), &c);
        assert_eq!(a, b);
        assert_ne!(a, Fr::zero());
    }

    #[test]
    fn auth_roundtrip() {
        let constants = mimc_round_constants::<Fr>();
        let secret = Fr::from(0xDEADBEEFu64);
        let nonce = Fr::from(0xCAFEBABEu64);

        let circuit = AuthCircuit::new(secret, nonce, constants.clone());
        let public = circuit.public_inputs().unwrap();

        let mut r = rng();
        let setup = AuthCircuit::<Fr>::empty(constants);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup, &mut r).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut r).unwrap();
        let ok = Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap();
        assert!(ok, "honest auth proof must verify");
    }

    #[test]
    fn auth_wrong_nullifier_fails() {
        let constants = mimc_round_constants::<Fr>();
        let secret = Fr::from(42u64);
        let nonce = Fr::from(99u64);

        let circuit = AuthCircuit::new(secret, nonce, constants.clone());
        let mut public = circuit.public_inputs().unwrap();
        // tamper nullifier
        public[1] = Fr::from(123u64);

        let mut r = rng();
        let setup = AuthCircuit::<Fr>::empty(constants);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup, &mut r).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut r).unwrap();
        let ok = Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap();
        assert!(!ok, "tampered nullifier must be rejected");
    }

    #[test]
    fn auth_different_nonce_different_nullifier() {
        let constants = mimc_round_constants::<Fr>();
        let secret = Fr::from(1234u64);

        let nf1 = mimc_hash(secret, Fr::from(1u64), &constants);
        let nf2 = mimc_hash(secret, Fr::from(2u64), &constants);
        assert_ne!(nf1, nf2);
    }
}
