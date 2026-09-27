//! # Circuit Library — Reusable Gadgets
#![allow(missing_docs)]
//!
//! Common circuit gadgets for building zkSNARK applications:
//!
//! - **Poseidon Hash**: x⁵ Poseidon permutation, every S-box constrained
//! - **Merkle Tree**: Binary Merkle tree membership proofs over Poseidon
//! - **Range Check**: bit decomposition
//!
//! All gadgets implement `ConstraintSynthesizer` and can be composed
//! with each other and used directly with the Groth16/UniGroth prover.

use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
    lc,
};
use ark_std::vec::Vec;

// ─── Poseidon Hash Circuit ─────────────────────────────────────────────────

/// Poseidon hash parameters (x⁵ S-box).
#[derive(Clone, Debug)]
pub struct PoseidonParams<F: PrimeField> {
    /// Number of full rounds
    pub full_rounds: usize,
    /// Number of partial rounds
    pub partial_rounds: usize,
    /// Width of the state (t)
    pub width: usize,
    /// Round constants, `width` per round, row-major
    pub round_constants: Vec<F>,
    /// MDS matrix (width x width)
    pub mds_matrix: Vec<Vec<F>>,
}

impl<F: PrimeField> PoseidonParams<F> {
    /// Poseidon parameters for width=3 (2-to-1 hash): 8 full and 57 partial
    /// rounds, with round constants and MDS matrix from the reference Grain
    /// LFSR generator. The x⁵ S-box requires gcd(5, p − 1) = 1, which holds
    /// for the BN254 and BLS12-381 scalar fields.
    pub fn default_2_to_1() -> Self {
        let (full_rounds, partial_rounds) = (
            crate::config::POSEIDON_FULL_ROUNDS,
            crate::config::POSEIDON_PARTIAL_ROUNDS,
        );
        let (ark, mds_matrix) = find_poseidon_ark_and_mds::<F>(
            F::MODULUS_BIT_SIZE as u64,
            crate::config::POSEIDON_WIDTH - 1,
            full_rounds as u64,
            partial_rounds as u64,
            0,
        );
        Self {
            full_rounds,
            partial_rounds,
            width: crate::config::POSEIDON_WIDTH,
            round_constants: ark.into_iter().flatten().collect(),
            mds_matrix,
        }
    }

    /// Whether round `r` applies the S-box to every state element.
    fn is_full_round(&self, r: usize) -> bool {
        let half = self.full_rounds / 2;
        r < half || r >= half + self.partial_rounds
    }

    fn num_rounds(&self) -> usize {
        self.full_rounds + self.partial_rounds
    }
}

/// Poseidon 2-to-1 hash circuit.
///
/// Proves knowledge of (left, right) such that Poseidon(left, right) = output.
#[derive(Clone)]
pub struct PoseidonHashCircuit<F: PrimeField> {
    pub left: Option<F>,
    pub right: Option<F>,
    pub params: PoseidonParams<F>,
}

fn poseidon_sbox<F: PrimeField>(x: F) -> F {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x // x^5
}

fn poseidon_permutation<F: PrimeField>(state: &mut [F], params: &PoseidonParams<F>) {
    let w = params.width;
    for r in 0..params.num_rounds() {
        for j in 0..w {
            state[j] += params.round_constants[r * w + j];
        }
        if params.is_full_round(r) {
            for s in state.iter_mut() {
                *s = poseidon_sbox(*s);
            }
        } else {
            state[0] = poseidon_sbox(state[0]);
        }
        let old = state.to_vec();
        for j in 0..w {
            state[j] = (0..w).map(|k| params.mds_matrix[j][k] * old[k]).sum();
        }
    }
}

/// Compute Poseidon hash natively (outside circuit).
pub fn poseidon_hash<F: PrimeField>(left: F, right: F, params: &PoseidonParams<F>) -> F {
    let mut state = vec![F::from(0u64); params.width];
    state[0] = left;
    state[1] = right;
    poseidon_permutation(&mut state, params);
    state[0]
}

/// A value in the circuit: a linear combination of variables and its assignment.
type Wire<F> = (LinearCombination<F>, Option<F>);

/// Constrain `out = x⁵` with three multiplication constraints.
fn sbox_gadget<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    x: &Wire<F>,
) -> Result<Wire<F>, SynthesisError> {
    let (x_lc, x_val) = x;
    let x2_val = x_val.map(|v| v * v);
    let x4_val = x2_val.map(|v| v * v);
    let x5_val = x4_val.zip(*x_val).map(|(a, b)| a * b);
    let x2 = cs.new_witness_variable(|| x2_val.ok_or(SynthesisError::AssignmentMissing))?;
    let x4 = cs.new_witness_variable(|| x4_val.ok_or(SynthesisError::AssignmentMissing))?;
    let x5 = cs.new_witness_variable(|| x5_val.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce_r1cs_constraint(|| x_lc.clone(), || x_lc.clone(), || lc!() + x2)?;
    cs.enforce_r1cs_constraint(|| lc!() + x2, || lc!() + x2, || lc!() + x4)?;
    cs.enforce_r1cs_constraint(|| lc!() + x4, || x_lc.clone(), || lc!() + x5)?;
    Ok((lc!() + x5, x5_val))
}

/// Constrain the Poseidon 2-to-1 hash of `left` and `right`, returning the output wire.
///
/// Round-constant additions and the MDS layer are linear and folded into
/// linear combinations; every S-box is enforced by R1CS constraints.
fn poseidon_gadget<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    left: Wire<F>,
    right: Wire<F>,
    params: &PoseidonParams<F>,
) -> Result<Wire<F>, SynthesisError> {
    let w = params.width;
    let mut state: Vec<Wire<F>> = vec![left, right];
    state.resize(w, (lc!(), Some(F::zero())));

    for r in 0..params.num_rounds() {
        for (j, (s_lc, s_val)) in state.iter_mut().enumerate() {
            let c = params.round_constants[r * w + j];
            *s_lc = s_lc.clone() + (c, Variable::One);
            *s_val = s_val.map(|v| v + c);
        }
        let sboxed = if params.is_full_round(r) { w } else { 1 };
        for s in state.iter_mut().take(sboxed) {
            *s = sbox_gadget(cs, s)?;
        }
        state = (0..w)
            .map(|j| {
                let mut out_lc = lc!();
                let mut out_val = Some(F::zero());
                for (k, (s_lc, s_val)) in state.iter().enumerate() {
                    let m = params.mds_matrix[j][k];
                    out_lc = out_lc + (m, s_lc);
                    out_val = out_val.zip(*s_val).map(|(acc, v)| acc + m * v);
                }
                (out_lc, out_val)
            })
            .collect();
    }

    Ok(state.swap_remove(0))
}

/// Allocate a fresh witness wire for `lc` so later constraints reference one variable.
fn materialize<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    wire: Wire<F>,
) -> Result<(Variable, Option<F>), SynthesisError> {
    let (w_lc, w_val) = wire;
    let var = cs.new_witness_variable(|| w_val.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce_r1cs_constraint(|| w_lc, || lc!() + Variable::One, || lc!() + var)?;
    Ok((var, w_val))
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PoseidonHashCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let left =
            cs.new_witness_variable(|| self.left.ok_or(SynthesisError::AssignmentMissing))?;
        let right =
            cs.new_witness_variable(|| self.right.ok_or(SynthesisError::AssignmentMissing))?;

        let (hash_lc, hash_val) = poseidon_gadget(
            &cs,
            (lc!() + left, self.left),
            (lc!() + right, self.right),
            &self.params,
        )?;
        let output = cs.new_input_variable(|| hash_val.ok_or(SynthesisError::AssignmentMissing))?;

        // output == Poseidon(left, right)
        cs.enforce_r1cs_constraint(|| hash_lc, || lc!() + Variable::One, || lc!() + output)?;

        Ok(())
    }
}

// ─── Merkle Tree Membership Circuit ────────────────────────────────────────

/// Merkle tree membership proof circuit.
///
/// Proves that a given leaf is at a specific position in a Merkle tree
/// with the given root hash.
#[derive(Clone)]
pub struct MerkleProofCircuit<F: PrimeField> {
    /// The leaf value
    pub leaf: Option<F>,
    /// Sibling hashes along the path (from leaf to root)
    pub path: Vec<Option<F>>,
    /// Path indices (0 = left, 1 = right)
    pub path_indices: Vec<Option<F>>,
    /// Poseidon parameters for hashing
    pub params: PoseidonParams<F>,
}

impl<F: PrimeField> MerkleProofCircuit<F> {
    /// Compute the Merkle root natively given the proof path.
    pub fn compute_root(&self) -> Option<F> {
        let leaf = self.leaf?;
        let mut current = leaf;

        for i in 0..self.path.len() {
            let sibling = self.path[i]?;
            let idx = self.path_indices[i]?;

            if idx == F::from(0u64) {
                current = poseidon_hash(current, sibling, &self.params);
            } else {
                current = poseidon_hash(sibling, current, &self.params);
            }
        }

        Some(current)
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MerkleProofCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        if self.path_indices.len() != self.path.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let leaf_var =
            cs.new_witness_variable(|| self.leaf.ok_or(SynthesisError::AssignmentMissing))?;

        let root_val = self.compute_root();
        let root_var =
            cs.new_input_variable(|| root_val.ok_or(SynthesisError::AssignmentMissing))?;

        let mut current = (leaf_var, self.leaf);

        for (sibling_val, idx_val) in self.path.iter().zip(&self.path_indices) {
            let (cur_var, cur_val) = current;
            let sibling_var =
                cs.new_witness_variable(|| sibling_val.ok_or(SynthesisError::AssignmentMissing))?;
            let idx_var =
                cs.new_witness_variable(|| idx_val.ok_or(SynthesisError::AssignmentMissing))?;

            // idx is boolean
            cs.enforce_r1cs_constraint(
                || lc!() + idx_var,
                || lc!() + Variable::One - idx_var,
                || lc!(),
            )?;

            // t = idx · (sibling − current); left = current + t, right = sibling − t
            let t_val = match (*idx_val, *sibling_val, cur_val) {
                (Some(i), Some(s), Some(c)) => Some(i * (s - c)),
                _ => None,
            };
            let t_var =
                cs.new_witness_variable(|| t_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_r1cs_constraint(
                || lc!() + idx_var,
                || lc!() + sibling_var - cur_var,
                || lc!() + t_var,
            )?;

            let left = (
                lc!() + cur_var + t_var,
                cur_val.zip(t_val).map(|(c, t)| c + t),
            );
            let right = (
                lc!() + sibling_var - t_var,
                sibling_val.zip(t_val).map(|(s, t)| s - t),
            );
            let hash = poseidon_gadget(&cs, left, right, &self.params)?;
            current = materialize(&cs, hash)?;
        }

        // Final hash must equal root
        cs.enforce_r1cs_constraint(
            || lc!() + current.0 - root_var,
            || lc!() + Variable::One,
            || lc!(),
        )?;

        Ok(())
    }
}

// ─── Range Check Gadget ────────────────────────────────────────────────────

/// Range check circuit: proves 0 <= value < 2^num_bits.
///
/// `num_bits` must be below the field's bit size so the bit sum cannot wrap
/// around the modulus.
#[derive(Clone)]
pub struct RangeCheckCircuit<F: PrimeField> {
    pub value: Option<F>,
    pub num_bits: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RangeCheckCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        if self.num_bits >= F::MODULUS_BIT_SIZE as usize {
            return Err(SynthesisError::Unsatisfiable);
        }
        let val = cs.new_input_variable(|| self.value.ok_or(SynthesisError::AssignmentMissing))?;

        let bits = self.value.map(|v| v.into_bigint().to_bits_le());

        let mut reconstructed_lc = lc!();
        let mut coeff = F::one();

        for i in 0..self.num_bits {
            let bit_val = bits.as_ref().map(|b| F::from(b[i]));
            let bit_var =
                cs.new_witness_variable(|| bit_val.ok_or(SynthesisError::AssignmentMissing))?;

            // Enforce boolean: bit * (1 - bit) = 0
            cs.enforce_r1cs_constraint(
                || lc!() + bit_var,
                || lc!() + Variable::One - bit_var,
                || lc!(),
            )?;

            reconstructed_lc += (coeff, bit_var);
            coeff.double_in_place();
        }

        // Enforce: sum(bit_i * 2^i) = value
        cs.enforce_r1cs_constraint(
            || reconstructed_lc,
            || lc!() + Variable::One,
            || lc!() + val,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_std::rand::{RngCore, SeedableRng};

    fn make_rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64())
    }

    #[test]
    fn test_poseidon_gadget_is_bound_to_output() {
        use ark_relations::gr1cs::ConstraintSystem;
        let params = PoseidonParams::<Fr>::default_2_to_1();
        let (l, r) = (Fr::from(3u64), Fr::from(4u64));
        let expected = poseidon_hash(l, r, &params);

        for (claimed, ok) in [(expected, true), (expected + Fr::from(1u64), false)] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let lv = cs.new_witness_variable(|| Ok(l)).unwrap();
            let rv = cs.new_witness_variable(|| Ok(r)).unwrap();
            let (h, h_val) =
                poseidon_gadget(&cs, (lc!() + lv, Some(l)), (lc!() + rv, Some(r)), &params)
                    .unwrap();
            assert_eq!(h_val, Some(expected));
            let out = cs.new_input_variable(|| Ok(claimed)).unwrap();
            cs.enforce_r1cs_constraint(|| h, || lc!() + Variable::One, || lc!() + out)
                .unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), ok);
        }
    }

    #[test]
    fn test_range_check_rejects_out_of_range() {
        use ark_relations::gr1cs::ConstraintSystem;
        let cs = ConstraintSystem::<Fr>::new_ref();
        RangeCheckCircuit::<Fr> {
            value: Some(Fr::from(300u64)),
            num_bits: 8,
        }
        .generate_constraints(cs.clone())
        .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_hash_native() {
        let params = PoseidonParams::<Fr>::default_2_to_1();
        let h = poseidon_hash(Fr::from(1u64), Fr::from(2u64), &params);
        let h2 = poseidon_hash(Fr::from(1u64), Fr::from(2u64), &params);
        assert_eq!(h, h2); // deterministic
        assert_ne!(h, Fr::from(0u64)); // non-trivial
    }

    #[test]
    fn test_poseidon_circuit() {
        let params = PoseidonParams::<Fr>::default_2_to_1();
        let left = Fr::from(42u64);
        let right = Fr::from(99u64);
        let output = poseidon_hash(left, right, &params);

        let circuit = PoseidonHashCircuit {
            left: Some(left),
            right: Some(right),
            params: params.clone(),
        };

        let mut rng = make_rng();
        let setup_circuit = PoseidonHashCircuit {
            left: None,
            right: None,
            params,
        };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[output], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_merkle_proof_circuit() {
        let params = PoseidonParams::<Fr>::default_2_to_1();

        let leaf = Fr::from(7u64);
        let sibling = Fr::from(13u64);
        let root = poseidon_hash(leaf, sibling, &params);

        let circuit = MerkleProofCircuit {
            leaf: Some(leaf),
            path: vec![Some(sibling)],
            path_indices: vec![Some(Fr::from(0u64))],
            params: params.clone(),
        };

        let mut rng = make_rng();
        let setup_circuit = MerkleProofCircuit {
            leaf: None,
            path: vec![None],
            path_indices: vec![None],
            params,
        };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[root], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_range_check_circuit() {
        let circuit = RangeCheckCircuit::<Fr> {
            value: Some(Fr::from(42u64)),
            num_bits: 8,
        };

        let mut rng = make_rng();
        let setup = RangeCheckCircuit::<Fr> {
            value: None,
            num_bits: 8,
        };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup, &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(42u64)], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_merkle_depth_3() {
        let params = PoseidonParams::<Fr>::default_2_to_1();

        let leaf = Fr::from(5u64);
        let s0 = Fr::from(10u64);
        let s1 = Fr::from(20u64);
        let s2 = Fr::from(30u64);

        let h0 = poseidon_hash(leaf, s0, &params);
        let h1 = poseidon_hash(h0, s1, &params);
        let root = poseidon_hash(h1, s2, &params);

        let circuit = MerkleProofCircuit {
            leaf: Some(leaf),
            path: vec![Some(s0), Some(s1), Some(s2)],
            path_indices: vec![
                Some(Fr::from(0u64)),
                Some(Fr::from(0u64)),
                Some(Fr::from(0u64)),
            ],
            params: params.clone(),
        };

        let setup = MerkleProofCircuit {
            leaf: None,
            path: vec![None, None, None],
            path_indices: vec![None, None, None],
            params,
        };

        let mut rng = make_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup, &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[root], &proof).unwrap();
        assert!(valid);
    }
}
