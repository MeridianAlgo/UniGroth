//! # Ergonomic Circuit Builder SDK
#![allow(missing_docs)]
//!
//! High-level API for building arithmetic circuits without directly
//! manipulating R1CS constraints. Provides a fluent interface for:
//!
//! - Arithmetic operations (add, mul, assert_equal)
//! - Boolean constraints
//! - Range checks
//! - Conditional selection
//! - Public input/output declaration
//!
//! The builder compiles down to R1CS constraints compatible with
//! the Groth16/UniGroth prover.

use ark_ff::PrimeField;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use ark_std::vec::Vec;

/// A wire in the circuit, representing a field element.
#[derive(Clone, Copy, Debug)]
pub struct Wire {
    index: usize,
}

/// Operation recorded by the builder for deferred constraint generation.
#[derive(Clone, Debug)]
enum Op<F: PrimeField> {
    AllocWitness {
        index: usize,
        value: Option<F>,
    },
    AllocPublic {
        index: usize,
        value: Option<F>,
    },
    MulConstraint {
        a: usize,
        b: usize,
        c: usize,
    },
    AddConstraint {
        a: usize,
        b: usize,
        c: usize,
    },
    ConstMul {
        input: usize,
        scalar: F,
        output: usize,
    },
    AssertEqual {
        a: usize,
        b: usize,
    },
    AssertBool {
        a: usize,
    },
    ConditionalSelect {
        cond: usize,
        a: usize,
        b: usize,
        out: usize,
    },
}

/// Ergonomic circuit builder.
///
/// # Example
/// ```rust,ignore
/// let mut builder = CircuitBuilder::new();
/// let x = builder.witness(Some(Fr::from(3)));
/// let y = builder.witness(Some(Fr::from(4)));
/// let xy = builder.mul(x, y);
/// builder.public_output(xy);
/// ```
pub struct CircuitBuilder<F: PrimeField> {
    ops: Vec<Op<F>>,
    wire_count: usize,
    wire_values: Vec<Option<F>>,
}

impl<F: PrimeField> Default for CircuitBuilder<F> {
    fn default() -> Self {
        Self {
            ops: Vec::new(),
            wire_count: 0,
            wire_values: Vec::new(),
        }
    }
}

impl<F: PrimeField> CircuitBuilder<F> {
    /// Create a new empty circuit builder.
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc_wire(&mut self, value: Option<F>) -> usize {
        let idx = self.wire_count;
        self.wire_count += 1;
        self.wire_values.push(value);
        idx
    }

    /// Allocate a private witness wire.
    pub fn witness(&mut self, value: Option<F>) -> Wire {
        let idx = self.alloc_wire(value);
        self.ops.push(Op::AllocWitness { index: idx, value });
        Wire { index: idx }
    }

    /// Allocate a public input wire.
    pub fn public_input(&mut self, value: Option<F>) -> Wire {
        let idx = self.alloc_wire(value);
        self.ops.push(Op::AllocPublic { index: idx, value });
        Wire { index: idx }
    }

    /// Constrain c = a * b and return wire c.
    pub fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        let c_val = match (self.wire_values[a.index], self.wire_values[b.index]) {
            (Some(av), Some(bv)) => Some(av * bv),
            _ => None,
        };
        let c_idx = self.alloc_wire(c_val);
        self.ops.push(Op::AllocWitness {
            index: c_idx,
            value: c_val,
        });
        self.ops.push(Op::MulConstraint {
            a: a.index,
            b: b.index,
            c: c_idx,
        });
        Wire { index: c_idx }
    }

    /// Constrain c = a + b and return wire c.
    pub fn add(&mut self, a: Wire, b: Wire) -> Wire {
        let c_val = match (self.wire_values[a.index], self.wire_values[b.index]) {
            (Some(av), Some(bv)) => Some(av + bv),
            _ => None,
        };
        let c_idx = self.alloc_wire(c_val);
        self.ops.push(Op::AllocWitness {
            index: c_idx,
            value: c_val,
        });
        self.ops.push(Op::AddConstraint {
            a: a.index,
            b: b.index,
            c: c_idx,
        });
        Wire { index: c_idx }
    }

    /// Constrain output = scalar * input and return output wire.
    pub fn const_mul(&mut self, input: Wire, scalar: F) -> Wire {
        let out_val = self.wire_values[input.index].map(|v| v * scalar);
        let out_idx = self.alloc_wire(out_val);
        self.ops.push(Op::AllocWitness {
            index: out_idx,
            value: out_val,
        });
        self.ops.push(Op::ConstMul {
            input: input.index,
            scalar,
            output: out_idx,
        });
        Wire { index: out_idx }
    }

    /// Assert a == b.
    pub fn assert_equal(&mut self, a: Wire, b: Wire) {
        self.ops.push(Op::AssertEqual {
            a: a.index,
            b: b.index,
        });
    }

    /// Assert wire is boolean (0 or 1).
    pub fn assert_bool(&mut self, a: Wire) {
        self.ops.push(Op::AssertBool { a: a.index });
    }

    /// Conditional select: out = cond ? a : b (cond must be boolean).
    pub fn conditional_select(&mut self, cond: Wire, a: Wire, b: Wire) -> Wire {
        let out_val = match (
            self.wire_values[cond.index],
            self.wire_values[a.index],
            self.wire_values[b.index],
        ) {
            (Some(c), Some(av), Some(bv)) => {
                if c == F::one() {
                    Some(av)
                } else {
                    Some(bv)
                }
            },
            _ => None,
        };
        let out_idx = self.alloc_wire(out_val);
        self.ops.push(Op::AllocWitness {
            index: out_idx,
            value: out_val,
        });
        self.ops.push(Op::ConditionalSelect {
            cond: cond.index,
            a: a.index,
            b: b.index,
            out: out_idx,
        });
        Wire { index: out_idx }
    }

    /// Declare a wire as public output (creates a public input constraint).
    pub fn public_output(&mut self, wire: Wire) -> Wire {
        let val = self.wire_values[wire.index];
        let pub_idx = self.alloc_wire(val);
        self.ops.push(Op::AllocPublic {
            index: pub_idx,
            value: val,
        });
        self.ops.push(Op::AssertEqual {
            a: wire.index,
            b: pub_idx,
        });
        Wire { index: pub_idx }
    }

    /// Return circuit stats.
    pub fn stats(&self) -> CircuitStats {
        let mut mul_gates = 0;
        let mut add_gates = 0;
        let mut witnesses = 0;
        let mut public_inputs = 0;

        for op in &self.ops {
            match op {
                Op::AllocWitness { .. } => witnesses += 1,
                Op::AllocPublic { .. } => public_inputs += 1,
                Op::MulConstraint { .. } => mul_gates += 1,
                Op::AddConstraint { .. } => add_gates += 1,
                _ => {},
            }
        }

        CircuitStats {
            total_wires: self.wire_count,
            witnesses,
            public_inputs,
            mul_gates,
            add_gates,
            total_constraints: mul_gates + add_gates,
        }
    }

    /// Build into a ConstraintSynthesizer that can be passed to Groth16.
    pub fn build(self) -> BuiltCircuit<F> {
        BuiltCircuit {
            ops: self.ops,
            wire_values: self.wire_values,
            wire_count: self.wire_count,
        }
    }
}

/// Circuit stats from the builder.
#[derive(Clone, Debug)]
pub struct CircuitStats {
    pub total_wires: usize,
    pub witnesses: usize,
    pub public_inputs: usize,
    pub mul_gates: usize,
    pub add_gates: usize,
    pub total_constraints: usize,
}

/// A compiled circuit ready for proving.
#[derive(Clone)]
#[allow(dead_code)]
pub struct BuiltCircuit<F: PrimeField> {
    ops: Vec<Op<F>>,
    wire_values: Vec<Option<F>>,
    wire_count: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for BuiltCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut vars: Vec<Variable> = Vec::with_capacity(self.wire_count);

        for op in &self.ops {
            match op {
                Op::AllocWitness { index, value } => {
                    let v = *value;
                    let var =
                        cs.new_witness_variable(|| v.ok_or(SynthesisError::AssignmentMissing))?;
                    while vars.len() <= *index {
                        vars.push(Variable::One);
                    }
                    vars[*index] = var;
                },
                Op::AllocPublic { index, value } => {
                    let v = *value;
                    let var =
                        cs.new_input_variable(|| v.ok_or(SynthesisError::AssignmentMissing))?;
                    while vars.len() <= *index {
                        vars.push(Variable::One);
                    }
                    vars[*index] = var;
                },
                Op::MulConstraint { a, b, c } => {
                    cs.enforce_r1cs_constraint(
                        || lc!() + vars[*a],
                        || lc!() + vars[*b],
                        || lc!() + vars[*c],
                    )?;
                },
                Op::AddConstraint { a, b, c } => {
                    cs.enforce_r1cs_constraint(
                        || lc!() + vars[*a] + vars[*b],
                        || lc!() + Variable::One,
                        || lc!() + vars[*c],
                    )?;
                },
                Op::ConstMul {
                    input,
                    scalar,
                    output,
                } => {
                    cs.enforce_r1cs_constraint(
                        || lc!() + vars[*input],
                        || lc!() + (*scalar, Variable::One),
                        || lc!() + vars[*output],
                    )?;
                },
                Op::AssertEqual { a, b } => {
                    cs.enforce_r1cs_constraint(
                        || lc!() + vars[*a] - vars[*b],
                        || lc!() + Variable::One,
                        || lc!(),
                    )?;
                },
                Op::AssertBool { a } => {
                    cs.enforce_r1cs_constraint(
                        || lc!() + vars[*a],
                        || lc!() + Variable::One - vars[*a],
                        || lc!(),
                    )?;
                },
                Op::ConditionalSelect { cond, a, b, out } => {
                    cs.enforce_r1cs_constraint(
                        || lc!() + vars[*cond],
                        || lc!() + vars[*a] - vars[*b],
                        || lc!() + vars[*out] - vars[*b],
                    )?;
                },
            }
        }

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
    fn test_builder_mul_circuit() {
        let mut builder = CircuitBuilder::<Fr>::new();
        let a = builder.witness(Some(Fr::from(3u64)));
        let b = builder.witness(Some(Fr::from(7u64)));
        let c = builder.mul(a, b);
        let _out = builder.public_output(c);

        let stats = builder.stats();
        assert_eq!(stats.mul_gates, 1);

        let circuit = builder.build();
        let mut rng = make_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(21u64)], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_builder_add_circuit() {
        let mut builder = CircuitBuilder::<Fr>::new();
        let a = builder.witness(Some(Fr::from(10u64)));
        let b = builder.witness(Some(Fr::from(20u64)));
        let c = builder.add(a, b);
        let _out = builder.public_output(c);

        let circuit = builder.build();
        let mut rng = make_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(30u64)], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_builder_conditional_select() {
        let mut builder = CircuitBuilder::<Fr>::new();
        let cond = builder.witness(Some(Fr::from(1u64)));
        builder.assert_bool(cond);
        let a = builder.witness(Some(Fr::from(42u64)));
        let b = builder.witness(Some(Fr::from(99u64)));
        let out = builder.conditional_select(cond, a, b);
        let _pub = builder.public_output(out);

        let circuit = builder.build();
        let mut rng = make_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(42u64)], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_builder_const_mul() {
        let mut builder = CircuitBuilder::<Fr>::new();
        let x = builder.witness(Some(Fr::from(5u64)));
        let scaled = builder.const_mul(x, Fr::from(7u64));
        let _out = builder.public_output(scaled);

        let circuit = builder.build();
        let mut rng = make_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(35u64)], &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_builder_stats() {
        let mut builder = CircuitBuilder::<Fr>::new();
        let a = builder.witness(Some(Fr::from(1u64)));
        let b = builder.witness(Some(Fr::from(2u64)));
        let _c = builder.mul(a, b);
        let _d = builder.add(a, b);

        let stats = builder.stats();
        assert_eq!(stats.mul_gates, 1);
        assert_eq!(stats.add_gates, 1);
        assert_eq!(stats.total_constraints, 2);
    }
}
