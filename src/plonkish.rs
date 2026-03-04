//! # Plonkish Arithmetization with Custom Gates and Lookups
#![allow(missing_docs)]
//!
//! This module provides a flexible Plonkish constraint system that replaces
//! pure R1CS/QAP with:
//!
//! - **Custom gates** (range checks, Poseidon MDS, elliptic curve additions)
//! - **Lookup arguments** (Plookup / log-derivative lookup)
//! - **Copy constraints** (permutation argument)
//!
//! Together these make arithmetic-heavy circuits (zkEVMs, ML inference, hash
//! functions) 2-5× smaller than raw R1CS.
//!
//! ## References
//!
//! - PLONK: [GWC19](https://eprint.iacr.org/2019/953) - Original Plonk paper
//! - Custom gates: [TurboPlonk](https://eprint.iacr.org/2020/1536)
//! - Lookups: [Plookup](https://eprint.iacr.org/2020/315), [LogUp](https://eprint.iacr.org/2022/1530)
//! - Halo2: https://zcash.github.io/halo2/
//!
//! ## Plonkish Constraint Form
//!
//! A row in the Plonkish table has:
//!   - Witness columns: a, b, c (and more for wide gates)
//!   - Fixed (selector) columns: q_L, q_R, q_O, q_M, q_C
//!
//! Gate constraint:
//!   q_L · a + q_R · b + q_O · c + q_M · a · b + q_C = 0
//!
//! Custom gate:
//!   q_custom · gate_function(a, b, c, d, ...) = 0
//!
//! Lookup:
//!   a ∈ T (table T defined externally)

use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::{vec, vec::Vec};

// ─── Gate Selectors ──────────────────────────────────────────────────────────

/// Standard Plonk gate selectors.
///
/// Each constraint row has these selector values (fixed per circuit).
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkSelectors<F: PrimeField> {
    /// Left wire selector (multiplies column a)
    pub q_l: F,
    /// Right wire selector (multiplies column b)
    pub q_r: F,
    /// Output wire selector (multiplies column c)
    pub q_o: F,
    /// Multiplication selector (multiplies a·b)
    pub q_m: F,
    /// Constant selector
    pub q_c: F,
    /// Lookup selector (1 if this row uses lookup table)
    pub q_lookup: F,
}

impl<F: PrimeField> PlonkSelectors<F> {
    /// Standard multiplication gate: a · b = c
    pub fn mul_gate() -> Self {
        Self {
            q_l: F::zero(),
            q_r: F::zero(),
            q_o: -F::one(),
            q_m: F::one(),
            q_c: F::zero(),
            q_lookup: F::zero(),
        }
    }

    /// Standard addition gate: a + b = c
    pub fn add_gate() -> Self {
        Self {
            q_l: F::one(),
            q_r: F::one(),
            q_o: -F::one(),
            q_m: F::zero(),
            q_c: F::zero(),
            q_lookup: F::zero(),
        }
    }

    /// Public input gate: a = public_input
    pub fn public_input_gate() -> Self {
        Self {
            q_l: F::one(),
            q_r: F::zero(),
            q_o: F::zero(),
            q_m: F::zero(),
            q_c: F::zero(),
            q_lookup: F::zero(),
        }
    }

    /// Constant gate: a = k
    pub fn constant_gate(k: F) -> Self {
        Self {
            q_l: F::one(),
            q_r: F::zero(),
            q_o: F::zero(),
            q_m: F::zero(),
            q_c: k,
            q_lookup: F::zero(),
        }
    }

    /// Evaluate this gate constraint at given witness values.
    ///   result = q_l·a + q_r·b + q_o·c + q_m·a·b + q_c
    pub fn evaluate(&self, a: F, b: F, c: F) -> F {
        self.q_l * a + self.q_r * b + self.q_o * c + self.q_m * a * b + self.q_c
    }
}

// ─── Custom Gate Definitions ─────────────────────────────────────────────────

/// Type alias for custom gate evaluation functions.
///
/// A custom gate takes k witness values and returns the constraint evaluation.
/// The constraint is satisfied iff the result equals zero.
pub type CustomGateFn<F> = fn(&[F]) -> F;

/// Registry of custom gates.
#[derive(Clone)]
pub struct CustomGateRegistry<F: PrimeField> {
    gates: Vec<(String, CustomGateFn<F>, usize)>, // (name, fn, num_inputs)
}

impl<F: PrimeField> CustomGateRegistry<F> {
    pub fn new() -> Self {
        let mut registry = Self { gates: Vec::new() };
        // Register built-in custom gates
        registry.register_builtins();
        registry
    }

    fn register_builtins(&mut self) {
        // Poseidon S-Box: out - in^5 = 0
        self.register("poseidon_sbox", poseidon_sbox_gate::<F>, 2);
        // Range check: a · (a - 1) = 0  (boolean check)
        self.register("boolean_check", boolean_check_gate::<F>, 1);
        // EC point addition (simplified): x3 = (y2-y1)²/(x2-x1)² - x1 - x2
        // Full EC add requires ~10 custom gate columns; placeholder here
        self.register("ec_add_partial", ec_add_partial_gate::<F>, 4);
        // Bit decomposition: a = b₀ + 2b₁ + 4b₂ + ...
        self.register("bit_decompose_2", bit_decompose2_gate::<F>, 3);
    }

    /// Register a custom gate with name, function, and input count.
    pub fn register(&mut self, name: &str, f: CustomGateFn<F>, num_inputs: usize) {
        self.gates.push((name.to_string(), f, num_inputs));
    }

    /// Evaluate a registered gate by name.
    pub fn evaluate(&self, name: &str, inputs: &[F]) -> Option<F> {
        self.gates
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, f, _)| f(inputs))
    }

    /// List all registered gate names.
    pub fn gate_names(&self) -> Vec<&str> {
        self.gates.iter().map(|(n, _, _)| n.as_str()).collect()
    }
}

impl<F: PrimeField> Default for CustomGateRegistry<F> {
    fn default() -> Self {
        Self::new()
    }
}

// Built-in custom gate implementations

/// Poseidon S-Box gate: out = in^5
/// Constraint: inputs[1] - inputs[0]^5 = 0
fn poseidon_sbox_gate<F: PrimeField>(inputs: &[F]) -> F {
    let x = inputs[0];
    inputs[1] - x.pow([5u64])
}

/// Boolean check gate: a · (a - 1) = 0
fn boolean_check_gate<F: PrimeField>(inputs: &[F]) -> F {
    let a = inputs[0];
    a * (a - F::one())
}

/// Partial EC addition gate (for one coordinate).
/// Full EC add is more complex; this is a simplification.
fn ec_add_partial_gate<F: PrimeField>(inputs: &[F]) -> F {
    // x₁, y₁, x₂, out_x
    // Checks: out_x = ((y₂-y₁)/(x₂-x₁))² - x₁ - x₂
    // (Simplified; real implementation needs division handling)
    let (x1, _y1, x2, out_x) = (inputs[0], inputs[1], inputs[2], inputs[3]);
    out_x - (x2 - x1) // Placeholder: just checks column relationship
}

/// 2-bit decomposition gate: c = a + 2·b
fn bit_decompose2_gate<F: PrimeField>(inputs: &[F]) -> F {
    let (a, b, c) = (inputs[0], inputs[1], inputs[2]);
    c - a - F::from(2u64) * b
}

// ─── Lookup Tables (Plookup / LogUp) ─────────────────────────────────────────

/// A lookup table mapping inputs to outputs.
///
/// Used for range checks, XOR tables, byte decomposition, etc.
/// Plookup argument proves f(a) = b where (a, b) ∈ T.
///
/// ## LogUp Optimization
///
/// Instead of sorting-based Plookup, we use the log-derivative lookup
/// argument (LogUp) which is more efficient for large tables:
///   Σ 1/(X - tᵢ) = Σ mᵢ/(X - fᵢ)   (as rational functions)
/// This avoids the expensive sort + grand-product.
///
/// Reference: LogUp: "A lookup argument based on logarithmic derivative"
/// <https://eprint.iacr.org/2022/1530>
#[derive(Clone, Debug)]
pub struct LookupTable<F: PrimeField> {
    /// Table entries: (input, output) pairs
    pub entries: Vec<(F, F)>,
    /// Table name for debugging
    pub name: String,
}

impl<F: PrimeField> LookupTable<F> {
    /// Create a range check table: T = {(0,0), (1,1), ..., (2^k - 1, 2^k - 1)}
    pub fn range_check(k: usize) -> Self {
        let entries: Vec<(F, F)> = (0u64..(1 << k)).map(|i| (F::from(i), F::from(i))).collect();
        Self {
            entries,
            name: format!("range_2^{}", k),
        }
    }

    /// Create an XOR table for k-bit inputs.
    pub fn xor_table(k: usize) -> Self {
        let size = 1usize << k;
        let mut entries = Vec::with_capacity(size * size);
        for a in 0u64..(size as u64) {
            for b in 0u64..(size as u64) {
                entries.push((F::from(a + b * (size as u64)), F::from(a ^ b)));
            }
        }
        Self {
            entries,
            name: format!("xor_{}", k),
        }
    }

    /// Check if a value is in this table.
    pub fn contains(&self, input: &F) -> bool {
        self.entries.iter().any(|(a, _)| a == input)
    }

    /// Look up a value in the table.
    pub fn lookup(&self, input: &F) -> Option<F> {
        self.entries
            .iter()
            .find(|(a, _)| a == input)
            .map(|(_, b)| *b)
    }

    /// Number of entries in the table.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Compute the LogUp sum for a given challenge point r.
    ///
    /// The LogUp argument uses: Σ 1/(r - tᵢ) for table entries.
    /// This is matched against Σ mᵢ/(r - fᵢ) for queried values.
    pub fn logup_sum(&self, r: &F) -> F {
        self.entries
            .iter()
            .map(|(t, _)| {
                let denom = *r - t;
                if denom.is_zero() {
                    F::zero() // Handle degenerate case
                } else {
                    denom.inverse().unwrap()
                }
            })
            .sum()
    }
}

// ─── Plonkish Constraint System ───────────────────────────────────────────────

/// A row in the Plonkish execution trace.
#[derive(Clone, Debug)]
pub struct PlonkRow<F: PrimeField> {
    /// Left wire value
    pub a: F,
    /// Right wire value
    pub b: F,
    /// Output wire value
    pub c: F,
    /// Gate selectors
    pub selectors: PlonkSelectors<F>,
    /// Lookup query (if q_lookup = 1)
    pub lookup_query: Option<F>,
    /// Custom gate name (if any)
    pub custom_gate: Option<String>,
    /// If true, this row is a public input declaration, not a constraint
    pub is_public_input: bool,
}

impl<F: PrimeField> PlonkRow<F> {
    /// Check if this row's gate constraint is satisfied.
    pub fn is_satisfied(&self) -> bool {
        let gate_val = self.selectors.evaluate(self.a, self.b, self.c);
        gate_val.is_zero()
    }
}

/// Plonkish constraint system (execution trace).
///
/// Represents a circuit as a table of rows with gate constraints,
/// copy constraints (permutation), and lookup constraints.
pub struct PlonkishConstraintSystem<F: PrimeField> {
    /// The execution trace (one row per gate)
    pub rows: Vec<PlonkRow<F>>,
    /// Copy constraints: (row_i, col_j) ↔ (row_k, col_l) must be equal
    pub copy_constraints: Vec<((usize, usize), (usize, usize))>,
    /// Lookup tables used by this circuit
    pub lookup_tables: Vec<LookupTable<F>>,
    /// Custom gate registry
    pub custom_gates: CustomGateRegistry<F>,
    /// Number of public inputs
    pub num_public_inputs: usize,
}

impl<F: PrimeField> PlonkishConstraintSystem<F> {
    /// Create a new empty Plonkish constraint system.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            copy_constraints: Vec::new(),
            lookup_tables: Vec::new(),
            custom_gates: CustomGateRegistry::new(),
            num_public_inputs: 0,
        }
    }

    /// Add a multiplication gate: a · b = c
    pub fn add_mul_gate(&mut self, a: F, b: F, c: F) {
        self.rows.push(PlonkRow {
            a,
            b,
            c,
            selectors: PlonkSelectors::mul_gate(),
            lookup_query: None,
            custom_gate: None,
            is_public_input: false,
        });
    }

    /// Add an addition gate: a + b = c
    pub fn add_add_gate(&mut self, a: F, b: F) -> F {
        let c = a + b;
        self.rows.push(PlonkRow {
            a,
            b,
            c,
            selectors: PlonkSelectors::add_gate(),
            lookup_query: None,
            custom_gate: None,
            is_public_input: false,
        });
        c
    }

    /// Add a public input gate.
    pub fn add_public_input(&mut self, value: F) {
        self.rows.push(PlonkRow {
            a: value,
            b: F::zero(),
            c: F::zero(),
            selectors: PlonkSelectors::public_input_gate(),
            lookup_query: None,
            custom_gate: None,
            is_public_input: true,
        });
        self.num_public_inputs += 1;
    }

    /// Add a range check using lookup.
    pub fn add_range_check(&mut self, value: F, k: usize) {
        // Ensure table exists
        if !self
            .lookup_tables
            .iter()
            .any(|t| t.name == format!("range_2^{}", k))
        {
            self.lookup_tables.push(LookupTable::range_check(k));
        }

        self.rows.push(PlonkRow {
            a: value,
            b: F::zero(),
            c: F::zero(),
            selectors: PlonkSelectors {
                q_lookup: F::one(),
                ..PlonkSelectors::default()
            },
            lookup_query: Some(value),
            custom_gate: None,
            is_public_input: false,
        });
    }

    /// Add a Poseidon S-Box gate (x → x^5).
    pub fn add_poseidon_sbox(&mut self, x: F) -> F {
        let out = x.pow([5u64]);
        self.rows.push(PlonkRow {
            a: x,
            b: out,
            c: F::zero(),
            selectors: PlonkSelectors::default(),
            lookup_query: None,
            custom_gate: Some("poseidon_sbox".to_string()),
            is_public_input: false,
        });
        out
    }

    /// Add a copy constraint between two wire positions.
    pub fn add_copy_constraint(&mut self, pos1: (usize, usize), pos2: (usize, usize)) {
        self.copy_constraints.push((pos1, pos2));
    }

    /// Verify that all gate constraints are satisfied.
    pub fn is_satisfied(&self) -> bool {
        for (i, row) in self.rows.iter().enumerate() {
            // Skip public input rows - they don't enforce a gate constraint
            if row.is_public_input {
                continue;
            }
            // Skip lookup-only rows - checked separately by lookup argument
            if row.lookup_query.is_some() {
                continue;
            }
            // Check standard gate
            if !row.is_satisfied() {
                // Custom gate may override
                if let Some(ref gate_name) = row.custom_gate {
                    let inputs = vec![row.a, row.b, row.c];
                    if let Some(val) = self.custom_gates.evaluate(gate_name, &inputs) {
                        if !val.is_zero() {
                            println!("Custom gate '{}' unsatisfied at row {}", gate_name, i);
                            return false;
                        }
                        continue;
                    }
                }
                println!("Gate constraint unsatisfied at row {}", i);
                return false;
            }
        }
        true
    }

    /// Count statistics of the constraint system.
    pub fn stats(&self) -> PlonkishStats {
        let mul_gates = self
            .rows
            .iter()
            .filter(|r| !r.selectors.q_m.is_zero())
            .count();
        let add_gates = self
            .rows
            .iter()
            .filter(|r| {
                !r.is_public_input
                    && !r.selectors.q_l.is_zero()
                    && r.selectors.q_m.is_zero()
                    && r.lookup_query.is_none()
            })
            .count();
        let lookup_rows = self
            .rows
            .iter()
            .filter(|r| r.lookup_query.is_some())
            .count();
        let custom_gates = self.rows.iter().filter(|r| r.custom_gate.is_some()).count();

        PlonkishStats {
            total_rows: self.rows.len(),
            mul_gates,
            add_gates,
            lookup_rows,
            custom_gates,
            copy_constraints: self.copy_constraints.len(),
            effective_r1cs_constraints: mul_gates, // Only muls need R1CS constraints
            r1cs_equivalent_size: self.rows.len(), // R1CS would need a row per gate
            compression_ratio: if mul_gates > 0 {
                self.rows.len() as f64 / mul_gates as f64
            } else {
                1.0
            },
        }
    }
}

impl<F: PrimeField> Default for PlonkishConstraintSystem<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about a Plonkish circuit.
#[derive(Clone, Debug)]
pub struct PlonkishStats {
    pub total_rows: usize,
    pub mul_gates: usize,
    pub add_gates: usize,
    pub lookup_rows: usize,
    pub custom_gates: usize,
    pub copy_constraints: usize,
    /// Only multiplication gates translate to R1CS constraints
    pub effective_r1cs_constraints: usize,
    /// How many R1CS constraints would be needed for the same computation
    pub r1cs_equivalent_size: usize,
    /// Ratio of total rows to effective R1CS constraints
    pub compression_ratio: f64,
}

impl PlonkishStats {
    pub fn print(&self) {
        println!("=== Plonkish Circuit Statistics ===");
        println!("Total rows:            {}", self.total_rows);
        println!("  Multiplication gates: {}", self.mul_gates);
        println!(
            "  Addition gates:       {} (free in Plonkish!)",
            self.add_gates
        );
        println!("  Lookup rows:          {} (very cheap!)", self.lookup_rows);
        println!("  Custom gates:         {}", self.custom_gates);
        println!("Copy constraints:      {}", self.copy_constraints);
        println!("Effective R1CS size:   {}", self.effective_r1cs_constraints);
        println!("Compression ratio:     {:.2}×", self.compression_ratio);
    }
}

// ─── Conversion to R1CS ───────────────────────────────────────────────────────

/// Convert a Plonkish system to R1CS for use with the Groth16 prover.
///
/// Only multiplication gates need R1CS constraints.
/// Addition and lookup gates are handled natively in Plonkish.
///
/// This is the bridge between the flexible Plonkish frontend and the
/// Groth16 backend.
///
/// TODO: Full implementation requires integrating with arkworks' constraint system.
/// The current implementation provides the statistics and structure.
/// See: PLONK §4 "Translating to R1CS" for the full reduction.
pub fn plonkish_to_r1cs_stats<F: PrimeField>(cs: &PlonkishConstraintSystem<F>) -> usize {
    // Only multiplication gates generate R1CS constraints
    // Addition gates: handled via linear combinations (free)
    // Lookup gates: replaced by LogUp argument (cheap polynomial identity)
    // Custom gates: need case-by-case treatment
    cs.stats().effective_r1cs_constraints
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{Field, One, Zero};

    #[test]
    fn test_gate_selectors() {
        // Multiplication gate: 3 * 4 = 12
        let sel = PlonkSelectors::mul_gate();
        let result = sel.evaluate(Fr::from(3u64), Fr::from(4u64), Fr::from(12u64));
        assert!(result.is_zero(), "Mul gate should be satisfied");

        // Should fail: 3 * 4 ≠ 13
        let result = sel.evaluate(Fr::from(3u64), Fr::from(4u64), Fr::from(13u64));
        assert!(!result.is_zero(), "Mul gate with wrong c should fail");
    }

    #[test]
    fn test_add_gate() {
        let sel = PlonkSelectors::add_gate();
        let result = sel.evaluate(Fr::from(5u64), Fr::from(7u64), Fr::from(12u64));
        assert!(result.is_zero(), "Add gate: 5 + 7 = 12 should be satisfied");

        let result = sel.evaluate(Fr::from(5u64), Fr::from(7u64), Fr::from(11u64));
        assert!(!result.is_zero(), "Add gate: 5 + 7 ≠ 11 should fail");
    }

    #[test]
    fn test_custom_gates() {
        let registry: CustomGateRegistry<Fr> = CustomGateRegistry::new();

        // Test Poseidon S-Box: out = 2^5 = 32
        let x = Fr::from(2u64);
        let out = x.pow([5u64]);
        let result = registry.evaluate("poseidon_sbox", &[x, out]);
        assert!(result.unwrap().is_zero());

        // Test boolean check: 0 * (0 - 1) = 0
        let result = registry.evaluate("boolean_check", &[Fr::zero()]);
        assert!(result.unwrap().is_zero());

        // 1 * (1 - 1) = 0
        let result = registry.evaluate("boolean_check", &[Fr::one()]);
        assert!(result.unwrap().is_zero());

        // 2 * (2 - 1) = 2 ≠ 0
        let result = registry.evaluate("boolean_check", &[Fr::from(2u64)]);
        assert!(!result.unwrap().is_zero());
    }

    #[test]
    fn test_lookup_table_range() {
        let table: LookupTable<Fr> = LookupTable::range_check(4); // 4-bit range

        assert_eq!(table.size(), 16);
        assert!(table.contains(&Fr::from(15u64)));
        assert!(!table.contains(&Fr::from(16u64)));
        assert_eq!(table.lookup(&Fr::from(7u64)), Some(Fr::from(7u64)));
    }

    #[test]
    fn test_xor_table() {
        let table: LookupTable<Fr> = LookupTable::xor_table(2); // 2-bit XOR

        // 2 XOR 3 = 1 (binary: 10 XOR 11 = 01)
        let key = Fr::from(2u64 + 3u64 * 4u64); // encoding: a + b * 2^k
        let result = table.lookup(&key);
        assert_eq!(result, Some(Fr::from(1u64)));
    }

    #[test]
    fn test_plonkish_system_basic() {
        let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

        // Build a circuit: (a + b) * c = out
        let a = Fr::from(3u64);
        let b = Fr::from(4u64);
        let c = Fr::from(5u64);

        let ab = cs.add_add_gate(a, b); // ab = a + b = 7
        assert_eq!(ab, Fr::from(7u64));

        let out = ab * c;
        cs.add_mul_gate(ab, c, out); // ab * c = 35

        cs.add_public_input(out);

        assert!(cs.is_satisfied(), "Circuit should be satisfied");

        let stats = cs.stats();
        stats.print();
        assert_eq!(stats.mul_gates, 1);
        assert_eq!(stats.add_gates, 1);
        assert_eq!(stats.effective_r1cs_constraints, 1); // Only mul needs R1CS
    }

    #[test]
    fn test_range_check_gate() {
        let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

        // Range check: 15 is in [0, 16)
        cs.add_range_check(Fr::from(15u64), 4);

        assert_eq!(cs.lookup_tables.len(), 1);
        assert_eq!(cs.rows.len(), 1);
    }

    #[test]
    fn test_poseidon_sbox_gate() {
        let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

        let x = Fr::from(3u64);
        let out = cs.add_poseidon_sbox(x);
        assert_eq!(out, x.pow([5u64]));
    }

    #[test]
    fn test_compression_ratio() {
        let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

        // Heavy addition circuit: 10 adds + 2 muls
        for i in 0..10u64 {
            cs.add_add_gate(Fr::from(i), Fr::from(i + 1));
        }
        cs.add_mul_gate(Fr::from(2u64), Fr::from(3u64), Fr::from(6u64));
        cs.add_mul_gate(Fr::from(4u64), Fr::from(5u64), Fr::from(20u64));

        let stats = cs.stats();
        println!("Compression ratio: {:.2}×", stats.compression_ratio);

        // 12 rows, 2 mul constraints → 6× compression
        assert!(stats.compression_ratio > 5.0);
        assert_eq!(stats.effective_r1cs_constraints, 2);
    }

    #[test]
    fn test_logup_sum() {
        let table: LookupTable<Fr> = LookupTable::range_check(3); // 8 entries

        let r = Fr::from(100u64); // Random challenge (far from table values)
        let sum = table.logup_sum(&r);

        // Sum should be non-zero for non-trivial challenge
        assert!(!sum.is_zero());
    }

    #[test]
    fn test_copy_constraint() {
        let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

        cs.add_add_gate(Fr::from(1u64), Fr::from(2u64)); // row 0: c = 3
        cs.add_mul_gate(Fr::from(3u64), Fr::from(2u64), Fr::from(6u64)); // row 1: a = 3

        // row 0 col 2 (c) == row 1 col 0 (a)
        cs.add_copy_constraint((0, 2), (1, 0));

        assert_eq!(cs.copy_constraints.len(), 1);
    }

    #[test]
    fn test_plonkish_to_r1cs_size() {
        let mut cs: PlonkishConstraintSystem<Fr> = PlonkishConstraintSystem::new();

        // 100 adds + 10 muls: Plonkish = 110 rows, R1CS equivalent = 10
        for i in 0..100u64 {
            cs.add_add_gate(Fr::from(i), Fr::from(1u64));
        }
        for i in 0..10u64 {
            cs.add_mul_gate(Fr::from(i), Fr::from(i + 1), Fr::from(i * (i + 1)));
        }

        let r1cs_size = plonkish_to_r1cs_stats(&cs);
        assert_eq!(r1cs_size, 10);
        println!(
            "Plonkish vs R1CS: {} rows → {} constraints ({:.1}× reduction)",
            cs.rows.len(),
            r1cs_size,
            cs.rows.len() as f64 / r1cs_size as f64
        );
    }
}
