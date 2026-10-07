//! # Lookup Arguments: Plookup + LogUp
#![allow(missing_docs)]
//!
//! Reference implementations of two lookup identities that show a query
//! vector is a subset of a table:
//!
//! - **Plookup** (Gabizon-Williamson-Ciobotaru 2020): grand-product argument
//!   over the sorted union s = sort(f ∪ T). O(n log n) prover (dominated by sort).
//!
//! - **LogUp** (Haböck 2022): log-derivative multiset argument. Reduces to
//!   ∑ 1/(f_i + γ) = ∑ m_j/(t_j + γ). O(n) prover, multi-table capable.
//!
//! ## Performance vs competitors
//!
//! | System   | Lookup complexity | Multi-table |
//! |----------|------------------|-------------|
//! | Plookup  | O(n log n) sort  | No          |
//! | LogUp    | O(n) scan        | Yes         |
//! | Lasso    | O(n) sumcheck    | Yes (Jolt)  |
//!
//! ## Scope
//!
//! The verifiers here receive the table and every query in the clear, so they
//! hide nothing and are not succinct: they check the same identities a SNARK
//! would check inside a polynomial IOP. Their challenges β, γ are derived by
//! Fiat-Shamir from the table, queries and proof, never taken from a caller,
//! because a prover who picks γ can make LogUp accept values outside the table.

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use sha2::{Digest, Sha256};

/// Fiat-Shamir challenges bound to everything the verifier is about to check.
fn lookup_challenges<F: PrimeField>(label: &[u8], parts: &[&dyn ErasedSerialize]) -> (F, F) {
    let mut h = Sha256::new()
        .chain_update(crate::config::DOMAIN_LOOKUP)
        .chain_update(label);
    for part in parts {
        let bytes = part.bytes();
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    let draw = |tag: u8| {
        let lo = h.clone().chain_update([tag, 0]).finalize();
        let hi = h.clone().chain_update([tag, 1]).finalize();
        F::from_le_bytes_mod_order(&[lo.as_slice(), hi.as_slice()].concat())
    };
    (draw(0), draw(1))
}

/// Object-safe "serialize me" so challenge inputs of different types can be listed together.
trait ErasedSerialize {
    fn bytes(&self) -> Vec<u8>;
}

impl<T: CanonicalSerialize + ?Sized> ErasedSerialize for T {
    fn bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_compressed(&mut buf)
            .expect("serializing to a Vec cannot fail");
        buf
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from lookup argument construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// Query at given index is not present in the table.
    QueryNotInTable(usize),
    /// Table entries must be sorted (ascending) for Plookup.
    TableNotSorted,
    /// Table index out of bounds in multi-table lookup.
    TableIndexOutOfBounds(usize),
    /// Table must have at least one entry.
    EmptyTable,
    /// Query vector must be non-empty.
    EmptyQueries,
    /// Division by zero in field inverse (degenerate gamma).
    ZeroDenominator,
}

// ─── Table ───────────────────────────────────────────────────────────────────

/// A lookup table: the set of values a prover is allowed to query.
///
/// For Plookup the entries must be **sorted ascending**. For LogUp they may
/// be in any order but duplicates inflate multiplicity counts.
#[derive(Clone, Debug)]
pub struct LookupTable<F: PrimeField> {
    /// Table entries. Must be sorted for Plookup.
    pub entries: Vec<F>,
}

impl<F: PrimeField> LookupTable<F> {
    /// Create from an already-sorted entry vector.
    pub fn new_sorted(entries: Vec<F>) -> Result<Self, LookupError> {
        if entries.is_empty() {
            return Err(LookupError::EmptyTable);
        }
        for w in entries.windows(2) {
            if w[0] > w[1] {
                return Err(LookupError::TableNotSorted);
            }
        }
        Ok(Self { entries })
    }

    /// Create from an unsorted entry vector (sorts internally).
    pub fn new(mut entries: Vec<F>) -> Result<Self, LookupError> {
        if entries.is_empty() {
            return Err(LookupError::EmptyTable);
        }
        entries.sort();
        Ok(Self { entries })
    }

    /// Binary-search membership check.
    pub fn contains(&self, v: &F) -> bool {
        self.entries.binary_search(v).is_ok()
    }

    /// Return the position of `v` in the table, or None.
    pub fn position(&self, v: &F) -> Option<usize> {
        self.entries.binary_search(v).ok()
    }
}

/// Build a range-check table [0, max_val] (inclusive) as field elements.
///
/// Useful for constraining witness values to a fixed bit-width:
/// e.g. `range_table(255)` enforces 8-bit values.
pub fn range_table<F: PrimeField>(max_val: u64) -> LookupTable<F> {
    let entries: Vec<F> = (0..=max_val).map(F::from).collect();
    // Already sorted by construction.
    LookupTable { entries }
}

// ─── Plookup ─────────────────────────────────────────────────────────────────

/// Plookup proof: the sorted union s = sort(f ∪ t) of length |f| + |t|.
///
/// ## Correctness
///
/// The verifier checks the Plookup product identity (Gabizon-Williamson-Ciobotaru 2020):
///
/// ```text
/// ∏_{i=0}^{n-1} (1+β)(γ+f_i) · ∏_{j=0}^{m-2} (γ(1+β)+t_j+β·t_{j+1})
/// = ∏_{k=0}^{n+m-2} (γ(1+β)+s_k+β·s_{k+1})
/// ```
///
/// where n = |f|, m = |t|, and s = sort(f ∥ t). Both sides have n+m-1 factors.
/// A valid lookup iff LHS == RHS for random β, γ.
#[derive(Clone, Debug)]
pub struct PlookupProof<F: PrimeField> {
    /// Sorted concatenation s = sort(f ∪ t). Length = |queries| + |table|.
    pub sorted: Vec<F>,
}

/// Prove that every element of `queries` appears in `table`.
///
/// Builds the sorted union s = sort(f ∪ t).
///
/// # Errors
/// Returns `LookupError::QueryNotInTable(i)` if `queries[i] ∉ table`.
pub fn prove_plookup<F: PrimeField>(
    table: &LookupTable<F>,
    queries: &[F],
) -> Result<PlookupProof<F>, LookupError> {
    if queries.is_empty() {
        return Err(LookupError::EmptyQueries);
    }
    // Validate: every query must be in table.
    for (i, q) in queries.iter().enumerate() {
        if !table.contains(q) {
            return Err(LookupError::QueryNotInTable(i));
        }
    }
    // s = sort(f ∥ t) — the prover's only commitment.
    let mut s: Vec<F> = queries
        .iter()
        .chain(table.entries.iter())
        .copied()
        .collect();
    s.sort();
    Ok(PlookupProof { sorted: s })
}

/// Verify a Plookup proof using the product identity.
///
/// Checks:
/// ```text
/// ∏(1+β)(γ+f_i) · ∏(γ(1+β)+t_j+β·t_{j+1}) == ∏(γ(1+β)+s_k+β·s_{k+1})
/// ```
/// with β, γ derived by Fiat-Shamir. Returns `false` on mismatch.
pub fn verify_plookup<F: PrimeField>(
    table: &LookupTable<F>,
    queries: &[F],
    proof: &PlookupProof<F>,
) -> bool {
    if queries.is_empty() || proof.sorted.is_empty() {
        return false;
    }
    let t = &table.entries;
    let n = queries.len();
    let m = t.len();
    if m < 1 {
        return false;
    }
    // Sorted union must have the right length.
    if proof.sorted.len() != n + m {
        return false;
    }

    let (beta, gamma): (F, F) =
        lookup_challenges(b"plookup", &[&table.entries, &queries, &proof.sorted]);
    let one_plus_beta = F::one() + beta;
    let gamma_opb = gamma * one_plus_beta; // γ(1+β)

    // LHS part 1: ∏_{i=0..n-1} (1+β)(γ+f_i)
    let mut lhs = F::one();
    for &fi in queries {
        lhs *= one_plus_beta * (gamma + fi);
    }
    // LHS part 2: ∏_{j=0..m-2} (γ(1+β)+t_j+β·t_{j+1})
    for j in 0..m.saturating_sub(1) {
        lhs *= gamma_opb + t[j] + beta * t[j + 1];
    }

    // RHS: ∏_{k=0..n+m-2} (γ(1+β)+s_k+β·s_{k+1})
    let s = &proof.sorted;
    let mut rhs = F::one();
    for k in 0..(n + m).saturating_sub(1) {
        rhs *= gamma_opb + s[k] + beta * s[k + 1];
    }

    lhs == rhs
}

// ─── LogUp ───────────────────────────────────────────────────────────────────

/// LogUp witness: multiplicity of each table entry in the query vector.
///
/// `multiplicities[j]` = number of times `table.entries[j]` appears in queries.
#[derive(Clone, Debug)]
pub struct LogUpWitness {
    pub multiplicities: Vec<usize>,
}

/// Prove that `queries ⊆ table` via the log-derivative multiset argument.
///
/// Returns the multiplicity vector. O(n) where n = |queries|.
///
/// # Errors
/// Returns `LookupError::QueryNotInTable(i)` if `queries[i] ∉ table`.
pub fn prove_logup<F: PrimeField>(
    table: &LookupTable<F>,
    queries: &[F],
) -> Result<LogUpWitness, LookupError> {
    if queries.is_empty() {
        return Err(LookupError::EmptyQueries);
    }

    let mut multiplicities = vec![0usize; table.entries.len()];

    for (i, q) in queries.iter().enumerate() {
        match table.position(q) {
            Some(j) => multiplicities[j] += 1,
            None => return Err(LookupError::QueryNotInTable(i)),
        }
    }

    Ok(LogUpWitness { multiplicities })
}

/// Verify a LogUp witness.
///
/// Checks ∑_i 1/(f_i + γ) == ∑_j m_j/(t_j + γ) with γ derived by
/// Fiat-Shamir from the table, queries and multiplicities.
pub fn verify_logup<F: PrimeField>(
    table: &LookupTable<F>,
    queries: &[F],
    witness: &LogUpWitness,
) -> bool {
    if witness.multiplicities.len() != table.entries.len() {
        return false;
    }
    // Multiplicities must sum to the number of queries; this also keeps every
    // m_j below the field characteristic, which LogUp's soundness needs.
    if witness
        .multiplicities
        .iter()
        .try_fold(0usize, |a, &m| a.checked_add(m))
        != Some(queries.len())
    {
        return false;
    }
    let mults: Vec<u64> = witness.multiplicities.iter().map(|&m| m as u64).collect();
    let (gamma, _): (F, F) = lookup_challenges(b"logup", &[&table.entries, &queries, &mults]);

    // LHS: ∑_i 1/(f_i + γ)
    let mut lhs = F::zero();
    for &fi in queries {
        let denom = fi + gamma;
        match denom.inverse() {
            Some(d) => lhs += d,
            None => return false, // γ = -f_i is a bad challenge
        }
    }

    // RHS: ∑_j m_j/(t_j + γ)
    let mut rhs = F::zero();
    for (j, &tj) in table.entries.iter().enumerate() {
        let mj = witness.multiplicities[j];
        if mj == 0 {
            continue;
        }
        let denom = tj + gamma;
        match denom.inverse() {
            Some(d) => rhs += F::from(mj as u64) * d,
            None => return false,
        }
    }

    lhs == rhs
}

// ─── Multi-Table LogUp ────────────────────────────────────────────────────────

/// A collection of lookup tables for multi-table LogUp.
pub struct MultiTableLookup<F: PrimeField> {
    pub tables: Vec<LookupTable<F>>,
}

impl<F: PrimeField> MultiTableLookup<F> {
    pub fn new(tables: Vec<LookupTable<F>>) -> Self {
        Self { tables }
    }
}

/// Prove `queries ⊆ tables[table_idx]` for each (table_idx, value) pair.
///
/// Returns one `LogUpWitness` per table.
pub fn prove_multi_table_logup<F: PrimeField>(
    multi: &MultiTableLookup<F>,
    queries: &[(usize, F)],
) -> Result<Vec<LogUpWitness>, LookupError> {
    if queries.is_empty() {
        return Err(LookupError::EmptyQueries);
    }

    let mut witnesses: Vec<LogUpWitness> = multi
        .tables
        .iter()
        .map(|t| LogUpWitness {
            multiplicities: vec![0usize; t.entries.len()],
        })
        .collect();

    for (i, &(table_idx, ref val)) in queries.iter().enumerate() {
        if table_idx >= multi.tables.len() {
            return Err(LookupError::TableIndexOutOfBounds(table_idx));
        }
        let table = &multi.tables[table_idx];
        match table.position(val) {
            Some(j) => witnesses[table_idx].multiplicities[j] += 1,
            None => return Err(LookupError::QueryNotInTable(i)),
        }
    }

    Ok(witnesses)
}

/// Verify multi-table LogUp witnesses.
///
/// Checks the log-derivative identity per table, each with its own
/// Fiat-Shamir challenge.
pub fn verify_multi_table_logup<F: PrimeField>(
    multi: &MultiTableLookup<F>,
    queries: &[(usize, F)],
    witnesses: &[LogUpWitness],
) -> bool {
    if witnesses.len() != multi.tables.len() {
        return false;
    }

    // Split queries per table.
    let mut per_table_queries: Vec<Vec<F>> = vec![Vec::new(); multi.tables.len()];
    for &(table_idx, ref val) in queries {
        if table_idx >= multi.tables.len() {
            return false;
        }
        per_table_queries[table_idx].push(*val);
    }

    // Verify each table independently.
    for (idx, (table, witness)) in multi.tables.iter().zip(witnesses.iter()).enumerate() {
        let qs = &per_table_queries[idx];
        if qs.is_empty() {
            // No queries for this table — witness must be all zeros.
            if witness.multiplicities.iter().any(|&m| m != 0) {
                return false;
            }
            continue;
        }
        if !verify_logup(table, qs, witness) {
            return false;
        }
    }
    true
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Field;

    /// With a caller-chosen γ, LogUp accepts a value outside the table: for
    /// table {t₀} and query f, multiplicity 2 and γ = t₀ − 2f satisfy
    /// 1/(f+γ) = 2/(t₀+γ). With Fiat-Shamir γ the same witness is rejected.
    #[test]
    fn test_logup_forgery_needs_chosen_gamma() {
        let (t0, f) = (Fr::from(0u64), Fr::from(5u64));
        let gamma = t0 - f - f;
        assert_eq!(
            (f + gamma).inverse().unwrap(),
            Fr::from(2u64) * (t0 + gamma).inverse().unwrap(),
            "the forgery satisfies the identity for this γ"
        );
        let table = LookupTable::new(vec![t0]).unwrap();
        let forged = LogUpWitness {
            multiplicities: vec![2],
        };
        assert!(!verify_logup(&table, &[f], &forged));
        // Even with the multiplicity count fixed to match the single query.
        let forged = LogUpWitness {
            multiplicities: vec![1],
        };
        assert!(!verify_logup(&table, &[f], &forged));
    }

    #[test]
    fn test_plookup_rejects_out_of_table_query_with_honest_looking_proof() {
        let t: LookupTable<Fr> = range_table(7);
        let queries = vec![Fr::from(3u64), Fr::from(99u64)];
        let mut sorted: Vec<Fr> = queries.iter().chain(&t.entries).copied().collect();
        sorted.sort();
        assert!(!verify_plookup(&t, &queries, &PlookupProof { sorted }));
    }

    #[test]
    fn test_logup_rejects_overflowing_multiplicities() {
        let t: LookupTable<Fr> = range_table(1);
        let w = LogUpWitness {
            multiplicities: vec![usize::MAX, 2],
        };
        assert!(!verify_logup(&t, &[Fr::from(0u64)], &w));
    }

    // ── LookupTable ──────────────────────────────────────────────────────────

    #[test]
    fn test_table_new_sorted_rejects_unsorted() {
        let entries = vec![Fr::from(3u64), Fr::from(1u64), Fr::from(2u64)];
        assert!(LookupTable::new_sorted(entries).is_err());
    }

    #[test]
    fn test_range_table_correct() {
        let t: LookupTable<Fr> = range_table(7);
        assert_eq!(t.entries.len(), 8);
        for i in 0u64..=7 {
            assert!(t.contains(&Fr::from(i)));
        }
        assert!(!t.contains(&Fr::from(8u64)));
    }

    // ── Plookup ──────────────────────────────────────────────────────────────

    #[test]
    fn test_plookup_valid() {
        let t: LookupTable<Fr> = range_table(15);
        let queries = vec![
            Fr::from(3u64),
            Fr::from(7u64),
            Fr::from(0u64),
            Fr::from(15u64),
        ];

        let proof = prove_plookup(&t, &queries).expect("prove must succeed");
        assert!(
            verify_plookup(&t, &queries, &proof),
            "valid plookup must verify"
        );
    }

    #[test]
    fn test_plookup_query_not_in_table() {
        let t: LookupTable<Fr> = range_table(7);
        let queries = vec![Fr::from(3u64), Fr::from(99u64)]; // 99 not in [0,7]

        let result = prove_plookup(&t, &queries);
        assert!(
            matches!(result, Err(LookupError::QueryNotInTable(1))),
            "must reject out-of-table query"
        );
    }

    #[test]
    fn test_plookup_tampered_sorted_fails_verify() {
        let t: LookupTable<Fr> = range_table(15);
        let queries = vec![Fr::from(5u64), Fr::from(10u64)];

        let mut proof = prove_plookup(&t, &queries).unwrap();
        // Tamper: flip first element of sorted vector
        proof.sorted[0] = Fr::from(999u64);

        assert!(
            !verify_plookup(&t, &queries, &proof),
            "tampered sorted must not verify"
        );
    }

    #[test]
    fn test_plookup_single_query() {
        let t: LookupTable<Fr> = range_table(10);
        let queries = vec![Fr::from(5u64)];

        let proof = prove_plookup(&t, &queries).unwrap();
        assert!(verify_plookup(&t, &queries, &proof));
    }

    #[test]
    fn test_plookup_repeated_query() {
        let t: LookupTable<Fr> = range_table(15);
        // Query same value multiple times — valid, should still verify
        let queries = vec![
            Fr::from(3u64),
            Fr::from(3u64),
            Fr::from(7u64),
            Fr::from(3u64),
        ];

        let proof = prove_plookup(&t, &queries).unwrap();
        assert!(verify_plookup(&t, &queries, &proof));
    }

    // ── LogUp ────────────────────────────────────────────────────────────────

    #[test]
    fn test_logup_valid() {
        let t: LookupTable<Fr> = range_table(31);
        let queries = vec![
            Fr::from(1u64),
            Fr::from(5u64),
            Fr::from(20u64),
            Fr::from(5u64),
        ];

        let witness = prove_logup(&t, &queries).expect("prove must succeed");
        assert!(
            verify_logup(&t, &queries, &witness),
            "valid logup must verify"
        );
    }

    #[test]
    fn test_logup_query_not_in_table() {
        let t: LookupTable<Fr> = range_table(7);
        let queries = vec![Fr::from(3u64), Fr::from(100u64)];

        let result = prove_logup(&t, &queries);
        assert!(
            matches!(result, Err(LookupError::QueryNotInTable(1))),
            "must reject out-of-table query"
        );
    }

    #[test]
    fn test_logup_multiplicities_correct() {
        let t: LookupTable<Fr> = range_table(4);
        let queries = vec![
            Fr::from(2u64),
            Fr::from(2u64),
            Fr::from(4u64),
            Fr::from(0u64),
        ];

        let witness = prove_logup(&t, &queries).unwrap();
        // Table is [0,1,2,3,4] → indices: 0→0, 2→2, 4→4
        assert_eq!(witness.multiplicities[0], 1); // Fr(0) appears once
        assert_eq!(witness.multiplicities[1], 0); // Fr(1) never queried
        assert_eq!(witness.multiplicities[2], 2); // Fr(2) appears twice
        assert_eq!(witness.multiplicities[3], 0); // Fr(3) never queried
        assert_eq!(witness.multiplicities[4], 1); // Fr(4) appears once
    }

    #[test]
    fn test_logup_tampered_multiplicity_fails() {
        let t: LookupTable<Fr> = range_table(15);
        let queries = vec![Fr::from(3u64), Fr::from(7u64)];

        let mut witness = prove_logup(&t, &queries).unwrap();
        // Tamper: inflate a multiplicity
        witness.multiplicities[0] += 1;

        assert!(
            !verify_logup(&t, &queries, &witness),
            "tampered witness must not verify"
        );
    }

    #[test]
    fn test_logup_large_table() {
        let t: LookupTable<Fr> = range_table(999);
        let queries: Vec<Fr> = (0u64..100).map(|i| Fr::from(i * 10)).collect();

        let witness = prove_logup(&t, &queries).unwrap();
        assert!(verify_logup(&t, &queries, &witness));
    }

    // ── Multi-table LogUp ────────────────────────────────────────────────────

    #[test]
    fn test_multi_table_logup_valid() {
        let bool_table = LookupTable::new(vec![Fr::from(0u64), Fr::from(1u64)]).unwrap();
        let range_t = range_table::<Fr>(255);
        let multi = MultiTableLookup::new(vec![bool_table, range_t]);

        let queries: Vec<(usize, Fr)> = vec![
            (0, Fr::from(0u64)), // bool table
            (0, Fr::from(1u64)),
            (1, Fr::from(42u64)), // range table
            (1, Fr::from(200u64)),
        ];

        let witnesses = prove_multi_table_logup(&multi, &queries).unwrap();
        assert!(verify_multi_table_logup(&multi, &queries, &witnesses));
    }

    #[test]
    fn test_multi_table_logup_wrong_table_index() {
        let bool_table = LookupTable::new(vec![Fr::from(0u64), Fr::from(1u64)]).unwrap();
        let multi = MultiTableLookup::new(vec![bool_table]);

        let queries: Vec<(usize, Fr)> = vec![
            (99, Fr::from(1u64)), // table 99 doesn't exist
        ];

        let result = prove_multi_table_logup(&multi, &queries);
        assert!(
            matches!(result, Err(LookupError::TableIndexOutOfBounds(99))),
            "must reject invalid table index"
        );
    }

    #[test]
    fn test_multi_table_logup_value_wrong_table() {
        let bool_table = LookupTable::new(vec![Fr::from(0u64), Fr::from(1u64)]).unwrap();
        let range_t = range_table::<Fr>(7);
        let multi = MultiTableLookup::new(vec![bool_table, range_t]);

        // Query value 5 against bool_table (table 0) — 5 is not in {0,1}
        let queries: Vec<(usize, Fr)> = vec![(0, Fr::from(5u64))];

        let result = prove_multi_table_logup(&multi, &queries);
        assert!(
            matches!(result, Err(LookupError::QueryNotInTable(0))),
            "must reject value not in specified table"
        );
    }
}
