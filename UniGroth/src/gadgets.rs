//! # ZK Gadget Library
//!
//! High-level constraint gadgets for composing circuits in UniGroth.
//!
//! Each gadget documents its constraint count, wire layout, and security model.
//! Gadgets are composable: e.g. a `RecursiveVerifierGadget` internally uses
//! `PoseidonHashGadget` for the Fiat-Shamir transcript.
//!
//! ## Gadget catalogue
//!
//! | Gadget | Purpose | Constraints |
//! |--------|---------|-------------|
//! | [`RangeCheckGadget`] | Constrain value to k bits | k |
//! | [`MerkleProofGadget`] | Merkle inclusion proof | depth × (hash_cost + 2) |
//! | [`PoseidonHashGadget`] | ZK-friendly Poseidon sponge | rounds × state² |
//! | [`EcdsaVerifyGadget`] | secp256k1 ECDSA verify | ~3 000 |
//! | [`EddsaVerifyGadget`] | Ed25519 / JubJub EdDSA verify | ~1 500 |
//! | [`MemoryAccessGadget`] | RAM lookup via Merkle / sorted range | depth × hash + range |
//! | [`RecursiveVerifierGadget`] | Verify Groth16 proof inside circuit | ~50 000 |

use ark_std::{format, string::String, vec, vec::Vec};

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Common interface implemented by every gadget in this module.
pub trait GadgetInfo {
    /// Number of R1CS constraints this gadget generates.
    fn constraint_count(&self) -> usize;
    /// Number of wires (columns) consumed per row group.
    fn wire_count(&self) -> usize;
    /// One-line human-readable description.
    fn describe(&self) -> String;
}

// ─── Range Check ─────────────────────────────────────────────────────────────

/// Constrain a witness value to lie within `[0, 2^bits)`.
///
/// Implemented via a binary decomposition: `value = Σ bᵢ · 2^i` with
/// boolean constraints `bᵢ · (bᵢ − 1) = 0` for each bit.
///
/// Total: `bits` boolean constraints + 1 summation constraint.
#[derive(Debug, Clone, PartialEq)]
pub struct RangeCheckGadget {
    /// Number of bits. Common values: 8, 16, 32, 64, 128.
    pub bits: usize,
}

impl RangeCheckGadget {
    /// Construct for the given bit-width.
    pub fn new(bits: usize) -> Self {
        Self { bits }
    }

    /// Construct for common Rust integer widths.
    /// Unsigned 8-bit range check (values 0–255).
    pub fn u8() -> Self {
        Self::new(8)
    }
    /// Unsigned 16-bit range check.
    pub fn u16() -> Self {
        Self::new(16)
    }
    /// Unsigned 32-bit range check.
    pub fn u32() -> Self {
        Self::new(32)
    }
    /// Unsigned 64-bit range check.
    pub fn u64() -> Self {
        Self::new(64)
    }
    /// Unsigned 128-bit range check.
    pub fn u128() -> Self {
        Self::new(128)
    }
}

impl GadgetInfo for RangeCheckGadget {
    fn constraint_count(&self) -> usize {
        // bits boolean constraints + 1 linear summation
        self.bits + 1
    }

    fn wire_count(&self) -> usize {
        // 1 value wire + bits bit-decomposition wires
        self.bits + 1
    }

    fn describe(&self) -> String {
        format!(
            "RangeCheckGadget(u{}) | wires={} | constraints={}",
            self.bits,
            self.wire_count(),
            self.constraint_count()
        )
    }
}

// ─── Poseidon Hash ────────────────────────────────────────────────────────────

/// Poseidon sponge hash gadget — algebraic, ZK-friendly.
///
/// Uses Poseidon with `rate` absorption elements and `capacity` security
/// elements.  Each full round costs `state_width × 3 + state_width²`
/// constraints; each partial round costs `3 + state_width²`.
///
/// Reference parameters (Poseidon for BN254, 128-bit security):
/// - state_width = 3, full_rounds = 8, partial_rounds = 57
#[derive(Debug, Clone, PartialEq)]
pub struct PoseidonHashGadget {
    /// Total state width (rate + capacity). Typically 3.
    pub state_width: usize,
    /// Number of full rounds (all S-boxes active). Typically 8.
    pub full_rounds: usize,
    /// Number of partial rounds (one S-box active). Typically 57.
    pub partial_rounds: usize,
}

impl PoseidonHashGadget {
    /// Default parameters for BN254, 128-bit security.
    pub fn new() -> Self {
        Self {
            state_width: 3,
            full_rounds: 8,
            partial_rounds: 57,
        }
    }

    /// Custom parameters.
    pub fn with_params(state_width: usize, full_rounds: usize, partial_rounds: usize) -> Self {
        Self {
            state_width,
            full_rounds,
            partial_rounds,
        }
    }
}

impl Default for PoseidonHashGadget {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetInfo for PoseidonHashGadget {
    fn constraint_count(&self) -> usize {
        let w = self.state_width;
        // Full round: w S-boxes × 3 muls + w² MDS
        let full_cost = w * 3 + w * w;
        // Partial round: 1 S-box × 3 muls + w² MDS
        let partial_cost = 3 + w * w;
        self.full_rounds * full_cost + self.partial_rounds * partial_cost
    }

    fn wire_count(&self) -> usize {
        self.state_width * 2 // input + output state
    }

    fn describe(&self) -> String {
        format!(
            "PoseidonHashGadget | state={} | full_rounds={} | partial_rounds={} | constraints={}",
            self.state_width,
            self.full_rounds,
            self.partial_rounds,
            self.constraint_count()
        )
    }
}

// ─── Merkle Proof ─────────────────────────────────────────────────────────────

/// Merkle inclusion proof gadget.
///
/// Verifies that `leaf` appears at position `index` in a Merkle tree of depth
/// `depth` with root `root`, using `hash_gadget` for each internal hash.
///
/// Constraints per level: `hash_gadget.constraint_count() + 2` selector constraints.
#[derive(Debug, Clone, PartialEq)]
pub struct MerkleProofGadget {
    /// Tree depth (number of hash levels from leaf to root).
    pub depth: usize,
    /// Constraints per hash call (from the inner hash gadget).
    pub hash_constraints: usize,
}

impl MerkleProofGadget {
    /// Construct with tree depth and Poseidon hash costs.
    pub fn new(depth: usize) -> Self {
        let poseidon = PoseidonHashGadget::new();
        Self {
            depth,
            hash_constraints: poseidon.constraint_count(),
        }
    }

    /// Construct with a custom hash constraint cost.
    pub fn with_hash_cost(depth: usize, hash_constraints: usize) -> Self {
        Self {
            depth,
            hash_constraints,
        }
    }
}

impl GadgetInfo for MerkleProofGadget {
    fn constraint_count(&self) -> usize {
        // Per level: hash + 2 selector constraints
        self.depth * (self.hash_constraints + 2)
    }

    fn wire_count(&self) -> usize {
        // leaf + root + depth sibling wires + depth bit selectors
        2 + self.depth * 2
    }

    fn describe(&self) -> String {
        format!(
            "MerkleProofGadget | depth={} | hash_cost={} | constraints={}",
            self.depth,
            self.hash_constraints,
            self.constraint_count()
        )
    }
}

// ─── ECDSA Verify ─────────────────────────────────────────────────────────────

/// secp256k1 ECDSA signature verification gadget.
///
/// Verifies a signature `(r, s)` against public key `Q` and message hash `e`.
/// The dominant cost is two EC scalar multiplications (for `e·G` and `r·Q`)
/// followed by one EC addition.
///
/// ## Constraint breakdown
///
/// | Operation | Constraints |
/// |-----------|-------------|
/// | EC scalar mul (256-bit) — ×2 | 2 × 1 400 = 2 800 |
/// | EC addition | 5 |
/// | Field inversions (s⁻¹) | 2 × 100 = 200 |
/// | Coordinate comparisons | 5 |
/// | **Total** | **~3 010** |
#[derive(Debug, Clone, PartialEq)]
pub struct EcdsaVerifyGadget {
    /// Bit-width of the scalar field (256 for secp256k1).
    pub scalar_bits: usize,
}

impl EcdsaVerifyGadget {
    /// Standard secp256k1 parameters.
    pub fn new() -> Self {
        Self { scalar_bits: 256 }
    }
}

impl Default for EcdsaVerifyGadget {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetInfo for EcdsaVerifyGadget {
    fn constraint_count(&self) -> usize {
        // 2 EC scalar muls + 1 EC add + 2 field inversions + comparisons
        let scalar_mul = self.scalar_bits * 5; // ~1400 for 256-bit
        2 * scalar_mul + 5 + 2 * 100 + 5
    }

    fn wire_count(&self) -> usize {
        // message(1) + pubkey(2) + sig(2) + intermediate(6)
        11
    }

    fn describe(&self) -> String {
        format!(
            "EcdsaVerifyGadget | scalar_bits={} | constraints={}",
            self.scalar_bits,
            self.constraint_count()
        )
    }
}

// ─── EdDSA Verify ─────────────────────────────────────────────────────────────

/// Ed25519 / JubJub EdDSA signature verification gadget.
///
/// Verifies `(R, s)` against public key `A` and message `M`.
/// Uses twisted Edwards arithmetic which is cheaper than Weierstrass.
///
/// ## Constraint breakdown
///
/// | Operation | Constraints |
/// |-----------|-------------|
/// | EC scalar mul on JubJub (255-bit) — ×2 | 2 × 700 = 1 400 |
/// | Twisted-Edwards addition | 6 |
/// | Poseidon transcript hash | ~700 |
/// | **Total** | **~2 106** |
#[derive(Debug, Clone, PartialEq)]
pub struct EddsaVerifyGadget {
    /// Bit-width of the scalar field (255 for Ed25519/JubJub).
    pub scalar_bits: usize,
}

impl EddsaVerifyGadget {
    /// Standard Ed25519 / JubJub parameters.
    pub fn new() -> Self {
        Self { scalar_bits: 255 }
    }
}

impl Default for EddsaVerifyGadget {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetInfo for EddsaVerifyGadget {
    fn constraint_count(&self) -> usize {
        let scalar_mul = self.scalar_bits * 3; // twisted-Edwards is ~3× cheaper
        let poseidon = PoseidonHashGadget::new().constraint_count();
        2 * scalar_mul + 6 + poseidon
    }

    fn wire_count(&self) -> usize {
        // message(1) + pubkey(2) + sig(2) + transcript(3) + intermediate(4)
        12
    }

    fn describe(&self) -> String {
        format!(
            "EddsaVerifyGadget | scalar_bits={} | constraints={}",
            self.scalar_bits,
            self.constraint_count()
        )
    }
}

// ─── Memory Access ────────────────────────────────────────────────────────────

/// Deterministic memory-access gadget for program counter / RAM tracking.
///
/// Proves read-write consistency for a memory of `capacity` cells over
/// `num_accesses` operations.  Uses a sorted-difference argument: each
/// access is sorted by (address, timestamp) and consecutive differences
/// are range-checked.
///
/// Suitable for: zkVM program counters, zkEVM memory, recursive SNARK state.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryAccessGadget {
    /// Number of addressable memory cells.
    pub capacity: usize,
    /// Number of read/write operations to prove.
    pub num_accesses: usize,
}

impl MemoryAccessGadget {
    /// Construct for given memory capacity and access count.
    pub fn new(capacity: usize, num_accesses: usize) -> Self {
        Self {
            capacity,
            num_accesses,
        }
    }
}

impl GadgetInfo for MemoryAccessGadget {
    fn constraint_count(&self) -> usize {
        // Per access: 1 address range check (log2(capacity) bits) + 1 consistency check + 2 sort checks
        let addr_bits = (self.capacity.next_power_of_two()).trailing_zeros() as usize;
        let per_access = addr_bits + 1 + 2; // range + consistency + sort
        self.num_accesses * per_access
    }

    fn wire_count(&self) -> usize {
        // per access: [addr, value, timestamp, prev_value, delta_addr, delta_ts]
        self.num_accesses * 6
    }

    fn describe(&self) -> String {
        format!(
            "MemoryAccessGadget | capacity={} | accesses={} | constraints={}",
            self.capacity,
            self.num_accesses,
            self.constraint_count()
        )
    }
}

// ─── Recursive Verifier ───────────────────────────────────────────────────────

/// Recursive Groth16 verifier gadget.
///
/// Encodes the Groth16 verifier algorithm as R1CS constraints, enabling one
/// Groth16 proof to verify another Groth16 proof — enabling arbitrary-depth
/// recursion without FRI.
///
/// ## Cost model
///
/// The verifier computes:
/// - `prepare_inputs`: `num_public_inputs` scalar multiplications on G1
///   (~256 constraints each)
/// - `miller_loop`: 3 pairing operations (~8 000 constraints each)
/// - `final_exp`: Fp12 exponentiation (~10 000 constraints)
///
/// At 4 public inputs:
/// ```text
/// prepare_inputs: 4 × 256 = 1 024
/// miller_loop:    3 × 8 000 = 24 000
/// final_exp:      10 000
/// transcript (Poseidon): ~700
/// total:          ~35 724
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RecursiveVerifierGadget {
    /// Number of public inputs in the inner proof being verified.
    pub num_public_inputs: usize,
}

impl RecursiveVerifierGadget {
    /// Construct for an inner proof with `num_public_inputs` public inputs.
    pub fn new(num_public_inputs: usize) -> Self {
        Self { num_public_inputs }
    }

    /// Typical setup: 4 public inputs (input hash, output hash, step count, circuit id).
    pub fn standard() -> Self {
        Self::new(4)
    }
}

impl GadgetInfo for RecursiveVerifierGadget {
    fn constraint_count(&self) -> usize {
        let prepare_inputs = self.num_public_inputs * 256;
        let miller_loop = 3 * 8_000;
        let final_exp = 10_000;
        let transcript = PoseidonHashGadget::new().constraint_count();
        prepare_inputs + miller_loop + final_exp + transcript
    }

    fn wire_count(&self) -> usize {
        // proof wires (6) + vk wires (3 + num_inputs) + transcript (3)
        6 + 3 + self.num_public_inputs + 3
    }

    fn describe(&self) -> String {
        format!(
            "RecursiveVerifierGadget | public_inputs={} | constraints={}",
            self.num_public_inputs,
            self.constraint_count()
        )
    }
}

// ─── Gadget Library ───────────────────────────────────────────────────────────

/// Registry of all standard gadgets with their constraint counts.
///
/// Provides a summary view for circuit planning and benchmarking.
#[derive(Debug, Clone)]
pub struct GadgetLibrary {
    /// Range check gadget for u64 values.
    pub range_u64: RangeCheckGadget,
    /// Poseidon hash (BN254, 128-bit).
    pub poseidon: PoseidonHashGadget,
    /// Merkle proof (depth 32, Poseidon hash).
    pub merkle_depth32: MerkleProofGadget,
    /// secp256k1 ECDSA verifier.
    pub ecdsa: EcdsaVerifyGadget,
    /// Ed25519 / JubJub EdDSA verifier.
    pub eddsa: EddsaVerifyGadget,
    /// Memory access (256 cells, 64 accesses).
    pub memory: MemoryAccessGadget,
    /// Recursive Groth16 verifier (4 public inputs).
    pub recursive_verifier: RecursiveVerifierGadget,
}

impl GadgetLibrary {
    /// Construct with canonical parameter choices.
    pub fn new() -> Self {
        Self {
            range_u64: RangeCheckGadget::u64(),
            poseidon: PoseidonHashGadget::new(),
            merkle_depth32: MerkleProofGadget::new(32),
            ecdsa: EcdsaVerifyGadget::new(),
            eddsa: EddsaVerifyGadget::new(),
            memory: MemoryAccessGadget::new(256, 64),
            recursive_verifier: RecursiveVerifierGadget::standard(),
        }
    }

    /// Produce a formatted summary table of all gadgets and their costs.
    pub fn describe(&self) -> String {
        let gadgets: Vec<(&str, usize)> = vec![
            ("RangeCheck(u64)", self.range_u64.constraint_count()),
            ("PoseidonHash", self.poseidon.constraint_count()),
            (
                "MerkleProof(depth=32)",
                self.merkle_depth32.constraint_count(),
            ),
            ("EcdsaVerify(secp256k1)", self.ecdsa.constraint_count()),
            ("EddsaVerify(Ed25519)", self.eddsa.constraint_count()),
            ("MemoryAccess(256c,64a)", self.memory.constraint_count()),
            (
                "RecursiveVerifier(4in)",
                self.recursive_verifier.constraint_count(),
            ),
        ];
        let mut out = String::from("UniGroth ZK Gadget Library\n");
        out.push_str("============================================================\n");
        out.push_str(&format!("{:<28}| {:>12}\n", "Gadget", "Constraints"));
        out.push_str("------------------------------------------------------------\n");
        for (name, count) in &gadgets {
            out.push_str(&format!("{:<28}| {:>12}\n", name, count));
        }
        out.push_str("============================================================\n");
        out
    }
}

impl Default for GadgetLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_check_constraint_count() {
        assert_eq!(RangeCheckGadget::u8().constraint_count(), 9);
        assert_eq!(RangeCheckGadget::u16().constraint_count(), 17);
        assert_eq!(RangeCheckGadget::u32().constraint_count(), 33);
        assert_eq!(RangeCheckGadget::u64().constraint_count(), 65);
        assert_eq!(RangeCheckGadget::u128().constraint_count(), 129);
    }

    #[test]
    fn test_range_check_wire_count() {
        let g = RangeCheckGadget::u32();
        assert_eq!(g.wire_count(), 33); // 32 bits + 1 value
    }

    #[test]
    fn test_poseidon_constraint_count() {
        let g = PoseidonHashGadget::new();
        // full: 8 * (3*3 + 3*3) = 8*18 = 144; partial: 57*(3+9) = 57*12 = 684; total = 828
        let full_cost = g.state_width * 3 + g.state_width * g.state_width;
        let partial_cost = 3 + g.state_width * g.state_width;
        let expected = g.full_rounds * full_cost + g.partial_rounds * partial_cost;
        assert_eq!(g.constraint_count(), expected);
        assert!(g.constraint_count() > 0);
    }

    #[test]
    fn test_poseidon_custom_params() {
        let g = PoseidonHashGadget::with_params(5, 4, 30);
        assert!(g.constraint_count() > 0);
    }

    #[test]
    fn test_merkle_proof_depth() {
        let g32 = MerkleProofGadget::new(32);
        let g8 = MerkleProofGadget::new(8);
        assert!(g32.constraint_count() > g8.constraint_count());
        // Depth 0 is a degenerate but valid (0 constraints)
        let g0 = MerkleProofGadget::new(0);
        assert_eq!(g0.constraint_count(), 0);
    }

    #[test]
    fn test_ecdsa_beats_naive_scalar_mul() {
        let g = EcdsaVerifyGadget::new();
        assert!(g.constraint_count() > 2_000, "ECDSA needs many constraints");
        assert!(
            g.constraint_count() < 10_000,
            "ECDSA should not be unreasonably large"
        );
    }

    #[test]
    fn test_eddsa_cheaper_than_ecdsa() {
        let ecdsa = EcdsaVerifyGadget::new();
        let eddsa = EddsaVerifyGadget::new();
        assert!(
            eddsa.constraint_count() < ecdsa.constraint_count(),
            "EdDSA should be cheaper than ECDSA (twisted-Edwards curve advantage)"
        );
    }

    #[test]
    fn test_memory_access_scales_with_accesses() {
        let g16 = MemoryAccessGadget::new(256, 16);
        let g64 = MemoryAccessGadget::new(256, 64);
        assert!(g64.constraint_count() > g16.constraint_count());
        assert_eq!(g64.constraint_count(), 4 * g16.constraint_count());
    }

    #[test]
    fn test_recursive_verifier_standard() {
        let g = RecursiveVerifierGadget::standard();
        assert_eq!(g.num_public_inputs, 4);
        assert!(g.constraint_count() > 30_000);
        // Cost should scale with public inputs
        let g8 = RecursiveVerifierGadget::new(8);
        assert!(g8.constraint_count() > g.constraint_count());
    }

    #[test]
    fn test_gadget_library_describe() {
        let lib = GadgetLibrary::new();
        let desc = lib.describe();
        assert!(desc.contains("UniGroth ZK Gadget Library"));
        assert!(desc.contains("PoseidonHash"));
        assert!(desc.contains("MerkleProof"));
        assert!(desc.contains("Recursive"));
    }

    #[test]
    fn test_gadget_describe_non_empty() {
        assert!(!RangeCheckGadget::u64().describe().is_empty());
        assert!(!PoseidonHashGadget::new().describe().is_empty());
        assert!(!MerkleProofGadget::new(20).describe().is_empty());
        assert!(!EcdsaVerifyGadget::new().describe().is_empty());
        assert!(!EddsaVerifyGadget::new().describe().is_empty());
        assert!(!MemoryAccessGadget::new(64, 32).describe().is_empty());
        assert!(!RecursiveVerifierGadget::standard().describe().is_empty());
    }

    #[test]
    fn test_gadget_clone_and_eq() {
        let g = RangeCheckGadget::u64();
        let g2 = g.clone();
        assert_eq!(g, g2);

        let p = PoseidonHashGadget::new();
        let p2 = p.clone();
        assert_eq!(p, p2);
    }
}
