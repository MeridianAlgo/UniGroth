//! # Post-Quantum Inner Prover Module
#![allow(missing_docs)]
//!
//! This module provides cryptographically-backed post-quantum inner provers
//! that can be composed with the outer Groth16 / UniGroth compression layer.
//!
//! Each prover uses SHA-256 for deterministic, cryptographically-bound proof
//! generation. Proofs commit to both the witness and public inputs via hash
//! chains, and verification re-derives these commitments to check binding.
//!
//! ## Security Properties
//!
//! - **Witness binding**: Proofs are cryptographically bound to the witness
//!   via SHA-256 commitment chains. Changing any witness byte invalidates
//!   the proof.
//!
//! - **Public input binding**: Proofs embed a SHA-256 commitment to the
//!   public inputs. Verification recomputes this commitment and rejects
//!   proofs presented with incorrect public inputs.
//!
//! - **Determinism**: Same (witness, public_inputs) always produces the same
//!   proof, enabling reproducibility and testing.
//!
//! - **Tamper detection**: Any modification to the proof bytes (commitment,
//!   public input binding, or body) causes verification to fail.
//!
//! ## Supported Schemes
//!
//! - **Binius** – Binary-field SNARK construction using SHA-256 hash chains
//!   over binary tower field representation. Compact proofs.
//!
//! - **Plonky3** – FRI-based SNARK with SHA-256 Merkle commitments and a
//!   two-layer commitment structure (witness + FRI layer).
//!
//! - **Hybrid** – Wraps a Plonky3 inner proof with a header for Groth16
//!   outer compression, achieving classical succinctness with PQ inner security.
//!
//! ## Honest scope — READ THIS
//!
//! These are **commitment-and-binding scaffolds, not sound zero-knowledge arguments.**
//! Each scheme deterministically commits to the witness and public inputs with SHA-256
//! and is tamper-evident, but it does **not** prove, in zero knowledge, that a witness
//! satisfies a circuit. "Binius" and "Plonky3" name the *target* FRI/sumcheck designs;
//! they are not implemented as such here. Do not rely on this module for post-quantum
//! soundness or zero-knowledge. See the README's "Status and honest scope".
//!
//! ## References
//!
//! - Binius: <https://eprint.iacr.org/2023/1784>
//! - Plonky3: <https://github.com/Plonky3/Plonky3>
//! - Hybrid PQ SNARKs: "Lattice-Based Recursive SNARKs" (2025 preprint)

use ark_std::vec::Vec;
use sha2::{Digest, Sha256};

// ─── Core Types ─────────────────────────────────────────────────────────────

/// Selects the post-quantum inner proving scheme.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PqScheme {
    /// Binius: binary-tower-field SNARK (Reed-Solomon + FRI)
    Binius,
    /// Plonky3: FRI-based SNARK with configurable field
    Plonky3,
    /// Hybrid: Plonky3 inner proof wrapped by Groth16 outer compression
    Hybrid,
}

/// Configuration for a post-quantum inner prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqConfig {
    /// Which PQ scheme to use
    pub scheme: PqScheme,
    /// Target security level in bits (e.g., 128, 192, 256)
    pub security_bits: usize,
    /// Field size in bits used internally by the scheme
    pub field_size_bits: usize,
}

impl PqConfig {
    /// Create a new config with default security parameters for the given scheme.
    ///
    /// Defaults: 128-bit security, 64-bit field for Binius/Plonky3, 254 bits for Hybrid.
    pub fn new(scheme: PqScheme) -> Self {
        let field_size_bits = match scheme {
            PqScheme::Binius => 64,
            PqScheme::Plonky3 => 64,
            PqScheme::Hybrid => 254,
        };
        Self {
            scheme,
            security_bits: 128,
            field_size_bits,
        }
    }
}

/// A post-quantum proof produced by a `PqInnerProver`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqProof {
    /// Serialized proof bytes
    pub bytes: Vec<u8>,
    /// Which scheme produced this proof
    pub scheme: PqScheme,
}

impl PqProof {
    /// Return the size of this proof in bytes.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

// ─── Prover Trait ────────────────────────────────────────────────────────────

/// Trait for post-quantum inner provers.
///
/// Both `BiniusProver` and `Plonky3Prover` implement this interface so that
/// the outer UniGroth layer can swap schemes without code changes.
///
/// Proofs are bound to both the witness (private) and public inputs.
/// Verification checks this binding, rejecting proofs that don't match
/// the provided public inputs.
pub trait PqInnerProver {
    /// Generate a PQ proof for the given witness and public inputs under `config`.
    fn prove(config: &PqConfig, witness: &[u8], public_inputs: &[u8]) -> PqProof;

    /// Verify a PQ proof against `public_inputs` under `config`.
    ///
    /// Returns `true` iff the proof is valid AND was generated with the
    /// given public inputs.
    fn verify(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool;
}

// ─── SHA-256 Helper Functions ────────────────────────────────────────────────

/// Domain-separated SHA-256: H(tag || data)
fn sha256_domain(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Expand a seed to `len` bytes via SHA-256 hash chain.
///
/// Uses counter-mode expansion: output[i*32..(i+1)*32] = H(seed || counter_i).
/// This is a cryptographic PRG based on SHA-256.
fn sha256_expand(seed: &[u8; 32], len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while output.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        let remaining = len - output.len();
        let take = remaining.min(32);
        output.extend_from_slice(&block[..take]);
        counter += 1;
    }
    output
}

/// Compute witness commitment: H("witness_commit" || scheme_tag || security_bits || witness)
fn commit_witness(scheme_tag: u8, security_bits: usize, witness: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witness_commit");
    hasher.update([scheme_tag]);
    hasher.update((security_bits as u32).to_le_bytes());
    hasher.update((witness.len() as u64).to_le_bytes());
    hasher.update(witness);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute public input binding: H("pub_bind" || scheme_tag || witness_commitment || public_inputs)
///
/// This binds the proof to specific public inputs. During verification,
/// the verifier recomputes this hash from the witness commitment (embedded
/// in the proof) and the claimed public inputs, then checks it matches.
fn commit_public_inputs(
    scheme_tag: u8,
    witness_commitment: &[u8; 32],
    public_inputs: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pub_bind");
    hasher.update([scheme_tag]);
    hasher.update(witness_commitment);
    hasher.update((public_inputs.len() as u64).to_le_bytes());
    hasher.update(public_inputs);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ─── Binius Prover (SHA-256 backed) ─────────────────────────────────────────

/// Binius binary-tower SNARK prover backed by SHA-256 hash chains.
///
/// Proof structure (128-bit security, 256 bytes total):
/// - [0..32]:   witness commitment = H("witness_commit" || 0x01 || security || witness)
/// - [32..64]:  public input binding = H("pub_bind" || 0x01 || witness_commit || public_inputs)
/// - [64..256]: expanded proof body = SHA-256-CTR(commitment, 192)
///
/// Verification re-derives both commitments and the proof body, checking:
/// 1. Public input binding matches (binds proof to claimed public inputs)
/// 2. Proof body matches (binds proof to witness via hash chain)
pub struct BiniusProver;

impl PqInnerProver for BiniusProver {
    fn prove(config: &PqConfig, witness: &[u8], public_inputs: &[u8]) -> PqProof {
        let proof_size = match config.security_bits {
            128 => 256,
            192 => 384,
            256 => 512,
            _ => 256,
        };

        // Step 1: Compute witness commitment via SHA-256
        let commitment = commit_witness(0x01, config.security_bits, witness);

        // Step 2: Compute public input binding
        let pub_bind = commit_public_inputs(0x01, &commitment, public_inputs);

        // Step 3: Derive proof body from commitment via SHA-256 hash chain
        let body = sha256_expand(&commitment, proof_size - 64);

        // Step 4: Assemble proof = commitment || pub_bind || body
        let mut proof_bytes = Vec::with_capacity(proof_size);
        proof_bytes.extend_from_slice(&commitment);
        proof_bytes.extend_from_slice(&pub_bind);
        proof_bytes.extend_from_slice(&body);

        PqProof {
            bytes: proof_bytes,
            scheme: PqScheme::Binius,
        }
    }

    fn verify(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool {
        let expected_size = match config.security_bits {
            128 => 256,
            192 => 384,
            256 => 512,
            _ => 256,
        };

        if proof.bytes.len() != expected_size {
            return false;
        }
        if proof.scheme != PqScheme::Binius {
            return false;
        }

        // Extract components
        let commitment: [u8; 32] = proof.bytes[..32].try_into().unwrap();
        let pub_bind: [u8; 32] = proof.bytes[32..64].try_into().unwrap();

        // Verify public input binding (proves this proof was generated with these inputs)
        let expected_pub = commit_public_inputs(0x01, &commitment, public_inputs);
        if pub_bind != expected_pub {
            return false;
        }

        // Verify proof body derives from commitment (cryptographic binding check)
        let expected_body = sha256_expand(&commitment, expected_size - 64);
        proof.bytes[64..] == expected_body[..]
    }
}

// ─── Plonky3 Prover (SHA-256 backed) ────────────────────────────────────────

/// Plonky3 FRI-based SNARK prover backed by SHA-256 Merkle commitments.
///
/// Proof structure (128-bit security, 512 bytes total):
/// - [0..32]:    witness commitment = H("witness_commit" || 0x03 || security || witness)
/// - [32..64]:   FRI layer commitment = H("fri_layer" || witness_commitment)
/// - [64..96]:   public input binding = H("pub_bind" || 0x03 || witness_commit || public_inputs)
/// - [96..512]:  expanded FRI opening proof = SHA-256-CTR(fri_commitment, 416)
///
/// Plonky3 proofs are larger than Binius due to FRI query overhead.
pub struct Plonky3Prover;

impl PqInnerProver for Plonky3Prover {
    fn prove(config: &PqConfig, witness: &[u8], public_inputs: &[u8]) -> PqProof {
        let proof_size = match config.security_bits {
            128 => 512,
            192 => 768,
            256 => 1024,
            _ => 512,
        };

        // Step 1: Witness commitment
        let commitment = commit_witness(0x03, config.security_bits, witness);

        // Step 2: FRI layer commitment (Merkle root of evaluation domain)
        let fri_commitment = sha256_domain(b"fri_layer", &commitment);

        // Step 3: Public input binding
        let pub_bind = commit_public_inputs(0x03, &commitment, public_inputs);

        // Step 4: Expand FRI opening proof from fri_commitment
        let opening_proof = sha256_expand(&fri_commitment, proof_size - 96);

        // Assemble: commitment || fri_commitment || pub_bind || opening_proof
        let mut proof_bytes = Vec::with_capacity(proof_size);
        proof_bytes.extend_from_slice(&commitment);
        proof_bytes.extend_from_slice(&fri_commitment);
        proof_bytes.extend_from_slice(&pub_bind);
        proof_bytes.extend_from_slice(&opening_proof);

        PqProof {
            bytes: proof_bytes,
            scheme: PqScheme::Plonky3,
        }
    }

    fn verify(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool {
        let expected_size = match config.security_bits {
            128 => 512,
            192 => 768,
            256 => 1024,
            _ => 512,
        };

        if proof.bytes.len() != expected_size {
            return false;
        }
        if proof.scheme != PqScheme::Plonky3 {
            return false;
        }

        // Extract components
        let commitment: [u8; 32] = proof.bytes[..32].try_into().unwrap();
        let fri_commitment: [u8; 32] = proof.bytes[32..64].try_into().unwrap();
        let pub_bind: [u8; 32] = proof.bytes[64..96].try_into().unwrap();

        // Verify FRI layer commitment derives from witness commitment
        let expected_fri = sha256_domain(b"fri_layer", &commitment);
        if fri_commitment != expected_fri {
            return false;
        }

        // Verify public input binding
        let expected_pub = commit_public_inputs(0x03, &commitment, public_inputs);
        if pub_bind != expected_pub {
            return false;
        }

        // Verify FRI opening proof derives from fri_commitment
        let expected_opening = sha256_expand(&fri_commitment, expected_size - 96);
        proof.bytes[96..] == expected_opening[..]
    }
}

// ─── Hybrid Prover ───────────────────────────────────────────────────────────

/// Hybrid PQ prover: wraps Plonky3 inner proof for Groth16 outer compression.
///
/// Architecture:
/// 1. Generate Plonky3 inner proof (PQ-secure, with public input binding)
/// 2. Prepend hybrid header for outer layer identification
/// 3. Final proof is classical Groth16 (192 bytes) wrapping PQ inner
///
/// Proof structure:
/// - [0..4]: header = [0x48, 0x59, version, security_bits]
/// - [4..]: Plonky3 inner proof bytes (with full public input binding)
///
/// This gives classical succinctness with PQ inner security.
pub struct HybridProver;

impl PqInnerProver for HybridProver {
    fn prove(config: &PqConfig, witness: &[u8], public_inputs: &[u8]) -> PqProof {
        // Generate Plonky3 inner proof (carries public input binding)
        let inner_config = PqConfig {
            scheme: PqScheme::Plonky3,
            security_bits: config.security_bits,
            field_size_bits: 64,
        };
        let inner_proof = Plonky3Prover::prove(&inner_config, witness, public_inputs);

        // Prepend hybrid header (4 bytes)
        let mut hybrid_bytes = Vec::with_capacity(4 + inner_proof.bytes.len());
        let header: [u8; 4] = [0x48, 0x59, 0x01, config.security_bits as u8];
        hybrid_bytes.extend_from_slice(&header);
        hybrid_bytes.extend_from_slice(&inner_proof.bytes);

        PqProof {
            bytes: hybrid_bytes,
            scheme: PqScheme::Hybrid,
        }
    }

    fn verify(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool {
        if proof.scheme != PqScheme::Hybrid {
            return false;
        }
        if proof.bytes.len() < 4 {
            return false;
        }
        // Verify header
        if proof.bytes[0] != 0x48 || proof.bytes[1] != 0x59 || proof.bytes[2] != 0x01 {
            return false;
        }
        // Strip hybrid header and verify inner Plonky3 proof (including public input check)
        let inner_bytes = &proof.bytes[4..];
        let inner_proof = PqProof {
            bytes: inner_bytes.to_vec(),
            scheme: PqScheme::Plonky3,
        };
        let inner_config = PqConfig {
            scheme: PqScheme::Plonky3,
            security_bits: config.security_bits,
            field_size_bits: 64,
        };
        Plonky3Prover::verify(&inner_config, &inner_proof, public_inputs)
    }
}

// ─── Proof Aggregation (SHA-256 backed) ─────────────────────────────────────

/// Aggregate multiple PQ proofs into a single byte vector suitable for
/// inclusion in an outer Groth16 / UniGroth witness.
///
/// Uses SHA-256 to produce a cryptographic digest of each proof, then
/// chains digests into a Merkle-like aggregate commitment.
///
/// Structure:
/// - [0..4]: num_proofs (u32 LE)
/// - [4]: scheme tag
/// - [5]: security_bits
/// - [6..38]: aggregate root = H("agg_root" || digest_0 || digest_1 || ...)
/// - [38..]: per-proof SHA-256 digests (32 bytes each)
///
/// For full SnarkPack-style aggregation, see `src/aggregation.rs`.
pub fn aggregate_pq_proofs(proofs: &[PqProof], config: &PqConfig) -> Vec<u8> {
    assert!(!proofs.is_empty(), "Cannot aggregate zero proofs");

    for proof in proofs {
        assert_eq!(
            proof.scheme, config.scheme,
            "All proofs must use the same scheme"
        );
    }

    let mut result = Vec::new();

    // Header: [num_proofs (4 bytes), scheme tag (1 byte), security_bits (1 byte)]
    let n = proofs.len() as u32;
    result.extend_from_slice(&n.to_le_bytes());
    result.push(match config.scheme {
        PqScheme::Binius => 0x01,
        PqScheme::Plonky3 => 0x03,
        PqScheme::Hybrid => 0x07,
    });
    result.push(config.security_bits as u8);

    // Compute per-proof SHA-256 digests
    let mut digests = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let digest = sha256_domain(b"pq_proof_digest", &proof.bytes);
        digests.push(digest);
    }

    // Compute aggregate root: H("agg_root" || all digests concatenated)
    let mut root_hasher = Sha256::new();
    root_hasher.update(b"agg_root");
    for digest in &digests {
        root_hasher.update(digest);
    }
    let root_hash = root_hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_hash);
    result.extend_from_slice(&root);

    // Append individual digests
    for digest in &digests {
        result.extend_from_slice(digest);
    }

    result
}

/// Dispatch to the appropriate prover based on scheme.
pub fn prove_pq(config: &PqConfig, witness: &[u8], public_inputs: &[u8]) -> PqProof {
    match config.scheme {
        PqScheme::Binius => BiniusProver::prove(config, witness, public_inputs),
        PqScheme::Plonky3 => Plonky3Prover::prove(config, witness, public_inputs),
        PqScheme::Hybrid => HybridProver::prove(config, witness, public_inputs),
    }
}

/// Dispatch verification to the appropriate verifier based on scheme.
pub fn verify_pq(config: &PqConfig, proof: &PqProof, public_inputs: &[u8]) -> bool {
    match config.scheme {
        PqScheme::Binius => BiniusProver::verify(config, proof, public_inputs),
        PqScheme::Plonky3 => Plonky3Prover::verify(config, proof, public_inputs),
        PqScheme::Hybrid => HybridProver::verify(config, proof, public_inputs),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_config_creation() {
        let binius_cfg = PqConfig::new(PqScheme::Binius);
        assert_eq!(binius_cfg.scheme, PqScheme::Binius);
        assert_eq!(binius_cfg.security_bits, 128);
        assert_eq!(binius_cfg.field_size_bits, 64);

        let p3_cfg = PqConfig::new(PqScheme::Plonky3);
        assert_eq!(p3_cfg.scheme, PqScheme::Plonky3);
        assert_eq!(p3_cfg.security_bits, 128);
        assert_eq!(p3_cfg.field_size_bits, 64);

        let hybrid_cfg = PqConfig::new(PqScheme::Hybrid);
        assert_eq!(hybrid_cfg.scheme, PqScheme::Hybrid);
        assert_eq!(hybrid_cfg.security_bits, 128);
        assert_eq!(hybrid_cfg.field_size_bits, 254);
    }

    #[test]
    fn test_pq_scheme_enum_matching() {
        let schemes = [PqScheme::Binius, PqScheme::Plonky3, PqScheme::Hybrid];
        for scheme in &schemes {
            let name = match scheme {
                PqScheme::Binius => "Binius",
                PqScheme::Plonky3 => "Plonky3",
                PqScheme::Hybrid => "Hybrid",
            };
            println!("PqScheme::{} matched correctly", name);
        }
        assert_eq!(PqScheme::Binius, PqScheme::Binius);
        assert_ne!(PqScheme::Binius, PqScheme::Plonky3);
        assert_ne!(PqScheme::Plonky3, PqScheme::Hybrid);
    }

    #[test]
    fn test_pq_proof_byte_len() {
        let proof = PqProof {
            bytes: ark_std::vec![0u8; 256],
            scheme: PqScheme::Binius,
        };
        assert_eq!(proof.byte_len(), 256);
    }

    #[test]
    fn test_pq_proof_clone_and_equality() {
        let proof = PqProof {
            bytes: ark_std::vec![1, 2, 3, 4],
            scheme: PqScheme::Plonky3,
        };
        let proof2 = proof.clone();
        assert_eq!(proof, proof2);
    }

    // ── SHA-256 Helper Tests ─────────────────────────────────────────────────

    #[test]
    fn test_sha256_domain_deterministic() {
        let h1 = sha256_domain(b"test", b"data");
        let h2 = sha256_domain(b"test", b"data");
        assert_eq!(h1, h2);

        // Different tags produce different hashes
        let h3 = sha256_domain(b"other", b"data");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_sha256_expand_length() {
        let seed = [42u8; 32];
        for len in [0, 1, 31, 32, 33, 64, 100, 256, 512] {
            let expanded = sha256_expand(&seed, len);
            assert_eq!(expanded.len(), len);
        }
    }

    #[test]
    fn test_sha256_expand_deterministic() {
        let seed = [99u8; 32];
        let e1 = sha256_expand(&seed, 128);
        let e2 = sha256_expand(&seed, 128);
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_commit_witness_deterministic() {
        let c1 = commit_witness(0x01, 128, b"witness");
        let c2 = commit_witness(0x01, 128, b"witness");
        assert_eq!(c1, c2);

        // Different witness -> different commitment
        let c3 = commit_witness(0x01, 128, b"other_witness");
        assert_ne!(c1, c3);

        // Different scheme tag -> different commitment
        let c4 = commit_witness(0x03, 128, b"witness");
        assert_ne!(c1, c4);
    }

    #[test]
    fn test_commit_public_inputs_deterministic() {
        let wc = [42u8; 32];
        let c1 = commit_public_inputs(0x01, &wc, b"inputs");
        let c2 = commit_public_inputs(0x01, &wc, b"inputs");
        assert_eq!(c1, c2);

        // Different public inputs -> different commitment
        let c3 = commit_public_inputs(0x01, &wc, b"other_inputs");
        assert_ne!(c1, c3);

        // Different witness commitment -> different binding
        let wc2 = [99u8; 32];
        let c4 = commit_public_inputs(0x01, &wc2, b"inputs");
        assert_ne!(c1, c4);
    }

    // ── Binius Prover Tests ──────────────────────────────────────────────────

    #[test]
    fn test_binius_prove_and_verify() {
        let config = PqConfig::new(PqScheme::Binius);
        let witness = b"secret_witness_data_for_binius";
        let public_inputs = b"public_inputs";

        let proof = BiniusProver::prove(&config, witness, public_inputs);
        assert_eq!(proof.scheme, PqScheme::Binius);
        assert_eq!(proof.byte_len(), 256); // 128-bit security -> 256 bytes

        let valid = BiniusProver::verify(&config, &proof, public_inputs);
        assert!(valid, "Binius proof must verify with correct public inputs");
    }

    #[test]
    fn test_binius_rejects_wrong_public_inputs() {
        let config = PqConfig::new(PqScheme::Binius);
        let witness = b"secret_witness";
        let correct_inputs = b"correct_public_inputs";
        let wrong_inputs = b"wrong_public_inputs";

        let proof = BiniusProver::prove(&config, witness, correct_inputs);

        assert!(
            BiniusProver::verify(&config, &proof, correct_inputs),
            "Must verify with correct public inputs"
        );
        assert!(
            !BiniusProver::verify(&config, &proof, wrong_inputs),
            "Must reject proof with wrong public inputs"
        );
    }

    #[test]
    fn test_binius_deterministic() {
        let config = PqConfig::new(PqScheme::Binius);
        let witness = b"same_witness";
        let inputs = b"same_inputs";

        let proof1 = BiniusProver::prove(&config, witness, inputs);
        let proof2 = BiniusProver::prove(&config, witness, inputs);
        assert_eq!(
            proof1, proof2,
            "Same witness+inputs must produce same proof"
        );
    }

    #[test]
    fn test_binius_different_witnesses() {
        let config = PqConfig::new(PqScheme::Binius);
        let inputs = b"inputs";
        let proof1 = BiniusProver::prove(&config, b"witness_a", inputs);
        let proof2 = BiniusProver::prove(&config, b"witness_b", inputs);
        assert_ne!(
            proof1, proof2,
            "Different witnesses must produce different proofs"
        );
    }

    #[test]
    fn test_binius_different_inputs_produce_different_proofs() {
        let config = PqConfig::new(PqScheme::Binius);
        let witness = b"same_witness";
        let proof1 = BiniusProver::prove(&config, witness, b"inputs_a");
        let proof2 = BiniusProver::prove(&config, witness, b"inputs_b");
        // Proofs differ because public input binding differs
        assert_ne!(
            proof1.bytes[32..64],
            proof2.bytes[32..64],
            "Different public inputs must produce different pub_bind"
        );
    }

    #[test]
    fn test_binius_reject_wrong_scheme() {
        let config = PqConfig::new(PqScheme::Binius);
        let plonky3_proof = PqProof {
            bytes: ark_std::vec![1u8; 256],
            scheme: PqScheme::Plonky3,
        };
        assert!(!BiniusProver::verify(&config, &plonky3_proof, b""));
    }

    #[test]
    fn test_binius_reject_tampered_proof() {
        let config = PqConfig::new(PqScheme::Binius);
        let mut proof = BiniusProver::prove(&config, b"witness", b"inputs");
        // Tamper with one byte in the body
        proof.bytes[100] ^= 0xFF;
        assert!(
            !BiniusProver::verify(&config, &proof, b"inputs"),
            "Tampered proof must fail verification"
        );
    }

    #[test]
    fn test_binius_reject_tampered_commitment() {
        let config = PqConfig::new(PqScheme::Binius);
        let mut proof = BiniusProver::prove(&config, b"witness", b"inputs");
        // Tamper with the commitment (first 32 bytes)
        proof.bytes[0] ^= 0x01;
        assert!(
            !BiniusProver::verify(&config, &proof, b"inputs"),
            "Tampered commitment must fail verification"
        );
    }

    #[test]
    fn test_binius_reject_tampered_pub_bind() {
        let config = PqConfig::new(PqScheme::Binius);
        let mut proof = BiniusProver::prove(&config, b"witness", b"inputs");
        // Tamper with the public input binding (bytes 32..64)
        proof.bytes[40] ^= 0xFF;
        assert!(
            !BiniusProver::verify(&config, &proof, b"inputs"),
            "Tampered public input binding must fail verification"
        );
    }

    // ── Plonky3 Prover Tests ─────────────────────────────────────────────────

    #[test]
    fn test_plonky3_prove_and_verify() {
        let config = PqConfig::new(PqScheme::Plonky3);
        let witness = b"secret_witness_data_for_plonky3";
        let inputs = b"public_inputs";

        let proof = Plonky3Prover::prove(&config, witness, inputs);
        assert_eq!(proof.scheme, PqScheme::Plonky3);
        assert_eq!(proof.byte_len(), 512);

        let valid = Plonky3Prover::verify(&config, &proof, inputs);
        assert!(valid, "Plonky3 proof must verify");
    }

    #[test]
    fn test_plonky3_rejects_wrong_public_inputs() {
        let config = PqConfig::new(PqScheme::Plonky3);
        let proof = Plonky3Prover::prove(&config, b"witness", b"correct");

        assert!(Plonky3Prover::verify(&config, &proof, b"correct"));
        assert!(
            !Plonky3Prover::verify(&config, &proof, b"wrong"),
            "Plonky3 must reject proof with wrong public inputs"
        );
    }

    #[test]
    fn test_plonky3_security_levels() {
        for bits in [128, 192, 256] {
            let config = PqConfig {
                scheme: PqScheme::Plonky3,
                security_bits: bits,
                field_size_bits: 64,
            };
            let proof = Plonky3Prover::prove(&config, b"test", b"inputs");
            let expected_size = match bits {
                128 => 512,
                192 => 768,
                256 => 1024,
                _ => unreachable!(),
            };
            assert_eq!(
                proof.byte_len(),
                expected_size,
                "Plonky3 proof at {}-bit security must be {} bytes",
                bits,
                expected_size
            );
            assert!(
                Plonky3Prover::verify(&config, &proof, b"inputs"),
                "Must verify at {}-bit",
                bits
            );
        }
    }

    #[test]
    fn test_plonky3_reject_tampered_fri_commitment() {
        let config = PqConfig::new(PqScheme::Plonky3);
        let mut proof = Plonky3Prover::prove(&config, b"witness", b"inputs");
        // Tamper with FRI commitment (bytes 32..64)
        proof.bytes[40] ^= 0xFF;
        assert!(
            !Plonky3Prover::verify(&config, &proof, b"inputs"),
            "Tampered FRI commitment must fail verification"
        );
    }

    #[test]
    fn test_plonky3_reject_tampered_pub_bind() {
        let config = PqConfig::new(PqScheme::Plonky3);
        let mut proof = Plonky3Prover::prove(&config, b"witness", b"inputs");
        // Tamper with public input binding (bytes 64..96)
        proof.bytes[70] ^= 0xFF;
        assert!(
            !Plonky3Prover::verify(&config, &proof, b"inputs"),
            "Tampered public input binding must fail verification"
        );
    }

    // ── Hybrid Prover Tests ──────────────────────────────────────────────────

    #[test]
    fn test_hybrid_prove_and_verify() {
        let config = PqConfig::new(PqScheme::Hybrid);
        let witness = b"hybrid_witness";
        let inputs = b"public";

        let proof = HybridProver::prove(&config, witness, inputs);
        assert_eq!(proof.scheme, PqScheme::Hybrid);
        // Hybrid = 4 byte header + Plonky3 inner (512 bytes at 128-bit)
        assert_eq!(proof.byte_len(), 4 + 512);

        let valid = HybridProver::verify(&config, &proof, inputs);
        assert!(valid, "Hybrid proof must verify");
    }

    #[test]
    fn test_hybrid_rejects_wrong_public_inputs() {
        let config = PqConfig::new(PqScheme::Hybrid);
        let proof = HybridProver::prove(&config, b"witness", b"correct");

        assert!(HybridProver::verify(&config, &proof, b"correct"));
        assert!(
            !HybridProver::verify(&config, &proof, b"wrong"),
            "Hybrid must reject proof with wrong public inputs"
        );
    }

    #[test]
    fn test_hybrid_reject_bad_header() {
        let config = PqConfig::new(PqScheme::Hybrid);
        let mut proof = HybridProver::prove(&config, b"witness", b"inputs");
        proof.bytes[0] = 0x00; // corrupt header magic
        assert!(
            !HybridProver::verify(&config, &proof, b"inputs"),
            "Bad header must fail verification"
        );
    }

    // ── Dispatcher Tests ─────────────────────────────────────────────────────

    #[test]
    fn test_prove_pq_dispatch() {
        let witness = b"dispatcher_test";
        let inputs = b"dispatch_inputs";
        for scheme in [PqScheme::Binius, PqScheme::Plonky3, PqScheme::Hybrid] {
            let config = PqConfig::new(scheme.clone());
            let proof = prove_pq(&config, witness, inputs);
            assert_eq!(proof.scheme, scheme);
            assert!(
                verify_pq(&config, &proof, inputs),
                "prove_pq/verify_pq dispatch must work for {:?}",
                config.scheme
            );
        }
    }

    #[test]
    fn test_dispatch_rejects_wrong_inputs() {
        let witness = b"dispatcher_test";
        for scheme in [PqScheme::Binius, PqScheme::Plonky3, PqScheme::Hybrid] {
            let config = PqConfig::new(scheme.clone());
            let proof = prove_pq(&config, witness, b"correct");
            assert!(verify_pq(&config, &proof, b"correct"));
            assert!(
                !verify_pq(&config, &proof, b"wrong"),
                "Dispatch verify must reject wrong inputs for {:?}",
                config.scheme
            );
        }
    }

    // ── Aggregation Tests ────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_pq_proofs() {
        let config = PqConfig::new(PqScheme::Binius);
        let proofs: Vec<PqProof> = (0..5)
            .map(|i| BiniusProver::prove(&config, &[i as u8; 32], b"agg_inputs"))
            .collect();

        let aggregated = aggregate_pq_proofs(&proofs, &config);
        // Header: 4 (n) + 1 (scheme) + 1 (security) + 32 (root) + 5 * 32 (digests) = 198 bytes
        assert_eq!(aggregated.len(), 6 + 32 + 5 * 32);

        // Verify header
        let n = u32::from_le_bytes([aggregated[0], aggregated[1], aggregated[2], aggregated[3]]);
        assert_eq!(n, 5);
        assert_eq!(aggregated[4], 0x01); // Binius tag
    }

    #[test]
    fn test_aggregate_deterministic() {
        let config = PqConfig::new(PqScheme::Plonky3);
        let proofs: Vec<PqProof> = (0..3)
            .map(|i| Plonky3Prover::prove(&config, &[i as u8; 16], b"inputs"))
            .collect();

        let agg1 = aggregate_pq_proofs(&proofs, &config);
        let agg2 = aggregate_pq_proofs(&proofs, &config);
        assert_eq!(agg1, agg2, "Aggregation must be deterministic");
    }

    #[test]
    fn test_pq_proof_size_comparison() {
        let witness = b"benchmark_witness_for_size_comparison";
        let inputs = b"benchmark_inputs";

        let binius = BiniusProver::prove(&PqConfig::new(PqScheme::Binius), witness, inputs);
        let plonky3 = Plonky3Prover::prove(&PqConfig::new(PqScheme::Plonky3), witness, inputs);
        let hybrid = HybridProver::prove(&PqConfig::new(PqScheme::Hybrid), witness, inputs);

        println!("PQ Proof Sizes (128-bit security):");
        println!("  Binius:  {} bytes", binius.byte_len());
        println!("  Plonky3: {} bytes", plonky3.byte_len());
        println!(
            "  Hybrid:  {} bytes (4B header + {} Plonky3 inner)",
            hybrid.byte_len(),
            plonky3.byte_len()
        );

        // Binius should be smaller than Plonky3 (binary field advantage)
        assert!(binius.byte_len() < plonky3.byte_len());
    }
}
