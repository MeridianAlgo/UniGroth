//! # Global Configuration
//!
//! Library-wide constants in one place, so integrators can see (and reference)
//! the parameters UniGroth uses without digging through individual modules.
//!
//! The domain-separation tags are part of the wire format: changing one changes
//! every Fiat-Shamir challenge or digest derived from it, so proofs and keys
//! made with the old value stop verifying.

/// Crate version, for tagging stored proofs and keys.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Target security level in bits.
pub const SECURITY_BITS: usize = 128;

/// Poseidon state width for the 2-to-1 hash used by the circuit library.
pub const POSEIDON_WIDTH: usize = 3;
/// Poseidon full rounds (x⁵ S-box on every state element).
pub const POSEIDON_FULL_ROUNDS: usize = 8;
/// Poseidon partial rounds (x⁵ S-box on the first state element only).
pub const POSEIDON_PARTIAL_ROUNDS: usize = 57;

/// Domain tag for universal-setup proofs of knowledge and shape checks.
pub const DOMAIN_SETUP_POK: &[u8] = b"unigroth-setup-v1";
/// Domain tag for the batch-verification challenge in `aggregation`.
pub const DOMAIN_AGGREGATE: &[u8] = b"unigroth-aggregate-v2";
/// Domain tag for the KZG batch-opening challenge.
pub const DOMAIN_KZG_BATCH: &[u8] = b"unigroth-kzg-batch-v1";
/// Domain tag for the IC-vector digest in `key_compression`.
pub const DOMAIN_VK_COMPRESSION: &[u8] = b"unigroth-vk-compression-v2";
/// Domain tag for the IPA transcript.
pub const DOMAIN_IPA: &[u8] = b"unigroth-ipa-v2";
/// Domain tag for Plookup / LogUp Fiat-Shamir challenges.
pub const DOMAIN_LOOKUP: &[u8] = b"unigroth-lookup-v1";
/// Domain tag for the Lasso transcript.
pub const DOMAIN_LASSO: &[u8] = b"lasso-v2";
/// Domain tag for recursive-chain entries.
pub const DOMAIN_RECURSION_CHAIN: &[u8] = b"UniGroth-Proof-Commit-v2";

/// Public-input count at which the verifier switches from direct scalar
/// multiplication to a Pippenger MSM for the input term.
pub const VERIFIER_MSM_THRESHOLD: usize = 16;
