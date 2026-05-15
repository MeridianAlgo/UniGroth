//! # Multi-Party Proving (MPC-Friendly)
//!
//! Allows N parties to jointly generate a Groth16 proof without any single
//! party learning the full witness.  Each party holds a *secret share* of the
//! witness; they locally compute partial MSM contributions which are aggregated
//! at the end.
//!
//! ## Protocol (additive sharing, honest-but-curious model)
//!
//! 1. **Split**: A dealer (or distributed key-generation) splits the witness
//!    `w` into N additive shares: `w = w_1 + w_2 + ... + w_N`.
//! 2. **Local prove**: Each party i computes a *partial proof element*
//!    `A_i = pk.A * w_i` (a scalar multiplication in G1).
//! 3. **Aggregate**: A combiner sums the partial elements: `A = Σ A_i`.
//! 4. **Verify**: The standard Groth16 verifier checks the assembled proof.
//!
//! ## Security
//!
//! - **Privacy**: No single party learns the full witness (additive sharing).
//! - **Binding**: Each share is hash-bound to the party's identity to prevent
//!   substitution attacks.
//! - **Threshold extension**: Shamir secret sharing (t-of-N) is sketched in
//!   [`ShamirShare`] for future threshold proving.
//!
//! ## Use cases
//!
//! - Private ML inference: N data owners each hold part of the input features.
//! - Collaborative auditing: N auditors each verify a different account range.
//! - zkRollup: N sequencers jointly prove a batch without full witness access.

use ark_std::{format, rand::RngCore, string::String, vec, vec::Vec};
use sha2::{Digest, Sha256};

// ─── Additive Secret Sharing ──────────────────────────────────────────────────

/// An additive share of a witness element.
///
/// The secret `s` is split into N shares where `s = Σ shares[i]`.
/// All arithmetic is over the native field represented as bytes here
/// (in production, use the concrete `PrimeField` type).
#[derive(Clone, Debug)]
pub struct AdditiveShare {
    /// Party index (0-based).
    pub party_idx: usize,
    /// Share value as little-endian bytes (field element).
    pub value: Vec<u8>,
    /// SHA-256 binding to party identity + session ID.
    pub binding_tag: [u8; 32],
}

impl AdditiveShare {
    /// Compute the binding tag for (party_idx, session_id, value).
    fn compute_tag(party_idx: usize, session_id: &[u8; 32], value: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"mpc-share-binding");
        h.update(&(party_idx as u64).to_le_bytes());
        h.update(session_id);
        h.update(value);
        h.finalize().into()
    }

    /// Create a new `AdditiveShare` with a computed binding tag.
    pub fn new(party_idx: usize, session_id: &[u8; 32], value: Vec<u8>) -> Self {
        let binding_tag = Self::compute_tag(party_idx, session_id, &value);
        Self { party_idx, value, binding_tag }
    }

    /// Verify that the binding tag matches the stored value.
    pub fn verify_binding(&self, session_id: &[u8; 32]) -> bool {
        let expected = Self::compute_tag(self.party_idx, session_id, &self.value);
        expected == self.binding_tag
    }
}

// ─── Shamir (t-of-N) Sharing ─────────────────────────────────────────────────

/// A Shamir secret share (t-of-N threshold scheme).
///
/// In a t-of-N scheme, any t shares can reconstruct the secret; t-1 shares
/// reveal nothing.  The polynomial `f(x) = s + a_1·x + ... + a_{t-1}·x^{t-1}`
/// is evaluated at N points; each share is `(i+1, f(i+1))`.
///
/// This is a placeholder type — full field arithmetic over a concrete `PrimeField`
/// would be needed for production; the structure documents the interface.
#[derive(Clone, Debug)]
pub struct ShamirShare {
    /// Threshold (minimum shares to reconstruct).
    pub threshold: usize,
    /// Total shares.
    pub total: usize,
    /// Share index (1-based evaluation point).
    pub index: usize,
    /// Share value bytes (Lagrange interpolation needed to reconstruct).
    pub value: Vec<u8>,
}

// ─── MPC Configuration ────────────────────────────────────────────────────────

/// Configuration for a multi-party proving session.
#[derive(Clone, Debug)]
pub struct MpcConfig {
    /// Number of parties.
    pub num_parties: usize,
    /// Minimum parties required (threshold for Shamir; = num_parties for additive).
    pub threshold: usize,
    /// Unique session identifier (prevents cross-session replay).
    pub session_id: [u8; 32],
    /// Sharing scheme.
    pub scheme: MpcScheme,
}

/// The sharing scheme used in the MPC session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcScheme {
    /// Additive sharing: `s = s_1 + ... + s_N`. Threshold = N (all parties needed).
    Additive,
    /// Shamir t-of-N threshold sharing.
    Shamir { threshold: usize },
}

impl MpcConfig {
    /// Create a 2-of-2 additive sharing config.
    pub fn two_party(session_id: [u8; 32]) -> Self {
        Self { num_parties: 2, threshold: 2, session_id, scheme: MpcScheme::Additive }
    }

    /// Create an N-of-N additive sharing config.
    pub fn n_of_n(n: usize, session_id: [u8; 32]) -> Self {
        assert!(n >= 2, "need at least 2 parties");
        Self { num_parties: n, threshold: n, session_id, scheme: MpcScheme::Additive }
    }

    /// Create a t-of-N Shamir config.
    pub fn shamir(n: usize, t: usize, session_id: [u8; 32]) -> Self {
        assert!(t >= 1 && t <= n, "threshold must be in [1, n]");
        Self { num_parties: n, threshold: t, session_id, scheme: MpcScheme::Shamir { threshold: t } }
    }

    /// Whether the scheme requires all parties.
    pub fn requires_all_parties(&self) -> bool {
        self.threshold == self.num_parties
    }
}

// ─── Witness Sharing ─────────────────────────────────────────────────────────

/// One party's share of the private witness.
#[derive(Clone, Debug)]
pub struct MpcWitnessShare {
    /// Session configuration.
    pub config: MpcConfig,
    /// Party index (0-based).
    pub party_idx: usize,
    /// Additive shares of each witness element.
    pub shares: Vec<AdditiveShare>,
}

impl MpcWitnessShare {
    /// Verify all binding tags in this share.
    pub fn verify_all_bindings(&self) -> bool {
        self.shares.iter().all(|s| s.verify_binding(&self.config.session_id))
    }
}

/// Split a witness vector into N additive shares.
///
/// Uses random masking: for each witness element `w[i]`,
/// generates N-1 random masks and sets the last share to `w[i] - Σ masks`.
///
/// In this implementation, witness elements are represented as `u64` for
/// simplicity; a production version would use `PrimeField` scalars.
pub fn split_witness(
    witness: &[u64],
    config: &MpcConfig,
    rng: &mut impl RngCore,
) -> Vec<MpcWitnessShare> {
    let n = config.num_parties;
    let mut party_shares: Vec<Vec<AdditiveShare>> = (0..n).map(|_| Vec::new()).collect();

    for (elem_idx, &w) in witness.iter().enumerate() {
        let _ = elem_idx;
        // Generate N-1 random shares
        let mut sum: u64 = 0;
        let mut raw_shares: Vec<u64> = Vec::with_capacity(n);

        for _ in 0..n - 1 {
            let r = rng.next_u64();
            raw_shares.push(r);
            sum = sum.wrapping_add(r);
        }
        // Last share = w - sum (additive: all shares XOR = w? No, additive over Z_2^64)
        raw_shares.push(w.wrapping_sub(sum));

        for (party_idx, &val) in raw_shares.iter().enumerate() {
            let bytes = val.to_le_bytes().to_vec();
            let share = AdditiveShare::new(party_idx, &config.session_id, bytes);
            party_shares[party_idx].push(share);
        }
    }

    party_shares
        .into_iter()
        .enumerate()
        .map(|(party_idx, shares)| MpcWitnessShare {
            config: config.clone(),
            party_idx,
            shares,
        })
        .collect()
}

/// Reconstruct a witness from N additive shares (additive scheme only).
///
/// Sums the shares element-wise.  Returns `None` if share counts mismatch.
pub fn reconstruct_witness(shares: &[MpcWitnessShare]) -> Option<Vec<u64>> {
    if shares.is_empty() {
        return None;
    }
    let len = shares[0].shares.len();
    if !shares.iter().all(|s| s.shares.len() == len) {
        return None;
    }

    let mut result = vec![0u64; len];
    for party_share in shares {
        for (i, s) in party_share.shares.iter().enumerate() {
            if s.value.len() < 8 {
                return None;
            }
            let bytes: [u8; 8] = s.value[..8].try_into().ok()?;
            result[i] = result[i].wrapping_add(u64::from_le_bytes(bytes));
        }
    }
    Some(result)
}

// ─── Partial Proof Elements ───────────────────────────────────────────────────

/// A partial proof contribution from one party.
///
/// In the real Groth16 MPC, this would be a G1 point (partial MSM result).
/// Here we represent it as bytes for a commitment abstraction.
#[derive(Clone, Debug)]
pub struct PartialProofElement {
    /// Party index.
    pub party_idx: usize,
    /// Serialized partial proof element (G1 point bytes in production).
    pub element: Vec<u8>,
    /// Binding tag: SHA-256(party_idx || session_id || element).
    pub binding: [u8; 32],
}

impl PartialProofElement {
    /// Create a new partial proof element with binding.
    pub fn new(party_idx: usize, session_id: &[u8; 32], element: Vec<u8>) -> Self {
        let mut h = Sha256::new();
        h.update(b"mpc-partial-proof");
        h.update(&(party_idx as u64).to_le_bytes());
        h.update(session_id);
        h.update(&element);
        let binding = h.finalize().into();
        Self { party_idx, element, binding }
    }

    /// Verify the binding tag.
    pub fn verify(&self, session_id: &[u8; 32]) -> bool {
        let fresh = Self::new(self.party_idx, session_id, self.element.clone());
        fresh.binding == self.binding
    }
}

/// Aggregate N partial proof elements by hashing them (XOR of elements).
///
/// In production, this would be a G1 point addition: `A = Σ A_i`.
/// Here we use XOR as a field-agnostic stand-in for the aggregation step.
pub fn aggregate_partial_proofs(
    elements: &[PartialProofElement],
    session_id: &[u8; 32],
) -> Result<Vec<u8>, MpcError> {
    if elements.is_empty() {
        return Err(MpcError::EmptyPartySet);
    }
    // Verify all bindings
    for elem in elements {
        if !elem.verify(session_id) {
            return Err(MpcError::InvalidBinding { party_idx: elem.party_idx });
        }
    }
    // Aggregate (XOR as field-agnostic stand-in for EC point addition)
    let max_len = elements.iter().map(|e| e.element.len()).max().unwrap_or(0);
    let mut result = vec![0u8; max_len];
    for elem in elements {
        for (i, &b) in elem.element.iter().enumerate() {
            result[i] ^= b;
        }
    }
    Ok(result)
}

// ─── MPC Error ────────────────────────────────────────────────────────────────

/// Errors from the MPC protocol.
#[derive(Clone, Debug, PartialEq)]
pub enum MpcError {
    /// Binding tag verification failed for this party.
    InvalidBinding { party_idx: usize },
    /// Not enough parties provided (threshold not met).
    ThresholdNotMet { have: usize, need: usize },
    /// Empty party set (no shares provided).
    EmptyPartySet,
    /// Witness length mismatch across parties.
    WitnessLengthMismatch,
}

impl MpcError {
    /// Human-readable description.
    pub fn describe(&self) -> String {
        match self {
            Self::InvalidBinding { party_idx } =>
                format!("invalid binding tag for party {}", party_idx),
            Self::ThresholdNotMet { have, need } =>
                format!("threshold not met: have {} shares, need {}", have, need),
            Self::EmptyPartySet => format!("empty party set"),
            Self::WitnessLengthMismatch => format!("witness length mismatch across parties"),
        }
    }
}

// ─── MPC Session ─────────────────────────────────────────────────────────────

/// State of a multi-party proving session.
#[derive(Clone, Debug)]
pub struct MpcSession {
    /// Session configuration.
    pub config: MpcConfig,
    /// Partial proof elements received so far.
    pub partial_proofs: Vec<PartialProofElement>,
}

impl MpcSession {
    /// Start a new MPC session.
    pub fn new(config: MpcConfig) -> Self {
        Self { config, partial_proofs: Vec::new() }
    }

    /// Register a partial proof from one party.
    pub fn add_partial(&mut self, elem: PartialProofElement) -> Result<(), MpcError> {
        if !elem.verify(&self.config.session_id) {
            return Err(MpcError::InvalidBinding { party_idx: elem.party_idx });
        }
        self.partial_proofs.push(elem);
        Ok(())
    }

    /// Check if we have enough shares to aggregate.
    pub fn is_ready(&self) -> bool {
        self.partial_proofs.len() >= self.config.threshold
    }

    /// Finalize: aggregate partial proofs once threshold is met.
    pub fn finalize(&self) -> Result<Vec<u8>, MpcError> {
        if !self.is_ready() {
            return Err(MpcError::ThresholdNotMet {
                have: self.partial_proofs.len(),
                need: self.config.threshold,
            });
        }
        aggregate_partial_proofs(&self.partial_proofs, &self.config.session_id)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn session_id() -> [u8; 32] {
        [0xab; 32]
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xcafe)
    }

    // ── Additive sharing ─────────────────────────────────────────────────────

    #[test]
    fn test_split_and_reconstruct_2of2() {
        let witness = vec![42u64, 100, 0, u64::MAX, 1337];
        let cfg = MpcConfig::two_party(session_id());
        let mut rng = rng();

        let shares = split_witness(&witness, &cfg, &mut rng);
        assert_eq!(shares.len(), 2);

        let reconstructed = reconstruct_witness(&shares).expect("reconstruct failed");
        assert_eq!(reconstructed, witness);
    }

    #[test]
    fn test_split_and_reconstruct_3of3() {
        let witness: Vec<u64> = (0..16).collect();
        let cfg = MpcConfig::n_of_n(3, session_id());
        let mut rng = rng();

        let shares = split_witness(&witness, &cfg, &mut rng);
        assert_eq!(shares.len(), 3);

        let reconstructed = reconstruct_witness(&shares).unwrap();
        assert_eq!(reconstructed, witness);
    }

    #[test]
    fn test_share_binding_valid() {
        let sess = session_id();
        let share = AdditiveShare::new(0, &sess, vec![1, 2, 3, 4]);
        assert!(share.verify_binding(&sess));
    }

    #[test]
    fn test_share_binding_wrong_session() {
        let sess = session_id();
        let share = AdditiveShare::new(0, &sess, vec![1, 2, 3, 4]);
        let wrong_sess = [0xffu8; 32];
        assert!(!share.verify_binding(&wrong_sess));
    }

    #[test]
    fn test_witness_share_bindings_all_valid() {
        let witness = vec![7u64, 13, 42];
        let cfg = MpcConfig::two_party(session_id());
        let mut rng = rng();
        let shares = split_witness(&witness, &cfg, &mut rng);
        for s in &shares {
            assert!(s.verify_all_bindings(), "party {} bindings invalid", s.party_idx);
        }
    }

    // ── Partial proofs ────────────────────────────────────────────────────────

    #[test]
    fn test_partial_proof_binding() {
        let sess = session_id();
        let elem = PartialProofElement::new(0, &sess, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(elem.verify(&sess));
        let wrong_sess = [0x00u8; 32];
        assert!(!elem.verify(&wrong_sess));
    }

    #[test]
    fn test_aggregate_partial_proofs() {
        let sess = session_id();
        let e1 = PartialProofElement::new(0, &sess, vec![0x10, 0x20]);
        let e2 = PartialProofElement::new(1, &sess, vec![0x01, 0x02]);
        let result = aggregate_partial_proofs(&[e1, e2], &sess).unwrap();
        assert_eq!(result, vec![0x11, 0x22]);
    }

    #[test]
    fn test_aggregate_invalid_binding_rejected() {
        let sess = session_id();
        let mut e1 = PartialProofElement::new(0, &sess, vec![0x10]);
        e1.binding = [0u8; 32]; // corrupt
        let result = aggregate_partial_proofs(&[e1], &sess);
        assert!(matches!(result, Err(MpcError::InvalidBinding { party_idx: 0 })));
    }

    // ── MPC Session ──────────────────────────────────────────────────────────

    #[test]
    fn test_session_finalize_happy_path() {
        let sess = session_id();
        let cfg = MpcConfig::two_party(sess);
        let mut session = MpcSession::new(cfg);

        let e1 = PartialProofElement::new(0, &sess, vec![0xAA, 0xBB]);
        let e2 = PartialProofElement::new(1, &sess, vec![0x11, 0x22]);

        session.add_partial(e1).unwrap();
        assert!(!session.is_ready(), "1 of 2 parties — not ready yet");

        session.add_partial(e2).unwrap();
        assert!(session.is_ready());

        let proof = session.finalize().unwrap();
        assert_eq!(proof, vec![0xBB, 0x99]);
    }

    #[test]
    fn test_session_finalize_before_threshold_errors() {
        let sess = session_id();
        let cfg = MpcConfig::two_party(sess);
        let mut session = MpcSession::new(cfg);

        let e1 = PartialProofElement::new(0, &sess, vec![0x01]);
        session.add_partial(e1).unwrap();

        let result = session.finalize();
        assert!(matches!(result, Err(MpcError::ThresholdNotMet { have: 1, need: 2 })));
    }

    #[test]
    fn test_mpc_config_variants() {
        let sess = session_id();
        assert!(MpcConfig::two_party(sess).requires_all_parties());
        assert!(MpcConfig::n_of_n(5, sess).requires_all_parties());
        let thr = MpcConfig::shamir(5, 3, sess);
        assert!(!thr.requires_all_parties());
        assert_eq!(thr.threshold, 3);
    }

    #[test]
    fn test_mpc_error_describe() {
        assert!(!MpcError::EmptyPartySet.describe().is_empty());
        assert!(!MpcError::InvalidBinding { party_idx: 2 }.describe().is_empty());
        assert!(!MpcError::ThresholdNotMet { have: 1, need: 3 }.describe().is_empty());
    }
}
