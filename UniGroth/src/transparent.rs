//! # Transparent Setup Option
//!
//! Provides a ceremony-free alternative to KZG polynomial commitments.
//!
//! KZG requires a trusted Powers-of-Tau ceremony. Environments that cannot
//! participate in such a ceremony (e.g. regulatory constraints, air-gapped
//! systems, or adversarial deployment contexts) can instead use hash-based
//! polynomial commitments (FRI / Ligero / Brakedown).
//!
//! ## Setup modes
//!
//! | Mode | Setup | Proof size | Security assumption |
//! |------|-------|-----------|---------------------|
//! | [`SetupMode::Kzg`] | Powers-of-Tau ceremony | 192 B | q-SDH (algebraic) |
//! | [`SetupMode::Transparent`] | No ceremony | 5–50 KB | Collision-resistant hash |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use unigroth::transparent::{SetupMode, TransparentConfig};
//!
//! // Ceremony-free setup
//! let config = TransparentConfig::default();
//! let mode = SetupMode::Transparent(config);
//! println!("requires ceremony: {}", mode.requires_ceremony());
//! ```

use ark_std::{format, string::String, vec::Vec};

// ─── TransparentConfig ───────────────────────────────────────────────────────

/// Configuration for the transparent (no-ceremony) setup mode.
///
/// Controls the security level and the underlying hash-based commitment scheme
/// used for polynomial evaluations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentConfig {
    /// Target security level in bits. Must be at least 80; 128 recommended.
    pub security_bits: usize,
    /// Which hash-based commitment scheme to use.
    pub scheme: TransparentScheme,
}

/// Hash-based polynomial commitment scheme variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransparentScheme {
    /// FRI (Fast Reed-Solomon IOP of Proximity).
    /// Proof size: O(log² n) — plausibly post-quantum.
    Fri {
        /// Ratio of evaluation domain size to polynomial degree.
        blowup_factor: usize,
    },
    /// Ligero commitment (Ames et al., 2017).
    /// Proof size: O(√n) — minimal prover time.
    Ligero,
    /// Brakedown commitment (Golovnev et al., 2023).
    /// Proof size: O(n^{2/3}) — linear prover time.
    Brakedown,
}

impl TransparentConfig {
    /// Default: 128-bit FRI with blowup factor 4.
    pub fn default() -> Self {
        Self {
            security_bits: 128,
            scheme: TransparentScheme::Fri { blowup_factor: 4 },
        }
    }

    /// FRI configuration.
    pub fn fri(security_bits: usize, blowup_factor: usize) -> Self {
        assert!(security_bits >= 80, "security_bits must be at least 80");
        assert!(blowup_factor.is_power_of_two() && blowup_factor >= 2);
        Self {
            security_bits,
            scheme: TransparentScheme::Fri { blowup_factor },
        }
    }

    /// Ligero configuration.
    pub fn ligero(security_bits: usize) -> Self {
        Self {
            security_bits,
            scheme: TransparentScheme::Ligero,
        }
    }

    /// Brakedown configuration.
    pub fn brakedown(security_bits: usize) -> Self {
        Self {
            security_bits,
            scheme: TransparentScheme::Brakedown,
        }
    }

    /// Human-readable scheme name.
    pub fn scheme_name(&self) -> &'static str {
        match &self.scheme {
            TransparentScheme::Fri { .. } => "FRI",
            TransparentScheme::Ligero => "Ligero",
            TransparentScheme::Brakedown => "Brakedown",
        }
    }
}

// ─── SetupMode ───────────────────────────────────────────────────────────────

/// Chooses between KZG (trusted ceremony) and transparent (no ceremony) setup.
///
/// Pass this to the prover/verifier infrastructure to select the polynomial
/// commitment scheme used for the proving system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupMode {
    /// KZG polynomial commitment. Requires a Powers-of-Tau ceremony.
    /// Produces the smallest proofs (192 B) with the fastest verification.
    Kzg,
    /// Transparent polynomial commitment. No trusted setup required.
    /// Larger proofs but deployable without any ceremony.
    Transparent(TransparentConfig),
}

impl SetupMode {
    /// `true` if this mode requires a trusted Powers-of-Tau ceremony.
    pub fn requires_ceremony(&self) -> bool {
        matches!(self, SetupMode::Kzg)
    }

    /// `true` if this mode is transparent (no trusted setup needed).
    pub fn is_transparent(&self) -> bool {
        !self.requires_ceremony()
    }

    /// Human-readable name.
    pub fn name(&self) -> String {
        match self {
            SetupMode::Kzg => format!("KZG (trusted setup)"),
            SetupMode::Transparent(cfg) => {
                format!("Transparent/{} ({}b)", cfg.scheme_name(), cfg.security_bits)
            },
        }
    }

    /// Security level in bits.
    pub fn security_bits(&self) -> usize {
        match self {
            SetupMode::Kzg => 128,
            SetupMode::Transparent(cfg) => cfg.security_bits,
        }
    }
}

// ─── TransparentProofSize ────────────────────────────────────────────────────

/// Proof size estimator for transparent commitment schemes.
///
/// Computes the proof size in bytes for a polynomial of given degree under
/// a chosen transparent configuration.
#[derive(Clone, Debug)]
pub struct TransparentProofSize {
    /// Scheme configuration.
    pub config: TransparentConfig,
    /// Polynomial degree (number of coefficients).
    pub degree: usize,
}

impl TransparentProofSize {
    /// Construct for a given config and degree.
    pub fn new(config: TransparentConfig, degree: usize) -> Self {
        Self { config, degree }
    }

    /// Estimated proof size in bytes.
    pub fn estimate_bytes(&self) -> usize {
        match &self.config.scheme {
            TransparentScheme::Fri { blowup_factor } => {
                // FRI: num_queries × log2(domain_size) × 32 bytes per Merkle level
                let domain_size = self.degree * blowup_factor;
                let log2_blowup = blowup_factor.trailing_zeros() as usize;
                let num_queries = (self.config.security_bits + log2_blowup - 1) / log2_blowup;
                let levels = (domain_size.next_power_of_two()).trailing_zeros() as usize;
                num_queries * levels * 32
            },
            TransparentScheme::Ligero => {
                // Ligero: O(sqrt(n)) field elements
                let sqrt_n = (self.degree as f64).sqrt().ceil() as usize;
                // Each field element is 32 bytes; proof contains ~3 × sqrt_n elements
                3 * sqrt_n * 32
            },
            TransparentScheme::Brakedown => {
                // Brakedown: O(n^{2/3}) field elements
                let n_23 = (self.degree as f64).powf(2.0 / 3.0).ceil() as usize;
                2 * n_23 * 32
            },
        }
    }

    /// Compare proof sizes across all three transparent schemes for this degree.
    pub fn compare_schemes(degree: usize, security_bits: usize) -> Vec<(String, usize)> {
        let schemes: Vec<TransparentConfig> = vec![
            TransparentConfig::fri(security_bits, 4),
            TransparentConfig::ligero(security_bits),
            TransparentConfig::brakedown(security_bits),
        ];
        schemes
            .into_iter()
            .map(|cfg| {
                let name = format!("{} ({}b)", cfg.scheme_name(), security_bits);
                let size = TransparentProofSize::new(cfg, degree).estimate_bytes();
                (name, size)
            })
            .collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_mode_kzg() {
        let mode = SetupMode::Kzg;
        assert!(mode.requires_ceremony());
        assert!(!mode.is_transparent());
        assert_eq!(mode.security_bits(), 128);
        assert!(mode.name().contains("KZG"));
    }

    #[test]
    fn test_setup_mode_transparent_fri() {
        let cfg = TransparentConfig::fri(128, 4);
        let mode = SetupMode::Transparent(cfg);
        assert!(!mode.requires_ceremony());
        assert!(mode.is_transparent());
        assert_eq!(mode.security_bits(), 128);
        assert!(mode.name().contains("FRI"));
    }

    #[test]
    fn test_transparent_config_default() {
        let cfg = TransparentConfig::default();
        assert_eq!(cfg.security_bits, 128);
        assert_eq!(cfg.scheme_name(), "FRI");
    }

    #[test]
    fn test_transparent_config_ligero() {
        let cfg = TransparentConfig::ligero(128);
        assert_eq!(cfg.scheme_name(), "Ligero");
    }

    #[test]
    fn test_transparent_config_brakedown() {
        let cfg = TransparentConfig::brakedown(128);
        assert_eq!(cfg.scheme_name(), "Brakedown");
    }

    #[test]
    fn test_proof_size_fri_grows_with_degree() {
        let cfg = TransparentConfig::fri(128, 4);
        let small = TransparentProofSize::new(cfg.clone(), 256).estimate_bytes();
        let large = TransparentProofSize::new(cfg, 4096).estimate_bytes();
        assert!(large > small, "FRI proof size must grow with degree");
    }

    #[test]
    fn test_proof_size_ligero_grows_with_degree() {
        let cfg = TransparentConfig::ligero(128);
        let small = TransparentProofSize::new(cfg.clone(), 256).estimate_bytes();
        let large = TransparentProofSize::new(cfg, 4096).estimate_bytes();
        assert!(large > small);
    }

    #[test]
    fn test_proof_size_brakedown_grows_with_degree() {
        let cfg = TransparentConfig::brakedown(128);
        let small = TransparentProofSize::new(cfg.clone(), 256).estimate_bytes();
        let large = TransparentProofSize::new(cfg, 4096).estimate_bytes();
        assert!(large > small);
    }

    #[test]
    fn test_compare_schemes_returns_three() {
        let comparison = TransparentProofSize::compare_schemes(1024, 128);
        assert_eq!(comparison.len(), 3);
        for (name, size) in &comparison {
            assert!(!name.is_empty());
            assert!(*size > 0);
        }
    }

    #[test]
    fn test_kzg_much_smaller_than_transparent() {
        // KZG: 192 bytes. FRI: much larger for typical degrees.
        let fri_cfg = TransparentConfig::fri(128, 4);
        let fri_size = TransparentProofSize::new(fri_cfg, 1024).estimate_bytes();
        // KZG single-opening is 48 bytes; FRI for degree-1024 should be much larger
        assert!(fri_size > 192, "FRI proof must be larger than KZG");
    }

    #[test]
    fn test_setup_mode_clone_eq() {
        let m1 = SetupMode::Kzg;
        let m2 = m1.clone();
        assert_eq!(m1, m2);

        let cfg = TransparentConfig::default();
        let t1 = SetupMode::Transparent(cfg.clone());
        let t2 = t1.clone();
        assert_eq!(t1, t2);
    }

    #[test]
    #[should_panic]
    fn test_transparent_config_low_security_panics() {
        TransparentConfig::fri(79, 4); // 79 < 80 minimum
    }
}
