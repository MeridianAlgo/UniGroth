//! # Universal Setup for UniGroth
//!
//! Groth16 keys from one reusable, updatable ceremony, following
//! [BGM17](https://eprint.iacr.org/2017/1050) (the scheme behind Zcash Sapling
//! and snarkjs).
//!
//! **Phase 1 (universal).** [`UniversalParams`] holds only public group
//! elements: `τⁱG` (i < 2N−1), `τⁱH` (i < N), `ατⁱG`, `βτⁱG` (i < N) and `βH`.
//! Anyone can add randomness with [`UniversalParams::contribute`]; each
//! contribution carries Schnorr proofs of knowledge, and
//! [`UniversalParams::verify_contribution`] checks it. The result is secure if
//! *one* contributor was honest. The same parameters serve every circuit with
//! at most N constraints + public inputs.
//!
//! **Phase 2 (per circuit).** [`UniversalParams::derive_unblinded_keys`] turns
//! the Phase 1 parameters into Groth16 keys with γ = 1 and δ = 1 using only
//! public data (no trapdoor is ever held). Those keys are **forgeable until δ
//! is randomized**: [`contribute_delta`] multiplies δ by a secret, and
//! [`UniversalParams::verify_keys`] checks a whole chain of δ contributions
//! against the circuit. [`UniversalParams::derive_keys`] does one
//! contribution in-process: convenient, but the caller then knows δ and can
//! forge proofs *for that circuit only*.
//!
//! ```ignore
//! let mut params = UniversalParams::<Bn254>::identity(1 << 16);
//! let t1 = params.contribute(&mut rng1);                  // party 1
//! let t2 = params.contribute(&mut rng2);                  // party 2
//! assert!(params.verify_transcript(&[t1, t2]));           // anyone can check
//!
//! let mut pk = params.derive_unblinded_keys(circuit.clone())?;
//! let c1 = contribute_delta(&mut pk, &mut rng3);          // party 1
//! let c2 = contribute_delta(&mut pk, &mut rng4);          // party 2
//! assert!(params.verify_keys(circuit, &pk, &[c1, c2])?);
//! ```
//!
//! Keys target the default [`crate::r1cs_to_qap::LibsnarkReduction`] prover.

use crate::{ProvingKey, Vec, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
    Result as R1CSResult, SynthesisError, SynthesisMode, R1CS_PREDICATE_LABEL,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{cfg_iter, cfg_iter_mut, rand::RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

// ─── Proof of knowledge of a discrete log ───────────────────────────────────

/// Schnorr proof that the prover knows `x` with `target = x · base`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DlogProof<E: Pairing> {
    /// Commitment `k · base`.
    pub r: E::G1Affine,
    /// Response `k + c·x`.
    pub z: E::ScalarField,
}

/// Hash `parts` (with length prefixes) into the scalar field.
fn hash_to_scalar<F: PrimeField>(label: &[u8], parts: &[&[u8]]) -> F {
    let mut h = Sha256::new()
        .chain_update(crate::config::DOMAIN_SETUP_POK)
        .chain_update(label);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    // 64 bytes of output so the reduction mod p is close to uniform.
    let lo = h.clone().chain_update([0u8]).finalize();
    let hi = h.chain_update([1u8]).finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&lo);
    wide[32..].copy_from_slice(&hi);
    F::from_le_bytes_mod_order(&wide)
}

fn statement_bytes<E: Pairing>(base: &E::G1Affine, target: &E::G1Affine) -> Vec<u8> {
    let mut buf = Vec::new();
    (base, target)
        .serialize_compressed(&mut buf)
        .expect("serializing to a Vec cannot fail");
    buf
}

impl<E: Pairing> DlogProof<E> {
    /// Prove knowledge of `x` such that `target = x · base`.
    ///
    /// `context` binds the proof to where it is used (ceremony phase, slot,
    /// circuit), so it cannot be presented anywhere else. The nonce is
    /// hedged: derived from `x`, the statement and fresh randomness, so a
    /// weak or repeated RNG does not leak `x`.
    pub fn prove(
        base: &E::G1Affine,
        target: &E::G1Affine,
        x: &E::ScalarField,
        context: &[u8],
        rng: &mut impl RngCore,
    ) -> Self {
        let stmt = statement_bytes::<E>(base, target);
        let mut secret = Vec::new();
        x.serialize_compressed(&mut secret)
            .expect("serializing to a Vec cannot fail");
        let mut fresh = [0u8; 32];
        rng.fill_bytes(&mut fresh);
        let mut k: E::ScalarField =
            hash_to_scalar(b"dlog-nonce", &[&secret, context, &stmt, &fresh]);
        secret.zeroize();
        fresh.zeroize();

        let r = (*base * k).into_affine();
        let c = Self::challenge(&stmt, context, &r);
        let z = k + c * x;
        k.zeroize();
        Self { r, z }
    }

    /// Check the proof for `context`. Rejects identity bases and targets.
    pub fn verify(&self, base: &E::G1Affine, target: &E::G1Affine, context: &[u8]) -> bool {
        if base.is_zero() || target.is_zero() || self.r.check().is_err() {
            return false;
        }
        let c = Self::challenge(&statement_bytes::<E>(base, target), context, &self.r);
        *base * self.z == self.r.into_group() + *target * c
    }

    fn challenge(stmt: &[u8], context: &[u8], r: &E::G1Affine) -> E::ScalarField {
        let mut r_bytes = Vec::new();
        r.serialize_compressed(&mut r_bytes)
            .expect("serializing to a Vec cannot fail");
        hash_to_scalar(b"dlog-challenge", &[stmt, context, &r_bytes])
    }
}

/// Proof-of-knowledge context for one Phase 1 slot in a setup of `n` powers.
fn phase1_context(slot: &[u8], n: usize) -> Vec<u8> {
    [b"phase1/".as_slice(), slot, &(n as u64).to_le_bytes()].concat()
}

/// Digest of the parts of a proving key that Phase 2 never changes; it
/// identifies the circuit (and Phase 1 parameters) a δ contribution is for.
pub fn circuit_digest<E: Pairing>(pk: &ProvingKey<E>) -> [u8; 32] {
    let mut buf = Vec::new();
    (&pk.vk.alpha_g1, &pk.vk.beta_g2, &pk.vk.gamma_abc_g1)
        .serialize_compressed(&mut buf)
        .expect("serializing to a Vec cannot fail");
    (&pk.a_query, &pk.b_g1_query, &(pk.h_query.len() as u64))
        .serialize_compressed(&mut buf)
        .expect("serializing to a Vec cannot fail");
    Sha256::new()
        .chain_update(crate::config::DOMAIN_SETUP_POK)
        .chain_update(b"circuit")
        .chain_update(&buf)
        .finalize()
        .into()
}

fn phase2_context(digest: &[u8; 32]) -> Vec<u8> {
    [b"phase2/".as_slice(), digest].concat()
}

fn nonzero_scalar<F: Field>(rng: &mut impl RngCore) -> F {
    crate::nonzero_rand(rng)
}

/// Weights ρ⁰, ρ¹, … for random linear combinations, with ρ hashed from `data`
/// so they are fixed only after everything they check is fixed.
fn fs_powers<F: PrimeField>(label: &[u8], data: &impl CanonicalSerialize, n: usize) -> Vec<F> {
    let mut buf = Vec::new();
    data.serialize_compressed(&mut buf)
        .expect("serializing to a Vec cannot fail");
    let digest = Sha256::new()
        .chain_update(crate::config::DOMAIN_SETUP_POK)
        .chain_update(label)
        .chain_update(&buf)
        .finalize();
    let rho = F::from_le_bytes_mod_order(&digest);
    let mut out = Vec::with_capacity(n);
    let mut acc = F::one();
    for _ in 0..n {
        out.push(acc);
        acc *= rho;
    }
    out
}

fn scale_all<G: CurveGroup>(points: &mut [G::Affine], scalars: &[G::ScalarField]) {
    let scaled: Vec<G> = cfg_iter!(points)
        .zip(scalars)
        .map(|(p, s)| *p * s)
        .collect();
    points.copy_from_slice(&G::normalize_batch(&scaled));
}

// ─── Phase 1 ─────────────────────────────────────────────────────────────────

/// Public, universal Phase 1 parameters (no secrets).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniversalParams<E: Pairing> {
    /// `τⁱ·G` for i < 2N−1, where `G` is the G1 generator.
    pub tau_g1: Vec<E::G1Affine>,
    /// `τⁱ·H` for i < N, where `H` is the G2 generator.
    pub tau_g2: Vec<E::G2Affine>,
    /// `α·τⁱ·G` for i < N.
    pub alpha_tau_g1: Vec<E::G1Affine>,
    /// `β·τⁱ·G` for i < N.
    pub beta_tau_g1: Vec<E::G1Affine>,
    /// `β·H`.
    pub beta_g2: E::G2Affine,
}

/// Proof that a Phase 1 contribution multiplied τ, α, β by known factors.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Proof<E: Pairing> {
    /// `τ·G` after this contribution.
    pub tau_g1: E::G1Affine,
    /// `α·G` after this contribution.
    pub alpha_g1: E::G1Affine,
    /// `β·G` after this contribution.
    pub beta_g1: E::G1Affine,
    /// Knowledge of the τ factor.
    pub tau: DlogProof<E>,
    /// Knowledge of the α factor.
    pub alpha: DlogProof<E>,
    /// Knowledge of the β factor.
    pub beta: DlogProof<E>,
}

impl<E: Pairing> Phase1Proof<E> {
    /// Each new anchor is a known multiple of the previous one, for a setup
    /// of `n` powers.
    fn extends(&self, n: usize, tau: E::G1Affine, alpha: E::G1Affine, beta: E::G1Affine) -> bool {
        self.tau
            .verify(&tau, &self.tau_g1, &phase1_context(b"tau", n))
            && self
                .alpha
                .verify(&alpha, &self.alpha_g1, &phase1_context(b"alpha", n))
            && self
                .beta
                .verify(&beta, &self.beta_g1, &phase1_context(b"beta", n))
    }
}

impl<E: Pairing> UniversalParams<E> {
    /// Parameters with τ = α = β = 1. Insecure on their own; every real setup
    /// starts here and applies at least one [`Self::contribute`].
    pub fn identity(max_domain_size: usize) -> Self {
        let n = max_domain_size.max(2).next_power_of_two();
        let g = E::G1Affine::generator();
        let h = E::G2Affine::generator();
        Self {
            tau_g1: vec![g; 2 * n - 1],
            tau_g2: vec![h; n],
            alpha_tau_g1: vec![g; n],
            beta_tau_g1: vec![g; n],
            beta_g2: h,
        }
    }

    /// Single-party setup: [`Self::identity`] plus one contribution. Fine for
    /// tests; production should chain contributions from independent parties.
    pub fn setup(max_domain_size: usize, rng: &mut impl RngCore) -> Self {
        let mut params = Self::identity(max_domain_size);
        params.contribute(rng);
        params
    }

    /// Largest supported QAP domain (constraints + public inputs, rounded up
    /// to a power of two).
    pub fn max_domain_size(&self) -> usize {
        self.tau_g2.len()
    }

    /// Multiply τ, α, β by fresh secret factors and return the proof that the
    /// new parameters extend the old ones. The factors are erased afterwards.
    pub fn contribute(&mut self, rng: &mut impl RngCore) -> Phase1Proof<E> {
        let mut x = nonzero_scalar::<E::ScalarField>(rng);
        let mut a = nonzero_scalar::<E::ScalarField>(rng);
        let mut b = nonzero_scalar::<E::ScalarField>(rng);
        let old = (self.tau_g1[1], self.alpha_tau_g1[0], self.beta_tau_g1[0]);

        let mut powers: Vec<E::ScalarField> = Vec::with_capacity(self.tau_g1.len());
        let mut acc = E::ScalarField::one();
        for _ in 0..self.tau_g1.len() {
            powers.push(acc);
            acc *= x;
        }
        let n = self.tau_g2.len();
        let mut a_powers: Vec<_> = powers[..n].iter().map(|p| *p * a).collect();
        let mut b_powers: Vec<_> = powers[..n].iter().map(|p| *p * b).collect();

        scale_all::<E::G1>(&mut self.tau_g1, &powers);
        scale_all::<E::G2>(&mut self.tau_g2, &powers[..n]);
        scale_all::<E::G1>(&mut self.alpha_tau_g1, &a_powers);
        scale_all::<E::G1>(&mut self.beta_tau_g1, &b_powers);
        self.beta_g2 = (self.beta_g2 * b).into_affine();

        let proof = Phase1Proof {
            tau_g1: self.tau_g1[1],
            alpha_g1: self.alpha_tau_g1[0],
            beta_g1: self.beta_tau_g1[0],
            tau: DlogProof::prove(&old.0, &self.tau_g1[1], &x, &phase1_context(b"tau", n), rng),
            alpha: DlogProof::prove(
                &old.1,
                &self.alpha_tau_g1[0],
                &a,
                &phase1_context(b"alpha", n),
                rng,
            ),
            beta: DlogProof::prove(
                &old.2,
                &self.beta_tau_g1[0],
                &b,
                &phase1_context(b"beta", n),
                rng,
            ),
        };

        for v in [&mut powers, &mut a_powers, &mut b_powers] {
            v.iter_mut().for_each(Zeroize::zeroize);
        }
        x.zeroize();
        a.zeroize();
        b.zeroize();
        acc.zeroize();
        proof
    }

    /// Final contribution from a public random beacon (e.g. a future block
    /// hash), stretched by `hash_iterations` rounds of SHA-256. Nobody knows the
    /// beacon in advance, so the last human contributor cannot steer the
    /// result, and anyone can recompute this step with
    /// [`Self::verify_beacon_contribution`].
    pub fn contribute_from_beacon(
        &mut self,
        beacon: &[u8],
        hash_iterations: u64,
    ) -> Phase1Proof<E> {
        self.contribute(&mut BeaconRng::new(b"phase1", beacon, hash_iterations))
    }

    /// Recompute the beacon step on `prev` and check it produced `next` and `proof`.
    pub fn verify_beacon_contribution(
        prev: &Self,
        next: &Self,
        proof: &Phase1Proof<E>,
        beacon: &[u8],
        hash_iterations: u64,
    ) -> bool {
        let mut expected = prev.clone();
        let expected_proof = expected.contribute_from_beacon(beacon, hash_iterations);
        expected == *next && expected_proof == *proof
    }

    /// Check that `next` is a valid contribution on top of `prev`.
    pub fn verify_contribution(prev: &Self, next: &Self, proof: &Phase1Proof<E>) -> bool {
        prev.tau_g1.len() == next.tau_g1.len()
            && prev.tau_g2.len() == next.tau_g2.len()
            && next.is_well_formed()
            && proof.extends(
                next.tau_g2.len(),
                prev.tau_g1[1],
                prev.alpha_tau_g1[0],
                prev.beta_tau_g1[0],
            )
            && next.ends_at(proof)
    }

    /// Check a whole ceremony: `transcript` lists every contribution, in
    /// order, starting from [`Self::identity`], and `self` is its result.
    /// Only the three anchor points per step are needed, not every
    /// intermediate parameter set. Secure if any one contributor was honest.
    pub fn verify_transcript(&self, transcript: &[Phase1Proof<E>]) -> bool {
        let Some(last) = transcript.last() else {
            return false; // the identity parameters have known trapdoors
        };
        let g = E::G1Affine::generator();
        let mut prev = (g, g, g);
        let n = self.tau_g2.len();
        for step in transcript {
            if !step.extends(n, prev.0, prev.1, prev.2) {
                return false;
            }
            prev = (step.tau_g1, step.alpha_g1, step.beta_g1);
        }
        self.ends_at(last) && self.is_well_formed()
    }

    fn ends_at(&self, step: &Phase1Proof<E>) -> bool {
        self.tau_g1[1] == step.tau_g1
            && self.alpha_tau_g1[0] == step.alpha_g1
            && self.beta_tau_g1[0] == step.beta_g1
    }

    /// Build parameters from an external Powers-of-Tau transcript (e.g. a
    /// Perpetual Powers of Tau or snarkjs `.ptau` phase 1), rejecting anything
    /// that is not correctly structured.
    pub fn from_transcript(
        tau_g1: Vec<E::G1Affine>,
        tau_g2: Vec<E::G2Affine>,
        alpha_tau_g1: Vec<E::G1Affine>,
        beta_tau_g1: Vec<E::G1Affine>,
        beta_g2: E::G2Affine,
    ) -> Option<Self> {
        let params = Self {
            tau_g1,
            tau_g2,
            alpha_tau_g1,
            beta_tau_g1,
            beta_g2,
        };
        params.is_well_formed().then_some(params)
    }

    /// Structural check: correct lengths, anchored generators, valid points and
    /// consistent powers of one τ with one α and one β. All ratio checks are
    /// folded into a single multi-pairing with Fiat-Shamir weights.
    pub fn is_well_formed(&self) -> bool {
        let n = self.tau_g2.len();
        let g = E::G1Affine::generator();
        let h = E::G2Affine::generator();
        if n < 2
            || !n.is_power_of_two()
            || self.tau_g1.len() != 2 * n - 1
            || self.alpha_tau_g1.len() != n
            || self.beta_tau_g1.len() != n
            || self.tau_g1[0] != g
            || self.tau_g2[0] != h
            || self.check().is_err()
        {
            return false;
        }
        let key_points_nonzero = !self.tau_g1[1].is_zero()
            && !self.tau_g2[1].is_zero()
            && !self.alpha_tau_g1[0].is_zero()
            && !self.beta_tau_g1[0].is_zero()
            && !self.beta_g2.is_zero();
        if !key_points_nonzero {
            return false;
        }

        // Σρⁱ·P[i+1] paired with H must equal Σρⁱ·P[i] paired with τH.
        let rho: Vec<E::ScalarField> = fs_powers(b"phase1-shape", self, 2 * n - 2);
        let mu: Vec<E::ScalarField> = fs_powers(b"phase1-checks", &rho[1], 5);
        let shift = |v: &[E::G1Affine], w: &[E::ScalarField]| -> (E::G1, E::G1) {
            let k = v.len() - 1;
            (
                E::G1::msm(&v[1..], &w[..k]).expect("lengths match"),
                E::G1::msm(&v[..k], &w[..k]).expect("lengths match"),
            )
        };
        let (t_hi, t_lo) = shift(&self.tau_g1, &rho);
        let (a_hi, a_lo) = shift(&self.alpha_tau_g1, &rho);
        let (b_hi, b_lo) = shift(&self.beta_tau_g1, &rho);
        let k = n - 1;
        let h_hi = E::G2::msm(&self.tau_g2[1..], &rho[..k]).expect("lengths match");
        let h_lo = E::G2::msm(&self.tau_g2[..k], &rho[..k]).expect("lengths match");

        // (1) τ in G1  (2) τ in G2  (3) α-powers  (4) β-powers  (5) βG1 ↔ βH
        let with_h = t_hi * mu[0] + a_hi * mu[2] + b_hi * mu[3] + self.beta_tau_g1[0] * mu[4];
        let with_tau_h = -(t_lo * mu[0] + a_lo * mu[2] + b_lo * mu[3]);
        let g1 = E::G1::normalize_batch(&[
            with_h,
            with_tau_h,
            g * mu[1],
            -(self.tau_g1[1] * mu[1]),
            -(g * mu[4]),
        ]);
        let g2 = E::G2::normalize_batch(&[
            h.into_group(),
            self.tau_g2[1].into_group(),
            h_hi,
            h_lo,
            self.beta_g2.into_group(),
        ]);
        E::multi_pairing(g1, g2).is_zero()
    }

    // ─── Phase 2 ─────────────────────────────────────────────────────────────

    /// Derive Groth16 keys for `circuit` with γ = 1 and δ = 1 from public data.
    ///
    /// **Not safe to prove with**: anyone can forge until at least one honest
    /// [`contribute_delta`] has been applied. Deterministic, so verifiers can
    /// recompute it (see [`Self::verify_keys`]).
    pub fn derive_unblinded_keys<C>(&self, circuit: C) -> R1CSResult<ProvingKey<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let cs = synthesize(circuit)?;
        let bases = self
            .lagrange_bases(qap_domain_size(&cs)?)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        self.keys_from(&cs, &bases)
    }

    /// Like [`Self::derive_unblinded_keys`] but with precomputed
    /// [`LagrangeBases`], which turns the dominant O(n log n) group FFTs into a
    /// one-off cost per domain size. The bases are checked against these
    /// parameters first, so a corrupted cache cannot produce wrong keys.
    pub fn derive_unblinded_keys_with<C>(
        &self,
        bases: &LagrangeBases<E>,
        circuit: C,
    ) -> R1CSResult<ProvingKey<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        if !bases.is_consistent_with(self) {
            return Err(SynthesisError::Unsatisfiable);
        }
        let cs = synthesize(circuit)?;
        self.keys_from(&cs, bases)
    }

    /// Lagrange-basis form of these parameters for a QAP domain of
    /// `domain_size` (a power of two ≤ [`Self::max_domain_size`]): the inverse
    /// DFT of the τ-powers in each group. A pure function of public data;
    /// compute it once per size and reuse it for every circuit.
    pub fn lagrange_bases(&self, domain_size: usize) -> Option<LagrangeBases<E>> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(domain_size)?;
        let n = domain.size();
        if n != domain_size || n > self.max_domain_size() {
            return None;
        }
        let time = start_timer!(|| format!("Lagrange bases (n = {n})"));
        fn ifft<G: CurveGroup>(
            d: &GeneralEvaluationDomain<G::ScalarField>,
            powers: &[G::Affine],
        ) -> Vec<G::Affine> {
            let proj: Vec<G> = powers.iter().map(|p| p.into_group()).collect();
            G::normalize_batch(&d.ifft(&proj))
        }
        let bases = LagrangeBases {
            g1: ifft::<E::G1>(&domain, &self.tau_g1[..n]),
            alpha_g1: ifft::<E::G1>(&domain, &self.alpha_tau_g1[..n]),
            beta_g1: ifft::<E::G1>(&domain, &self.beta_tau_g1[..n]),
            g2: ifft::<E::G2>(&domain, &self.tau_g2[..n]),
        };
        end_timer!(time);
        Some(bases)
    }

    fn keys_from(
        &self,
        cs: &ConstraintSystemRef<E::ScalarField>,
        bases: &LagrangeBases<E>,
    ) -> R1CSResult<ProvingKey<E>> {
        let derive_time = start_timer!(|| "Derive keys from universal params");
        let num_constraints = cs.num_constraints();
        let num_inputs = cs.num_instance_variables();
        let num_vars = num_inputs + cs.num_witness_variables();
        let n = qap_domain_size(cs)?;
        if n > self.max_domain_size() {
            return Err(SynthesisError::PolynomialDegreeTooLarge);
        }
        if bases.g1.len() != n {
            return Err(SynthesisError::Unsatisfiable);
        }
        let matrices = &cs.to_matrices()?[R1CS_PREDICATE_LABEL];

        // Transpose the constraint rows into per-variable columns. The libsnark
        // reduction also puts public input i on row num_constraints + i of A.
        let mut cols: [Vec<Vec<(usize, E::ScalarField)>>; 3] =
            core::array::from_fn(|_| vec![Vec::new(); num_vars]);
        for (k, matrix) in matrices.iter().take(3).enumerate() {
            for (row, entries) in matrix.iter().enumerate() {
                for &(coeff, var) in entries {
                    cols[k][var].push((row, coeff));
                }
            }
        }
        for i in 0..num_inputs {
            cols[0][i].push((num_constraints + i, E::ScalarField::one()));
        }
        let [col_a, col_b, col_c] = &cols;

        // Columns are short and mostly have coefficient 1, so direct sums beat
        // a Pippenger MSM here.
        fn combine<G: CurveGroup>(terms: &[(&[(usize, G::ScalarField)], &[G::Affine])]) -> G {
            let mut acc = G::zero();
            for (col, basis) in terms {
                for &(row, s) in col.iter() {
                    if s.is_one() {
                        acc += basis[row];
                    } else {
                        acc += basis[row] * s;
                    }
                }
            }
            acc
        }

        let (lag_g1, lag_g2) = (&bases.g1[..], &bases.g2[..]);
        let a_query: Vec<E::G1> = cfg_iter!(col_a)
            .map(|c| combine::<E::G1>(&[(&c[..], lag_g1)]))
            .collect();
        let b_g1_query: Vec<E::G1> = cfg_iter!(col_b)
            .map(|c| combine::<E::G1>(&[(&c[..], lag_g1)]))
            .collect();
        let b_g2_query: Vec<E::G2> = cfg_iter!(col_b)
            .map(|c| combine::<E::G2>(&[(&c[..], lag_g2)]))
            .collect();
        // (β·uᵢ + α·vᵢ + wᵢ)(τ)·G, divided by γ = 1 (inputs) or δ = 1 (witness).
        let k_query: Vec<E::G1> = cfg_into_iter_range(num_vars)
            .map(|i| {
                combine::<E::G1>(&[
                    (&col_a[i][..], &bases.beta_g1[..]),
                    (&col_b[i][..], &bases.alpha_g1[..]),
                    (&col_c[i][..], lag_g1),
                ])
            })
            .collect();
        let k_query = E::G1::normalize_batch(&k_query);

        // H query: Z(τ)·τⁱ·G = τⁿ⁺ⁱ·G − τⁱ·G for i < n−1.
        let h_query: Vec<E::G1> = (0..n - 1)
            .map(|i| self.tau_g1[n + i].into_group() - self.tau_g1[i])
            .collect();
        if h_query[0].is_zero() {
            // τ is an n-th root of unity: Z(τ) = 0 and the keys would be unsound.
            return Err(SynthesisError::Unsatisfiable);
        }

        let vk = VerifyingKey {
            alpha_g1: self.alpha_tau_g1[0],
            beta_g2: self.beta_g2,
            gamma_g2: E::G2Affine::generator(),
            delta_g2: E::G2Affine::generator(),
            gamma_abc_g1: k_query[..num_inputs].to_vec(),
        };
        end_timer!(derive_time);
        Ok(ProvingKey {
            vk,
            beta_g1: self.beta_tau_g1[0],
            delta_g1: E::G1Affine::generator(),
            a_query: E::G1::normalize_batch(&a_query),
            b_g1_query: E::G1::normalize_batch(&b_g1_query),
            b_g2_query: E::G2::normalize_batch(&b_g2_query),
            h_query: E::G1::normalize_batch(&h_query),
            l_query: k_query[num_inputs..].to_vec(),
        })
    }

    /// Derive keys and apply one δ contribution from `rng`.
    ///
    /// The caller learns δ and could forge proofs **for this circuit**; use
    /// [`Self::derive_unblinded_keys`] + several [`contribute_delta`] calls by
    /// independent parties when that matters.
    pub fn derive_keys<C>(
        &self,
        circuit: C,
        rng: &mut impl RngCore,
    ) -> R1CSResult<(ProvingKey<E>, VerifyingKey<E>)>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let mut pk = self.derive_unblinded_keys(circuit)?;
        contribute_delta(&mut pk, rng);
        let vk = pk.vk.clone();
        Ok((pk, vk))
    }

    /// Check that `pk` is the key for `circuit` derived from these parameters
    /// after the δ contributions in `transcript`, in order. An empty transcript
    /// is rejected: δ = 1 keys are forgeable.
    pub fn verify_keys<C>(
        &self,
        circuit: C,
        pk: &ProvingKey<E>,
        transcript: &[DeltaContribution<E>],
    ) -> R1CSResult<bool>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let base = self.derive_unblinded_keys(circuit)?;
        Ok(verify_delta_chain(&base, pk, transcript))
    }

    /// [`Self::verify_keys`] with precomputed (and re-checked) [`LagrangeBases`].
    pub fn verify_keys_with<C>(
        &self,
        bases: &LagrangeBases<E>,
        circuit: C,
        pk: &ProvingKey<E>,
        transcript: &[DeltaContribution<E>],
    ) -> R1CSResult<bool>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let base = self.derive_unblinded_keys_with(bases, circuit)?;
        Ok(verify_delta_chain(&base, pk, transcript))
    }
}

#[cfg(feature = "parallel")]
fn cfg_into_iter_range(n: usize) -> rayon::range::Iter<usize> {
    (0..n).into_par_iter()
}
#[cfg(not(feature = "parallel"))]
fn cfg_into_iter_range(n: usize) -> core::ops::Range<usize> {
    0..n
}

fn synthesize<F: PrimeField, C: ConstraintSynthesizer<F>>(
    circuit: C,
) -> R1CSResult<ConstraintSystemRef<F>> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    Ok(cs)
}

/// Size of the QAP domain the prover will use for `cs`.
fn qap_domain_size<F: PrimeField>(cs: &ConstraintSystemRef<F>) -> R1CSResult<usize> {
    GeneralEvaluationDomain::<F>::new(cs.num_constraints() + cs.num_instance_variables())
        .map(|d| d.size())
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)
}

/// Phase 1 parameters in Lagrange form for one domain size; see
/// [`UniversalParams::lagrange_bases`].
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct LagrangeBases<E: Pairing> {
    /// `Lⱼ(τ)·G`.
    pub g1: Vec<E::G1Affine>,
    /// `α·Lⱼ(τ)·G`.
    pub alpha_g1: Vec<E::G1Affine>,
    /// `β·Lⱼ(τ)·G`.
    pub beta_g1: Vec<E::G1Affine>,
    /// `Lⱼ(τ)·H`.
    pub g2: Vec<E::G2Affine>,
}

impl<E: Pairing> LagrangeBases<E> {
    /// Check these bases are the inverse DFT of `params`' powers without
    /// redoing the FFT: for random r, Σ rⱼ·Lⱼ must equal Σ IFFT(r)ᵢ·τⁱ (the
    /// DFT matrix is symmetric). Costs a few size-n MSMs.
    pub fn is_consistent_with(&self, params: &UniversalParams<E>) -> bool {
        let n = self.g1.len();
        let Some(domain) = GeneralEvaluationDomain::<E::ScalarField>::new(n) else {
            return false;
        };
        if domain.size() != n
            || n > params.max_domain_size()
            || self.alpha_g1.len() != n
            || self.beta_g1.len() != n
            || self.g2.len() != n
            || self.check().is_err()
        {
            return false;
        }
        let r: Vec<E::ScalarField> = fs_powers(b"lagrange", &(params, self), n);
        let s = domain.ifft(&r);
        let g1_eq = |lag: &[E::G1Affine], pow: &[E::G1Affine]| {
            E::G1::msm_unchecked(lag, &r) == E::G1::msm_unchecked(&pow[..n], &s)
        };
        g1_eq(&self.g1, &params.tau_g1)
            && g1_eq(&self.alpha_g1, &params.alpha_tau_g1)
            && g1_eq(&self.beta_g1, &params.beta_tau_g1)
            && E::G2::msm_unchecked(&self.g2, &r) == E::G2::msm_unchecked(&params.tau_g2[..n], &s)
    }
}

// ─── Phase 2 contributions ──────────────────────────────────────────────────

/// One Phase 2 contribution: the new `δ·G` and a proof of knowledge of the
/// factor that took the previous `δ·G` to it.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeltaContribution<E: Pairing> {
    /// `δ·G` after this contribution.
    pub delta_g1: E::G1Affine,
    /// Knowledge of the multiplier.
    pub proof: DlogProof<E>,
}

/// Multiply δ by a fresh secret `d`: δ·G and δ·H scale by `d`, the L and H
/// queries by `1/d`. `d` is erased afterwards.
pub fn contribute_delta<E: Pairing>(
    pk: &mut ProvingKey<E>,
    rng: &mut impl RngCore,
) -> DeltaContribution<E> {
    let mut d = nonzero_scalar::<E::ScalarField>(rng);
    let mut d_inv = d.inverse().expect("d is non-zero");
    let old = pk.delta_g1;

    pk.delta_g1 = (pk.delta_g1 * d).into_affine();
    pk.vk.delta_g2 = (pk.vk.delta_g2 * d).into_affine();
    let rescale = |v: &mut Vec<E::G1Affine>| {
        let scaled: Vec<E::G1> = cfg_iter_mut!(v).map(|p| *p * d_inv).collect();
        *v = E::G1::normalize_batch(&scaled);
    };
    rescale(&mut pk.l_query);
    rescale(&mut pk.h_query);

    let context = phase2_context(&circuit_digest(pk));
    let proof = DlogProof::prove(&old, &pk.delta_g1, &d, &context, rng);
    d.zeroize();
    d_inv.zeroize();
    DeltaContribution {
        delta_g1: pk.delta_g1,
        proof,
    }
}

/// Final δ contribution from a public random beacon; see
/// [`UniversalParams::contribute_from_beacon`]. It is an ordinary
/// [`DeltaContribution`], so [`verify_delta_chain`] checks it like any other;
/// [`verify_delta_beacon`] additionally checks it came from the beacon.
pub fn contribute_delta_from_beacon<E: Pairing>(
    pk: &mut ProvingKey<E>,
    beacon: &[u8],
    hash_iterations: u64,
) -> DeltaContribution<E> {
    contribute_delta(pk, &mut BeaconRng::new(b"phase2", beacon, hash_iterations))
}

/// Recompute the δ beacon step on `prev` and check it produced `next` and `step`.
pub fn verify_delta_beacon<E: Pairing>(
    prev: &ProvingKey<E>,
    next: &ProvingKey<E>,
    step: &DeltaContribution<E>,
    beacon: &[u8],
    hash_iterations: u64,
) -> bool {
    let mut expected = prev.clone();
    let expected_step = contribute_delta_from_beacon(&mut expected, beacon, hash_iterations);
    expected == *next && expected_step == *step
}

/// Deterministic RNG for beacon steps: SHA-256 in counter mode, keyed by the
/// beacon after `hash_iterations` rounds of sequential hashing (the delay makes
/// it costly to precompute outcomes for many candidate beacons).
struct BeaconRng {
    key: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    used: usize,
}

impl BeaconRng {
    fn new(phase: &[u8], beacon: &[u8], hash_iterations: u64) -> Self {
        let mut key: [u8; 32] = Sha256::new()
            .chain_update(crate::config::DOMAIN_SETUP_POK)
            .chain_update(b"beacon/")
            .chain_update(phase)
            .chain_update((beacon.len() as u64).to_le_bytes())
            .chain_update(beacon)
            .finalize()
            .into();
        for _ in 0..hash_iterations {
            key = Sha256::digest(key).into();
        }
        Self {
            key,
            counter: 0,
            buf: [0; 32],
            used: 32,
        }
    }
}

impl RngCore for BeaconRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.used == 32 {
                self.buf = Sha256::new()
                    .chain_update(self.key)
                    .chain_update(self.counter.to_le_bytes())
                    .finalize()
                    .into();
                self.counter += 1;
                self.used = 0;
            }
            *byte = self.buf[self.used];
            self.used += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Check `pk` against the unblinded `base` key and a non-empty chain of δ
/// contributions.
pub fn verify_delta_chain<E: Pairing>(
    base: &ProvingKey<E>,
    pk: &ProvingKey<E>,
    transcript: &[DeltaContribution<E>],
) -> bool {
    let Some(last) = transcript.last() else {
        return false;
    };
    // Everything except δ, L and H must be exactly the derived key.
    let same_shape = pk.vk.alpha_g1 == base.vk.alpha_g1
        && pk.vk.beta_g2 == base.vk.beta_g2
        && pk.vk.gamma_g2 == base.vk.gamma_g2
        && pk.vk.gamma_abc_g1 == base.vk.gamma_abc_g1
        && pk.beta_g1 == base.beta_g1
        && pk.a_query == base.a_query
        && pk.b_g1_query == base.b_g1_query
        && pk.b_g2_query == base.b_g2_query
        && pk.l_query.len() == base.l_query.len()
        && pk.h_query.len() == base.h_query.len()
        && pk.delta_g1 == last.delta_g1
        && pk.delta_g1.check().is_ok()
        && pk.vk.delta_g2.check().is_ok()
        && pk.l_query.check().is_ok()
        && pk.h_query.check().is_ok();
    if !same_shape {
        return false;
    }
    // Each step proves knowledge of its multiplier.
    let context = phase2_context(&circuit_digest(base));
    let mut prev = base.delta_g1;
    for step in transcript {
        if !step.proof.verify(&prev, &step.delta_g1, &context) {
            return false;
        }
        prev = step.delta_g1;
    }
    // δ·H matches δ·G, and every L, H element was divided by the same δ:
    //   e(δG, H) = e(G, δH)   and   e(Σρⁱ·Xᵢ, δH) = e(Σρⁱ·Xᵢ_base, H).
    let n = pk.l_query.len() + pk.h_query.len();
    let rho: Vec<E::ScalarField> = fs_powers(b"phase2", &(pk, transcript), n + 1);
    let new_bases: Vec<E::G1Affine> = pk.l_query.iter().chain(&pk.h_query).copied().collect();
    let old_bases: Vec<E::G1Affine> = base.l_query.iter().chain(&base.h_query).copied().collect();
    let new_sum = E::G1::msm(&new_bases, &rho[1..]).expect("lengths match");
    let old_sum = E::G1::msm(&old_bases, &rho[1..]).expect("lengths match");
    let g = E::G1::generator();
    let h = E::G2Affine::generator();
    let g1 = E::G1::normalize_batch(&[pk.delta_g1.into_group(), -g, new_sum, -old_sum]);
    let g2 = [h, pk.vk.delta_g2, pk.vk.delta_g2, h];
    // Fold the two equations with a hash-derived weight w (a constant weight
    // would let errors in one equation cancel errors in the other).
    let w = fs_powers::<E::ScalarField>(b"phase2-fold", &rho[1], 2)[1];
    let g1: Vec<E::G1Affine> = vec![
        g1[0],
        g1[1],
        (g1[2] * w).into_affine(),
        (g1[3] * w).into_affine(),
    ];
    E::multi_pairing(g1, g2).is_zero()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[derive(Clone)]
    struct TestCircuit {
        x: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let x_squared = cs.new_input_variable(|| {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val)
            })?;
            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + x, || lc!() + x_squared)
        }
    }

    fn prove_and_verify(pk: &ProvingKey<Bn254>, x: u64, rng: &mut StdRng) -> bool {
        let x = Fr::from(x);
        let proof = Groth16::<Bn254>::prove(pk, TestCircuit { x: Some(x) }, rng).unwrap();
        let pvk = crate::prepare_verifying_key(&pk.vk);
        Groth16::<Bn254>::verify_proof(&pvk, &proof, &[x * x]).unwrap()
    }

    #[test]
    fn test_universal_setup() {
        let mut rng = StdRng::seed_from_u64(1);
        let params = UniversalParams::<Bn254>::setup(64, &mut rng);
        assert!(params.is_well_formed());
        let (pk, _vk) = params
            .derive_keys(TestCircuit { x: None }, &mut rng)
            .unwrap();
        assert!(prove_and_verify(&pk, 3, &mut rng));
    }

    #[test]
    fn test_universal_setup_multiple_circuits() {
        let mut rng = StdRng::seed_from_u64(2);
        let params = UniversalParams::<Bn254>::setup(64, &mut rng);
        for i in 1..=3 {
            let (pk, _) = params
                .derive_keys(TestCircuit { x: None }, &mut rng)
                .unwrap();
            assert!(prove_and_verify(&pk, i, &mut rng));
        }
    }

    #[test]
    fn test_updatable_setup() {
        let mut rng = StdRng::seed_from_u64(3);
        let prev = UniversalParams::<Bn254>::setup(16, &mut rng);
        let mut next = prev.clone();
        let proof = next.contribute(&mut rng);
        assert!(UniversalParams::verify_contribution(&prev, &next, &proof));
        let (pk, _) = next.derive_keys(TestCircuit { x: None }, &mut rng).unwrap();
        assert!(prove_and_verify(&pk, 7, &mut rng));
    }

    #[test]
    fn test_phase2_chain_verifies() {
        let mut rng = StdRng::seed_from_u64(4);
        let params = UniversalParams::<Bn254>::setup(16, &mut rng);
        let mut pk = params
            .derive_unblinded_keys(TestCircuit { x: None })
            .unwrap();
        let t: Vec<_> = (0..3)
            .map(|_| contribute_delta(&mut pk, &mut rng))
            .collect();
        assert!(params
            .verify_keys(TestCircuit { x: None }, &pk, &t)
            .unwrap());
        assert!(!params
            .verify_keys(TestCircuit { x: None }, &pk, &t[..2])
            .unwrap());
        assert!(!params
            .verify_keys(TestCircuit { x: None }, &pk, &[])
            .unwrap());
        assert!(prove_and_verify(&pk, 5, &mut rng));
    }

    #[test]
    fn test_too_large_circuit_rejected() {
        let mut rng = StdRng::seed_from_u64(5);
        let params = UniversalParams::<Bn254>::setup(2, &mut rng);
        // 1 constraint + 2 instance variables needs a domain of 4 > 2.
        assert!(params
            .derive_keys(TestCircuit { x: None }, &mut rng)
            .is_err());
    }
}
