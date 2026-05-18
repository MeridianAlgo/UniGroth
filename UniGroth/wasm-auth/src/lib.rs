//! # UniGroth WASM Auth Bindings
//!
//! Browser-side proving and host-side verification for the
//! [`unigroth::auth::AuthCircuit`].
//!
//! ## Public API
//!
//! ```ignore
//! prove(pk_bytes, secret_bytes, nonce_bytes) -> Vec<u8>
//! verify(vk_bytes, proof_bytes, commitment_bytes, nullifier_bytes, nonce_bytes) -> bool
//! commitment(secret_bytes) -> Vec<u8>
//! nullifier(secret_bytes, nonce_bytes) -> Vec<u8>
//! ```
//!
//! All byte arguments are big-endian 32-byte field elements (BN254 scalar field),
//! with one exception: `prove()` accepts a `secret_bytes` of arbitrary length and
//! hashes it to a field element via SHA-256.
//!
//! `prove()` returns a self-describing blob: `[proof || commitment || nullifier]`,
//! each component a length-prefixed 4-byte big-endian field followed by raw bytes.

#![allow(clippy::missing_safety_doc)]

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use unigroth::{
    auth::{mimc_hash, mimc_round_constants, AuthCircuit},
    Groth16, ProvingKey, SimExtractableProof, VerifyingKey,
};

// ─── Panic hook ─────────────────────────────────────────────────────────────

/// Install the `console.error` panic hook. Idempotent; safe to call many times.
#[wasm_bindgen(start)]
pub fn __wasm_start() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

// ─── Field conversion helpers ───────────────────────────────────────────────

/// Hash arbitrary-length input to a BN254 scalar via SHA-256, then reduce.
fn bytes_to_fr_hash(bytes: &[u8]) -> Fr {
    let digest = Sha256::digest(bytes);
    Fr::from_le_bytes_mod_order(&digest)
}

/// Interpret 32 big-endian bytes as a BN254 scalar (reduced mod r).
fn be_bytes_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Serialize a BN254 scalar as 32 big-endian bytes.
fn fr_to_be_bytes(f: &Fr) -> Vec<u8> {
    let mut le = f.into_bigint().to_bytes_le();
    le.resize(32, 0);
    le.reverse();
    le
}

/// Derive a per-proof RNG seed from the public inputs + a fresh OS draw.
fn rng_from_seed(domain: &[u8], nonce_bytes: &[u8]) -> ChaCha20Rng {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(nonce_bytes);
    let mut os_seed = [0u8; 32];
    if getrandom::getrandom(&mut os_seed).is_ok() {
        hasher.update(os_seed);
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    ChaCha20Rng::from_seed(seed)
}

// ─── Hash exports (server + browser parity) ─────────────────────────────────

/// Compute the commitment `H(secret, 0)` and return 32 big-endian bytes.
#[wasm_bindgen]
pub fn commitment(secret_bytes: &[u8]) -> Vec<u8> {
    let constants = mimc_round_constants::<Fr>();
    let s = bytes_to_fr_hash(secret_bytes);
    let c = mimc_hash(s, Fr::from(0u64), &constants);
    fr_to_be_bytes(&c)
}

/// Compute the nullifier `H(secret, nonce)` and return 32 big-endian bytes.
#[wasm_bindgen]
pub fn nullifier(secret_bytes: &[u8], nonce_bytes: &[u8]) -> Vec<u8> {
    let constants = mimc_round_constants::<Fr>();
    let s = bytes_to_fr_hash(secret_bytes);
    let n = be_bytes_to_fr(nonce_bytes);
    let nf = mimc_hash(s, n, &constants);
    fr_to_be_bytes(&nf)
}

// ─── Prove ──────────────────────────────────────────────────────────────────

/// Generate a proof for `AuthCircuit`.
///
/// Inputs:
/// * `pk_bytes`     — compressed proving key (output of `auth_setup`).
/// * `secret_bytes` — user credential. SHA-256 hashed to the field; never leaves the browser.
/// * `nonce_bytes`  — 32 big-endian bytes of the server-issued nonce.
///
/// Returns a length-prefixed blob: `[u32 proof_len][proof][u32 32][commitment][u32 32][nullifier]`.
#[wasm_bindgen]
pub fn prove(pk_bytes: &[u8], secret_bytes: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes)
        .map_err(|e| JsValue::from_str(&alloc::format!("pk deserialize: {e}")))?;

    let constants = mimc_round_constants::<Fr>();
    let secret = bytes_to_fr_hash(secret_bytes);
    let nonce = be_bytes_to_fr(nonce_bytes);

    let circuit = AuthCircuit::new(secret, nonce, constants);
    let commitment = circuit.commitment.expect("commitment computed");
    let nullifier_val = circuit.nullifier.expect("nullifier computed");

    let mut rng = rng_from_seed(b"unigroth-wasm-auth/v1", nonce_bytes);
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| JsValue::from_str(&alloc::format!("prove: {e}")))?;

    let mut proof_buf = Vec::new();
    proof
        .serialize_compressed(&mut proof_buf)
        .map_err(|e| JsValue::from_str(&alloc::format!("proof serialize: {e}")))?;

    let mut out = Vec::with_capacity(4 + proof_buf.len() + 4 + 32 + 4 + 32);
    out.extend_from_slice(&(proof_buf.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof_buf);
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&fr_to_be_bytes(&commitment));
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&fr_to_be_bytes(&nullifier_val));
    Ok(out)
}

// ─── Verify ─────────────────────────────────────────────────────────────────

/// Verify a proof for `AuthCircuit`.
///
/// All field-element arguments are 32 big-endian bytes (BN254 scalar field).
#[wasm_bindgen]
pub fn verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    commitment_bytes: &[u8],
    nullifier_bytes: &[u8],
    nonce_bytes: &[u8],
) -> Result<bool, JsValue> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|e| JsValue::from_str(&alloc::format!("vk deserialize: {e}")))?;
    let proof = SimExtractableProof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| JsValue::from_str(&alloc::format!("proof deserialize: {e}")))?;

    let public = [
        be_bytes_to_fr(commitment_bytes),
        be_bytes_to_fr(nullifier_bytes),
        be_bytes_to_fr(nonce_bytes),
    ];

    Groth16::<Bn254>::verify(&vk, &public, &proof)
        .map_err(|e| JsValue::from_str(&alloc::format!("verify: {e}")))
}

extern crate alloc;

// ─── Tests (host-side, not WASM) ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn end_to_end() {
        let constants = mimc_round_constants::<Fr>();
        let mut rng = StdRng::seed_from_u64(42);
        let setup = AuthCircuit::<Fr>::empty(constants.clone());
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup, &mut rng).unwrap();
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();

        let secret = b"hunter2";
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[31] = 7;

        let bundle = prove(&pk_bytes, secret, &nonce_bytes).unwrap();
        // Parse the bundle
        let proof_len = u32::from_be_bytes(bundle[0..4].try_into().unwrap()) as usize;
        let proof = &bundle[4..4 + proof_len];
        let mut cur = 4 + proof_len;
        let c_len = u32::from_be_bytes(bundle[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        let c = &bundle[cur..cur + c_len];
        cur += c_len;
        let n_len = u32::from_be_bytes(bundle[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        let n = &bundle[cur..cur + n_len];

        let expected_c = commitment(secret);
        let expected_n = nullifier(secret, &nonce_bytes);
        assert_eq!(c, &expected_c[..]);
        assert_eq!(n, &expected_n[..]);

        let ok = verify(&vk_bytes, proof, c, n, &nonce_bytes).unwrap();
        assert!(ok);

        // Tamper with nullifier — must reject.
        let mut bad = expected_n.clone();
        bad[0] ^= 0xff;
        let ok2 = verify(&vk_bytes, proof, c, &bad, &nonce_bytes).unwrap();
        assert!(!ok2);
    }
}
