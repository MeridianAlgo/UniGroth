# `unigroth-wasm-auth` — Secure-Sharing Auth Bindings

Browser-side zero-knowledge proof of credential ownership built on
[UniGroth](https://github.com/MeridianAlgo/UniGroth).

The proof asserts:

```
I know a secret `s` such that
   commitment = H(s, 0)              // stable per-user identifier
   nullifier  = H(s, nonce)          // unique per upload, prevents replay
```

`s` is a private witness that **never leaves the browser**. `commitment`,
`nullifier`, and `nonce` are public inputs the verifier checks.

## 1 — Trusted setup (one-time)

```bash
# from the UniGroth/ workspace root
cargo run --release --features auth-bin --bin auth_setup -- --out keys/
# writes:
#   keys/pk.bin  (≈ 376 KB)  — proving key, ship to the browser
#   keys/vk.bin  (≈ 360 B)   — verifying key, ship to the server
```

Setup randomness comes from the OS CSPRNG and is never written to disk.
For production, prefer a multi-party ceremony over a single machine.

## 2 — Build the WASM bundle

```bash
# install once
cargo install wasm-pack

# from UniGroth/wasm-auth/
wasm-pack build --release --target web --out-dir pkg
# emits:
#   pkg/unigroth_wasm_auth_bg.wasm
#   pkg/unigroth_wasm_auth.js
#   pkg/unigroth_wasm_auth.d.ts
```

## 3 — Browser API

```ts
import init, { derive_secret, prove, verify, commitment, nullifier }
  from "./pkg/unigroth_wasm_auth.js";

await init();

// Registration: the server picks a random 16+ byte salt per user and stores it
// (it is not secret) next to the commitment.
const salt   = crypto.getRandomValues(new Uint8Array(16));
const secret = derive_secret(new TextEncoder().encode(password), salt); // Argon2id, ~1 s
const commit = commitment(secret);             // Uint8Array(32)

// Login: fetch this user's salt, derive the same secret.

// Upload: server issues a fresh 32-byte nonce. It must be a canonical,
// non-zero field element; clearing the top 3 bits keeps it below the modulus.
const nonce  = crypto.getRandomValues(new Uint8Array(32));
nonce[0] &= 0x1f;
const nf     = nullifier(secret, nonce);

// Generate the proof
const pk = new Uint8Array(await (await fetch("/pk.bin")).arrayBuffer());
const bundle = prove(pk, secret, nonce);

// Bundle layout (length-prefixed):
//   [u32 BE: proof_len][proof bytes][u32 BE: 32][commitment][u32 BE: 32][nullifier]
```

Parse the bundle:

```ts
const view = new DataView(bundle.buffer);
const proofLen = view.getUint32(0, false);
const proof = bundle.subarray(4, 4 + proofLen);
let cur = 4 + proofLen;
const cLen = view.getUint32(cur, false); cur += 4;
const commitmentBytes = bundle.subarray(cur, cur + cLen); cur += cLen;
const nLen = view.getUint32(cur, false); cur += 4;
const nullifierBytes  = bundle.subarray(cur, cur + nLen);
```

POST `{proof, commitment: commitmentBytes, nullifier: nullifierBytes, nonce}`
to your server.

## 4 — Server-side verification

Server is also Rust, same API:

```rust
use unigroth_wasm_auth::verify;
let ok = verify(&vk_bytes, &proof, &commitment, &nullifier, &nonce)?;
```

Server-side rules:

- Persist `(commitment, nullifier)` pairs and reject any repeat nullifier for
  a given commitment. `verify` rejects non-canonical and wrong-length
  encodings, so each nullifier has exactly one byte form.
- Issue each nonce to one session, accept it only from that session, and
  expire it after one use or a short timeout.
- Never deduplicate on proof bytes: Groth16 proofs can be rerandomized.

## Threat model

- **Offline guessing.** The commitment is public, so the circuit secret comes
  from Argon2id (64 MiB, 3 passes) with a per-user salt: each password guess
  costs that much memory and time. A strong password is still the real
  defence.
- **Phishing and relay are not prevented.** The user types the password into
  a page; a malicious page can collect it, or run its own copy of this WASM
  and relay the server's nonce. No library code running in the attacker's
  page can stop that. If you need phishing resistance, use WebAuthn
  passkeys, where the browser binds credentials to the origin.
- **Replay** is stopped by the nullifier and the one-time, session-bound nonce.
- **Timing.** Proving is not constant time; run it on the user's device only.

## Wire format

| Field        | Size       | Encoding                                  |
|--------------|-----------:|-------------------------------------------|
| `pk.bin`     | ~376 KB    | `ark-serialize` compressed `ProvingKey`   |
| `vk.bin`     | ~360 B     | `ark-serialize` compressed `VerifyingKey` |
| `proof`      | 128 B      | `ark-serialize` compressed Groth16 proof  |
| field elem   | 32 B       | canonical big-endian BN254 scalar (< r)   |
| `secret`     | 32 B       | `derive_secret` output (Argon2id → BN254) |
| `salt`       | ≥ 16 B     | random per user, stored with commitment   |
| `nonce`      | 32 B       | canonical, non-zero BN254 scalar          |

## Soundness

The auth circuit constrains every round of MiMC (`LongsightF322p3`, 322
rounds). 644 R1CS constraints per hash, 1 288 total — the prover cannot
forge a commitment without knowing the secret.

## Build sizes

* raw `wasm32-unknown-unknown` binary: ≈ 1.6 MB
* after `wasm-pack` + `wasm-opt -O4`:  ≈ 700–900 KB
* gzipped: ≈ 250 KB
