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

For production, replace the deterministic seed with a multi-party
ceremony (or pass `--rand`).

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
import init, { prove, verify, commitment, nullifier }
  from "./pkg/unigroth_wasm_auth.js";

await init();

// Registration: store H(secret) in your DB
const secret = new TextEncoder().encode("hunter2");
const commit = commitment(secret);             // Uint8Array(32)

// Upload: server issues a fresh 32-byte nonce
const nonce  = crypto.getRandomValues(new Uint8Array(32));
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

Server-side anti-replay: persist `(commitment, nullifier)` pairs; reject any
repeat nullifier for a given commitment.

## Wire format

| Field        | Size       | Encoding                                  |
|--------------|-----------:|-------------------------------------------|
| `pk.bin`     | ~376 KB    | `ark-serialize` compressed `ProvingKey`   |
| `vk.bin`     | ~360 B     | `ark-serialize` compressed `VerifyingKey` |
| `proof`      | ~192 B     | `ark-serialize` compressed Groth16 proof  |
| field elem   | 32 B       | big-endian BN254 scalar                   |
| `secret`     | arbitrary  | hashed to BN254 via SHA-256 (in-crate)    |
| `nonce`      | 32 B       | big-endian BN254 scalar                   |

## Soundness

The auth circuit constrains every round of MiMC (`LongsightF322p3`, 322
rounds). 644 R1CS constraints per hash, 1 288 total — the prover cannot
forge a commitment without knowing the secret.

## Build sizes

* raw `wasm32-unknown-unknown` binary: ≈ 1.6 MB
* after `wasm-pack` + `wasm-opt -O4`:  ≈ 700–900 KB
* gzipped: ≈ 250 KB
