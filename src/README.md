# UniGroth — JavaScript Reference Implementation

A small R1CS toolkit in plain JavaScript: build circuits (including a 91-round MiMC7 (x^7) hash), compute witnesses, and check them.

> **Not zero-knowledge.** A proof from `prover.js` carries the full witness, including private inputs, and `verifier.js` re-checks every constraint. It shows a computation was done correctly; it does not hide anything. For private proofs, use the Rust library in `../UniGroth/`, or `../phrase.circom` with snarkjs.

## Files

| File | Purpose |
|------|---------|
| `index.js` | `UniGroth` API: `newCircuit`, `compile`, `prove`, `verify`, `mimcHash` |
| `circuit.js` | Circuit builder, witness computation, MiMC gadget |
| `field.js` | BN254 scalar-field arithmetic |
| `prover.js` | Checks the witness and packages it as a proof |
| `verifier.js` | Canonical-encoding checks, public-input binding, full constraint check |
| `commitment.js` | SHA-256 Merkle tree and Fiat-Shamir transcript utilities |

## Usage

```js
const { UniGroth } = require('./src');

const c = UniGroth.newCircuit('preimage');
const expected = c.publicInput('expectedHash');
const secret = c.privateInput('secret');
c.assertEqual(c.hash(secret), expected);
const compiled = UniGroth.compile(c);

const proof = UniGroth.prove(compiled, { secret: 5n, expectedHash: UniGroth.mimcHash(5n) });
console.log(UniGroth.verify(compiled, proof).passed); // true
```

```bash
npm test               # verifier tests, including forgery attempts
node compute_hash.js   # Poseidon hash input for phrase.circom (needs npm install)
```
