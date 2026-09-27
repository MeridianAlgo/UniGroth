// run: npm test
const test = require('node:test');
const assert = require('node:assert');
const { UniGroth, Field: F } = require('../src/index');

function hashCircuit() {
    const c = UniGroth.newCircuit('preimage');
    const expected = c.publicInput('expectedHash');
    const secret = c.privateInput('secret');
    c.assertEqual(c.hash(secret), expected);
    return UniGroth.compile(c);
}

const SECRET = 123456789n;
const HASH = UniGroth.mimcHash(SECRET);

test('honest proof verifies', () => {
    const compiled = hashCircuit();
    const proof = UniGroth.prove(compiled, { secret: SECRET, expectedHash: HASH });
    assert.strictEqual(UniGroth.verify(compiled, proof).passed, true);
});

test('wrong secret cannot produce an accepted proof', () => {
    const compiled = hashCircuit();
    const proof = UniGroth.prove(compiled, { secret: SECRET, expectedHash: HASH });
    // forger keeps the public hash but swaps in a different secret and recomputes
    const fake = UniGroth.prove(compiled, {
        secret: 42n,
        expectedHash: UniGroth.mimcHash(42n),
    });
    fake.publicInputs.expectedHash = HASH.toString();
    assert.strictEqual(UniGroth.verify(compiled, fake).passed, false);

    // tampering with any single intermediate signal is caught
    for (let i = 3; i < proof.witness.length; i += 37) {
        const t = structuredClone(proof);
        t.witness[i] = F.add(BigInt(t.witness[i]), 1n).toString();
        assert.strictEqual(UniGroth.verify(compiled, t).passed, false, `signal ${i}`);
    }
});

test('prover-supplied summaries are ignored', () => {
    const compiled = hashCircuit();
    const proof = UniGroth.prove(compiled, { secret: SECRET, expectedHash: HASH });
    const t = structuredClone(proof);
    t.aggregatedCheck = '0';
    t.witness[5] = '7';
    assert.strictEqual(UniGroth.verify(compiled, t).passed, false);
});

test('non-canonical or malformed encodings are rejected', () => {
    const compiled = hashCircuit();
    const proof = UniGroth.prove(compiled, { secret: SECRET, expectedHash: HASH });
    const t = structuredClone(proof);
    t.publicInputs.expectedHash = (HASH + F.ORDER).toString();
    assert.strictEqual(UniGroth.verify(compiled, t).passed, false);
    assert.strictEqual(UniGroth.verify(compiled, { ...proof, witness: proof.witness.slice(1) }).passed, false);
    assert.strictEqual(UniGroth.verify(compiled, null).passed, false);
});
