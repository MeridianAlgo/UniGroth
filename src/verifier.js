// unigroth js verifier — checks every constraint of a reference (non-zk) proof
//
// nothing is taken on the prover's word: each value must be a canonical field
// element, signal 0 must be 1, every claimed public input must equal its
// witness signal, and every r1cs constraint is re-evaluated.
const F = require('./field');
const { PROTOCOL } = require('./prover');

// accept only canonical decimal strings in [0, ORDER) so each value has one encoding
function parseField(v) {
    if (typeof v !== 'string' || !/^[0-9]{1,78}$/.test(v)) return null;
    const x = BigInt(v);
    return x < F.ORDER ? x : null;
}

function verify(circuit, proof) {
    const t0 = performance.now();
    const results = { checks: [], passed: false };
    const done = () => {
        results.verifyTimeMs = Math.round((performance.now() - t0) * 100) / 100;
        return results;
    };
    const fail = (name, detail) => {
        results.checks.push({ name, passed: false, detail });
        return done();
    };

    if (!proof || proof.protocol !== PROTOCOL || !Array.isArray(proof.witness)) {
        return fail('format', 'malformed proof');
    }
    if (proof.witness.length !== circuit.nSignals) {
        return fail('format', `expected ${circuit.nSignals} signals, got ${proof.witness.length}`);
    }

    const w = proof.witness.map(parseField);
    const bad = w.indexOf(null);
    if (bad !== -1) return fail('format', `signal ${bad} is not a canonical field element`);
    if (w[0] !== 1n) return fail('one_signal', 'signal 0 must equal 1');

    for (const pi of circuit.publicInputs) {
        const claimed = parseField(proof.publicInputs ? proof.publicInputs[pi.name] : undefined);
        if (claimed === null) return fail(`public_input_${pi.name}`, 'missing or malformed');
        if (claimed !== w[pi.index]) return fail(`public_input_${pi.name}`, 'does not match witness');
    }
    results.checks.push({ name: 'public_inputs', passed: true, detail: 'bound to witness' });

    const check = circuit.checkWitness(w);
    if (!check.valid) {
        return fail(`constraint_${check.failedConstraint}`, 'constraint violated');
    }
    results.checks.push({
        name: 'constraints',
        passed: true,
        detail: `all ${circuit.constraints.length} constraints satisfied`,
    });

    results.passed = true;
    return done();
}

module.exports = { verify };
