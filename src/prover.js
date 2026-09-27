// unigroth js prover — reference implementation, NOT zero-knowledge
//
// the proof carries the full witness so the verifier can check every
// constraint. it shows the computation was done correctly; it does not hide
// the private inputs. the earlier spot-check design was neither sound (the
// verifier trusted a prover-supplied aggregate and a cheater could grind the
// sampled constraints) nor hiding (openings revealed private values).
// for real zero-knowledge proofs use the rust library in ../UniGroth or
// phrase.circom + snarkjs.
const PROTOCOL = 'unigroth-js-v2';

function prove(circuit, witness, publicInputs) {
    const t0 = performance.now();

    const check = circuit.checkWitness(witness);
    if (!check.valid) {
        throw new Error(`witness does not satisfy constraint ${check.failedConstraint}`);
    }

    return {
        protocol: PROTOCOL,
        curve: 'bn254',
        zeroKnowledge: false,
        witness: witness.map(w => w.toString()),
        publicInputs,
        metadata: {
            circuit: circuit.name,
            constraints: circuit.constraints.length,
            signals: circuit.nSignals,
            proveTimeMs: Math.round((performance.now() - t0) * 100) / 100,
        },
    };
}

module.exports = { prove, PROTOCOL };
