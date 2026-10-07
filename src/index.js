// unigroth — javascript reference implementation (NOT zero-knowledge)
// proofs are sound but carry the full witness; use the rust library for zk
const { Circuit } = require('./circuit');
const { prove, PROTOCOL } = require('./prover');
const { verify } = require('./verifier');
const F = require('./field');

class UniGroth {
    // parameters of the reference protocol (no setup or trapdoor needed)
    static setup() {
        return {
            protocol: PROTOCOL,
            zeroKnowledge: false,
            field: 'bn254-scalar',
            fieldOrder: F.ORDER.toString(),
            hashFunction: 'mimc7-bn254-91r',
        };
    }

    // compile a circuit — returns the circuit ready for proving/verifying
    static compile(circuit) {
        const stats = circuit.stats();
        return {
            circuit,
            stats,
            compiled: true,
        };
    }

    // generate a proof
    static prove(compiled, inputs) {
        if (!compiled.compiled) throw new Error('circuit not compiled — call UniGroth.compile() first');
        const circuit = compiled.circuit;

        // separate public and private inputs
        const publicInputs = {};
        for (const pi of circuit.publicInputs) {
            if (inputs[pi.name] === undefined) throw new Error(`missing public input: ${pi.name}`);
            publicInputs[pi.name] = F.toBigInt(inputs[pi.name]).toString();
        }

        // compute witness (fills in all intermediate values)
        const witness = circuit.computeWitness(inputs);

        // generate the proof
        return prove(circuit, witness, publicInputs);
    }

    // verify a proof
    static verify(compiled, proof) {
        if (!compiled.compiled) throw new Error('circuit not compiled');
        return verify(compiled.circuit, proof);
    }

    // compute mimc hash outside of a circuit (for generating public inputs)
    static mimcHash(input) {
        const { MIMC_CONSTANTS, MIMC_ROUNDS } = require('./circuit');
        let x = F.toBigInt(input);
        for (let i = 0; i < MIMC_ROUNDS; i++) {
            x = F.pow(F.add(x, MIMC_CONSTANTS[i]), 7n);
        }
        return x;
    }

    // utility: create a new circuit
    static newCircuit(name) {
        return new Circuit(name);
    }
}

module.exports = { UniGroth, Circuit, Field: F };
