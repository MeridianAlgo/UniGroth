// unigroth — self-contained zero-knowledge proof framework
// no circom, no snarkjs, no external ceremony — just import and prove
const { Circuit } = require('./circuit');
const { prove } = require('./prover');
const { verify } = require('./verifier');
const F = require('./field');

class UniGroth {
    // universal setup — no per-circuit ceremony, no toxic waste
    // works for ANY circuit up to any size (hash-based, transparent)
    static setup(options = {}) {
        const securityLevel = options.securityLevel || 128;
        return {
            protocol: 'unigroth-v1',
            type: 'universal-transparent',
            securityBits: securityLevel,
            field: 'bn254-scalar',
            fieldOrder: F.ORDER.toString(),
            commitmentScheme: 'merkle-sha256',
            hashFunction: 'mimc-bn254-91r',
            created: new Date().toISOString(),
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
            publicInputs[pi.name] = inputs[pi.name].toString();
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
            x = F.add(x, MIMC_CONSTANTS[i]);
            x = F.mul(F.mul(x, x), x); // x^3
        }
        return x;
    }

    // utility: create a new circuit
    static newCircuit(name) {
        return new Circuit(name);
    }
}

module.exports = { UniGroth, Circuit, Field: F };
