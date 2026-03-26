// unigroth circuit builder — define zk circuits in pure javascript
// no circom, no external dsl, just clean js
const F = require('./field');
const crypto = require('crypto');

// precompute mimc round constants (91 rounds for 128-bit security on bn254)
const MIMC_ROUNDS = 91;
const MIMC_CONSTANTS = [];
for (let i = 0; i < MIMC_ROUNDS; i++) {
    const h = crypto.createHash('sha256').update(`unigroth_mimc_${i}`).digest();
    let val = 0n;
    for (const b of h) val = (val << 8n) | BigInt(b);
    MIMC_CONSTANTS.push(F.mod(val));
}

class Circuit {
    constructor(name = 'circuit') {
        this.name = name;
        this.nSignals = 0;
        this.constraints = [];
        this.publicInputs = [];
        this.privateInputs = [];
        this.signalNames = [];
        this.signalMap = {};

        // signal 0 is always constant 1
        this._alloc('__one');
    }

    _alloc(name) {
        const idx = this.nSignals++;
        this.signalNames.push(name);
        this.signalMap[name] = idx;
        return idx;
    }

    // declare a public input (visible to verifier)
    publicInput(name) {
        const idx = this._alloc(name);
        this.publicInputs.push({ name, index: idx });
        return idx;
    }

    // declare a private input (hidden from verifier — the secret!)
    privateInput(name) {
        const idx = this._alloc(name);
        this.privateInputs.push({ name, index: idx });
        return idx;
    }

    // add r1cs constraint: (a·w) * (b·w) = (c·w)
    // a, b, c are objects mapping signal index to field coefficient
    _addConstraint(a, b, c) {
        this.constraints.push({ a, b, c });
    }

    // --- arithmetic operations (each returns a new signal index) ---

    add(x, y) {
        const out = this._alloc(`add_${this.nSignals}`);
        // (x + y) * 1 = out
        this._addConstraint({ [x]: 1n, [y]: 1n }, { 0: 1n }, { [out]: 1n });
        return out;
    }

    sub(x, y) {
        const out = this._alloc(`sub_${this.nSignals}`);
        // (x - y) * 1 = out
        this._addConstraint({ [x]: 1n, [y]: F.ORDER - 1n }, { 0: 1n }, { [out]: 1n });
        return out;
    }

    mul(x, y) {
        const out = this._alloc(`mul_${this.nSignals}`);
        // x * y = out
        this._addConstraint({ [x]: 1n }, { [y]: 1n }, { [out]: 1n });
        return out;
    }

    addConst(x, constant) {
        const c = F.toBigInt(constant);
        const out = this._alloc(`addc_${this.nSignals}`);
        // (x + c*1) * 1 = out
        this._addConstraint({ [x]: 1n, 0: c }, { 0: 1n }, { [out]: 1n });
        return out;
    }

    mulConst(x, constant) {
        const c = F.toBigInt(constant);
        const out = this._alloc(`mulc_${this.nSignals}`);
        // (c*x) * 1 = out
        this._addConstraint({ [x]: c }, { 0: 1n }, { [out]: 1n });
        return out;
    }

    // constrain two signals to be equal
    assertEqual(x, y) {
        // x * 1 = y
        this._addConstraint({ [x]: 1n }, { 0: 1n }, { [y]: 1n });
    }

    // x^3 (two constraints: sq = x*x, cu = sq*x)
    cube(x) {
        const sq = this.mul(x, x);
        const cu = this.mul(sq, x);
        return cu;
    }

    // built-in mimc hash (zk-friendly algebraic hash, 91 rounds)
    // replaces poseidon — same security level, simpler circuit
    hash(input) {
        let x = input;
        for (let i = 0; i < MIMC_ROUNDS; i++) {
            x = this.addConst(x, MIMC_CONSTANTS[i]);
            x = this.cube(x);
        }
        return x;
    }

    // compute the full witness given input values
    computeWitness(inputs) {
        const w = new Array(this.nSignals);
        const set = new Array(this.nSignals).fill(false);

        // signal 0 = 1
        w[0] = 1n; set[0] = true;

        // fill public inputs
        for (const { name, index } of this.publicInputs) {
            if (inputs[name] === undefined) throw new Error(`missing public input: ${name}`);
            w[index] = F.toBigInt(inputs[name]);
            set[index] = true;
        }

        // fill private inputs
        for (const { name, index } of this.privateInputs) {
            if (inputs[name] === undefined) throw new Error(`missing private input: ${name}`);
            w[index] = F.toBigInt(inputs[name]);
            set[index] = true;
        }

        // propagate through constraints to compute intermediate signals
        for (const con of this.constraints) {
            const aVal = this._evalLC(con.a, w);
            const bVal = this._evalLC(con.b, w);
            const product = F.mul(aVal, bVal);

            // find unknown signal in c and solve for it
            let known = 0n;
            let unknownIdx = -1;
            let unknownCoeff = 0n;

            for (const [idx, coeff] of Object.entries(con.c)) {
                const i = parseInt(idx);
                if (set[i]) {
                    known = F.add(known, F.mul(coeff, w[i]));
                } else {
                    unknownIdx = i;
                    unknownCoeff = coeff;
                }
            }

            if (unknownIdx >= 0 && unknownCoeff !== 0n) {
                w[unknownIdx] = F.div(F.sub(product, known), unknownCoeff);
                set[unknownIdx] = true;
            }
        }

        return w;
    }

    // evaluate a linear combination against witness
    _evalLC(lc, w) {
        let sum = 0n;
        for (const [idx, coeff] of Object.entries(lc)) {
            sum = F.add(sum, F.mul(coeff, w[parseInt(idx)]));
        }
        return sum;
    }

    // check that witness satisfies all constraints
    checkWitness(w) {
        for (let i = 0; i < this.constraints.length; i++) {
            const con = this.constraints[i];
            const aVal = this._evalLC(con.a, w);
            const bVal = this._evalLC(con.b, w);
            const cVal = this._evalLC(con.c, w);
            if (!F.eq(F.mul(aVal, bVal), cVal)) {
                return { valid: false, failedConstraint: i };
            }
        }
        return { valid: true };
    }

    // get circuit stats
    stats() {
        return {
            name: this.name,
            signals: this.nSignals,
            constraints: this.constraints.length,
            publicInputs: this.publicInputs.length,
            privateInputs: this.privateInputs.length,
        };
    }
}

module.exports = { Circuit, MIMC_CONSTANTS, MIMC_ROUNDS };
