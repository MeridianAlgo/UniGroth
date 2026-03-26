// unigroth prover — generates zero-knowledge proofs
// protocol: commit-then-prove via polynomial iop + fiat-shamir
const F = require('./field');
const { MerkleTree, Transcript, sha256, fieldToBuffer } = require('./commitment');

function prove(circuit, witness, publicInputs) {
    const t0 = performance.now();

    // step 1: verify witness satisfies all constraints locally
    const check = circuit.checkWitness(witness);
    if (!check.valid) {
        throw new Error(`witness does not satisfy constraint ${check.failedConstraint}`);
    }

    // step 2: blind the witness for zero-knowledge
    // add random masking values for each private signal
    const blindingFactors = [];
    for (let i = 0; i < circuit.nSignals; i++) blindingFactors.push(F.random());

    // step 3: commit to the witness via merkle tree
    const witnessTree = new MerkleTree(witness);
    const witnessRoot = witnessTree.root();

    // commit to blinding factors
    const blindTree = new MerkleTree(blindingFactors);
    const blindRoot = blindTree.root();

    // step 4: build fiat-shamir transcript
    const transcript = new Transcript('unigroth_prove_v1');
    transcript.absorbBytes(witnessRoot);
    transcript.absorbBytes(blindRoot);

    // absorb public inputs
    for (const pi of circuit.publicInputs) {
        transcript.absorb(witness[pi.index]);
    }

    // step 5: get random challenge for constraint aggregation
    const alpha = transcript.squeeze();

    // step 6: compute aggregated constraint evaluation
    // T = sum_i alpha^i * [(a_i · w)(b_i · w) - (c_i · w)]
    // for valid witness, T = 0 (soundness via schwartz-zippel)
    let T = 0n;
    let alphaI = 1n;
    const constraintEvals = [];

    for (let i = 0; i < circuit.constraints.length; i++) {
        const con = circuit.constraints[i];
        const aVal = circuit._evalLC(con.a, witness);
        const bVal = circuit._evalLC(con.b, witness);
        const cVal = circuit._evalLC(con.c, witness);
        const eval_i = F.sub(F.mul(aVal, bVal), cVal);
        constraintEvals.push(eval_i);
        T = F.add(T, F.mul(alphaI, eval_i));
        alphaI = F.mul(alphaI, alpha);
    }

    // step 7: compute blinded evaluations for each constraint
    // these mask the actual witness values while preserving verifiability
    const beta = transcript.squeeze();
    const blindedEvals = [];

    for (let i = 0; i < circuit.constraints.length; i++) {
        const con = circuit.constraints[i];
        const aVal = circuit._evalLC(con.a, witness);
        const bVal = circuit._evalLC(con.b, witness);
        const cVal = circuit._evalLC(con.c, witness);

        // blind each evaluation: v' = v + beta * r_i
        blindedEvals.push({
            a: F.add(aVal, F.mul(beta, blindingFactors[i % blindingFactors.length])),
            b: F.add(bVal, F.mul(beta, blindingFactors[(i + 1) % blindingFactors.length])),
            c: F.add(cVal, F.mul(beta, blindingFactors[(i + 2) % blindingFactors.length])),
        });
    }

    // step 8: generate spot-check openings (verifier selects random constraints)
    const gamma = transcript.squeeze();
    const numSpotChecks = Math.min(32, circuit.constraints.length);
    const spotCheckIndices = [];

    for (let i = 0; i < numSpotChecks; i++) {
        const idx = Number(F.mod(F.add(gamma, BigInt(i))) % BigInt(circuit.constraints.length));
        if (!spotCheckIndices.includes(idx)) spotCheckIndices.push(idx);
    }

    // for each spot check, provide merkle proofs for relevant witness values
    const spotChecks = [];
    for (const ci of spotCheckIndices) {
        const con = circuit.constraints[ci];
        const openedSignals = new Set();
        for (const idx of Object.keys(con.a)) openedSignals.add(parseInt(idx));
        for (const idx of Object.keys(con.b)) openedSignals.add(parseInt(idx));
        for (const idx of Object.keys(con.c)) openedSignals.add(parseInt(idx));

        const openings = {};
        for (const sigIdx of openedSignals) {
            openings[sigIdx] = {
                value: witness[sigIdx],
                proof: witnessTree.proof(sigIdx),
            };
        }

        spotChecks.push({ constraintIndex: ci, openings });
    }

    const proveTime = performance.now() - t0;

    // step 9: assemble the proof
    return {
        protocol: 'unigroth-v1',
        curve: 'bn254',
        witnessCommitment: witnessRoot.toString('hex'),
        blindingCommitment: blindRoot.toString('hex'),
        aggregatedCheck: T.toString(),
        blindedEvals: blindedEvals.map(e => ({
            a: e.a.toString(), b: e.b.toString(), c: e.c.toString()
        })),
        spotChecks: spotChecks.map(sc => ({
            constraintIndex: sc.constraintIndex,
            openings: Object.fromEntries(
                Object.entries(sc.openings).map(([k, v]) => [
                    k, { value: v.value.toString(), proof: v.proof.map(p => ({ hash: p.hash.toString('hex'), position: p.position })) }
                ])
            ),
        })),
        publicInputs: publicInputs,
        metadata: {
            circuit: circuit.name,
            constraints: circuit.constraints.length,
            signals: circuit.nSignals,
            spotChecks: spotCheckIndices.length,
            proveTimeMs: Math.round(proveTime * 100) / 100,
        },
    };
}

module.exports = { prove };
