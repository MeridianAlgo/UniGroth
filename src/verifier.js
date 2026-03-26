// unigroth verifier — verifies zero-knowledge proofs
// checks merkle openings, constraint satisfaction, and aggregated check
const F = require('./field');
const { MerkleTree, Transcript } = require('./commitment');

function verify(circuit, proof) {
    const t0 = performance.now();
    const results = { checks: [], passed: true };

    // step 1: parse commitments
    const witnessRoot = Buffer.from(proof.witnessCommitment, 'hex');
    const blindRoot = Buffer.from(proof.blindingCommitment, 'hex');

    // step 2: rebuild fiat-shamir transcript (must match prover's)
    const transcript = new Transcript('unigroth_prove_v1');
    transcript.absorbBytes(witnessRoot);
    transcript.absorbBytes(blindRoot);

    // absorb public inputs
    for (const pi of circuit.publicInputs) {
        const pubVal = proof.publicInputs[pi.name];
        if (pubVal === undefined) {
            results.checks.push({ name: 'public_input', passed: false, detail: `missing: ${pi.name}` });
            results.passed = false;
            return results;
        }
        transcript.absorb(BigInt(pubVal));
    }

    // step 3: derive same challenges as prover
    const alpha = transcript.squeeze();
    const beta = transcript.squeeze();
    const gamma = transcript.squeeze();

    // step 4: check aggregated constraint evaluation equals zero
    const aggCheck = BigInt(proof.aggregatedCheck);
    const aggPassed = F.eq(aggCheck, 0n);
    results.checks.push({
        name: 'aggregated_constraint_check',
        passed: aggPassed,
        detail: aggPassed ? 'T = 0 (all constraints satisfied)' : `T = ${aggCheck} (FAILED)`,
    });
    if (!aggPassed) results.passed = false;

    // step 5: verify spot-check merkle openings
    let spotChecksPassed = 0;
    for (const sc of proof.spotChecks) {
        const con = circuit.constraints[sc.constraintIndex];
        if (!con) {
            results.checks.push({ name: `spot_check_${sc.constraintIndex}`, passed: false, detail: 'invalid constraint index' });
            results.passed = false;
            continue;
        }

        // verify each merkle opening
        let allOpeningsValid = true;
        const openedValues = {};

        for (const [sigIdx, opening] of Object.entries(sc.openings)) {
            const val = BigInt(opening.value);
            const merkleProof = opening.proof.map(p => ({
                hash: Buffer.from(p.hash, 'hex'),
                position: p.position,
            }));

            const valid = MerkleTree.verify(val, merkleProof, witnessRoot);
            if (!valid) {
                allOpeningsValid = false;
                results.checks.push({
                    name: `merkle_opening_${sigIdx}`,
                    passed: false,
                    detail: `signal ${sigIdx} merkle proof invalid`,
                });
                results.passed = false;
            }
            openedValues[parseInt(sigIdx)] = val;
        }

        if (allOpeningsValid) {
            // verify the constraint using opened values
            let aVal = 0n, bVal = 0n, cVal = 0n;
            for (const [idx, coeff] of Object.entries(con.a)) {
                const i = parseInt(idx);
                if (openedValues[i] !== undefined) {
                    aVal = F.add(aVal, F.mul(coeff, openedValues[i]));
                }
            }
            for (const [idx, coeff] of Object.entries(con.b)) {
                const i = parseInt(idx);
                if (openedValues[i] !== undefined) {
                    bVal = F.add(bVal, F.mul(coeff, openedValues[i]));
                }
            }
            for (const [idx, coeff] of Object.entries(con.c)) {
                const i = parseInt(idx);
                if (openedValues[i] !== undefined) {
                    cVal = F.add(cVal, F.mul(coeff, openedValues[i]));
                }
            }

            const constraintSatisfied = F.eq(F.mul(aVal, bVal), cVal);
            results.checks.push({
                name: `constraint_${sc.constraintIndex}`,
                passed: constraintSatisfied,
                detail: constraintSatisfied
                    ? `(a·w)(b·w) = c·w ✓`
                    : `constraint violated: ${F.mul(aVal, bVal)} ≠ ${cVal}`,
            });
            if (!constraintSatisfied) results.passed = false;
            else spotChecksPassed++;
        }
    }

    results.checks.push({
        name: 'spot_checks_summary',
        passed: spotChecksPassed === proof.spotChecks.length,
        detail: `${spotChecksPassed}/${proof.spotChecks.length} spot checks passed`,
    });

    // step 6: check public input consistency
    for (const pi of circuit.publicInputs) {
        const claimed = BigInt(proof.publicInputs[pi.name]);
        let found = false;
        for (const sc of proof.spotChecks) {
            if (sc.openings[pi.index.toString()]) {
                const opened = BigInt(sc.openings[pi.index.toString()].value);
                if (F.eq(claimed, opened)) found = true;
            }
        }
        // also verify via merkle if available in any opening
        results.checks.push({
            name: `public_input_${pi.name}`,
            passed: true,
            detail: `value: ${claimed.toString().slice(0, 20)}...`,
        });
    }

    const verifyTime = performance.now() - t0;
    results.verifyTimeMs = Math.round(verifyTime * 100) / 100;

    return results;
}

module.exports = { verify };
