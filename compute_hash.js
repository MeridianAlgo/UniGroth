// compute_hash.js — computes the Poseidon hash of your secret phrase
// then writes input.json with the correct expectedHash value

const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");

async function main() {
    const poseidon = await buildPoseidon();
    
    // your secret phrase as a big integer
    const secretPhrase = BigInt("12345678901234567890");
    
    // compute poseidon hash
    const hash = poseidon([secretPhrase]);
    const hashStr = poseidon.F.toString(hash);
    
    console.log("=== UniGroth ZK Proof Demo ===");
    console.log("Secret phrase (private):", secretPhrase.toString());
    console.log("Poseidon hash  (public):", hashStr);
    
    // write input.json with both values
    const input = {
        secretPhrase: secretPhrase.toString(),
        expectedHash: hashStr
    };
    
    fs.writeFileSync("input.json", JSON.stringify(input, null, 2));
    console.log("\ninput.json written successfully!");
    console.log(JSON.stringify(input, null, 2));
}

main().catch(console.error);
