pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// prove you know a secret phrase whose poseidon hash matches a known public value
// the secret stays private — only the hash is revealed on-chain
template SecretPhrase() {
    signal input secretPhrase;      // private — your secret number
    signal input expectedHash;      // public — the hash value to check against

    component p = Poseidon(1);
    p.inputs[0] <== secretPhrase;

    // constrain: poseidon(secretPhrase) must equal the expected public hash
    p.out === expectedHash;
}

component main {public [expectedHash]} = SecretPhrase();
