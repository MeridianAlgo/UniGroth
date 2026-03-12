// unigroth commitment scheme — merkle tree + fiat-shamir transcript
// transparent (no trusted setup), hash-based (potentially post-quantum)
const crypto = require('crypto');
const F = require('./field');

function sha256(...buffers) {
    const h = crypto.createHash('sha256');
    for (const b of buffers) h.update(b);
    return h.digest();
}

function fieldToBuffer(val) {
    const hex = F.mod(val).toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
}

// merkle tree over field elements
class MerkleTree {
    constructor(leaves) {
        this.leaves = leaves.map(l => fieldToBuffer(l));
        this.layers = [this.leaves.map(l => sha256(Buffer.from('leaf:'), l))];
        this._build();
    }

    _build() {
        while (this.layers[this.layers.length - 1].length > 1) {
            const prev = this.layers[this.layers.length - 1];
            const next = [];
            for (let i = 0; i < prev.length; i += 2) {
                const left = prev[i];
                const right = i + 1 < prev.length ? prev[i + 1] : left;
                next.push(sha256(Buffer.from('node:'), left, right));
            }
            this.layers.push(next);
        }
    }

    root() {
        return this.layers[this.layers.length - 1][0];
    }

    proof(index) {
        const path = [];
        let idx = index;
        for (let i = 0; i < this.layers.length - 1; i++) {
            const layer = this.layers[i];
            const sibling = idx % 2 === 0
                ? (idx + 1 < layer.length ? layer[idx + 1] : layer[idx])
                : layer[idx - 1];
            path.push({ hash: sibling, position: idx % 2 === 0 ? 'right' : 'left' });
            idx = Math.floor(idx / 2);
        }
        return path;
    }

    static verify(leaf, proof, root) {
        let current = sha256(Buffer.from('leaf:'), fieldToBuffer(leaf));
        for (const step of proof) {
            if (step.position === 'right') {
                current = sha256(Buffer.from('node:'), current, step.hash);
            } else {
                current = sha256(Buffer.from('node:'), step.hash, current);
            }
        }
        return current.equals(root);
    }
}

// fiat-shamir transcript — turns interactive protocol into non-interactive
class Transcript {
    constructor(label) {
        this.state = sha256(Buffer.from(`unigroth_transcript:${label}`));
    }

    // absorb a field element into the transcript
    absorb(val) {
        this.state = sha256(this.state, fieldToBuffer(F.toBigInt(val)));
    }

    // absorb raw bytes
    absorbBytes(buf) {
        this.state = sha256(this.state, buf);
    }

    // squeeze a challenge (field element) from the transcript
    squeeze() {
        this.state = sha256(this.state, Buffer.from('challenge'));
        let val = 0n;
        for (const b of this.state) val = (val << 8n) | BigInt(b);
        return F.mod(val);
    }

    // squeeze multiple challenges
    squeezeN(n) {
        const challenges = [];
        for (let i = 0; i < n; i++) challenges.push(this.squeeze());
        return challenges;
    }
}

module.exports = { MerkleTree, Transcript, sha256, fieldToBuffer };
