// unigroth field arithmetic — bn254 scalar field
// all operations done over the bn254 curve order (same field groth16 uses)
const crypto = require('crypto');

const ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function mod(a) {
    const r = ((a % ORDER) + ORDER) % ORDER;
    return r;
}

function add(a, b) { return mod(a + b); }
function sub(a, b) { return mod(a - b); }
function mul(a, b) { return mod(a * b); }
function neg(a) { return mod(-a); }

function pow(base, exp) {
    base = mod(base);
    if (exp < 0n) exp = mod(exp);
    let result = 1n;
    base = mod(base);
    while (exp > 0n) {
        if (exp & 1n) result = mul(result, base);
        base = mul(base, base);
        exp >>= 1n;
    }
    return result;
}

function inv(a) {
    if (mod(a) === 0n) throw new Error('cannot invert zero');
    return pow(a, ORDER - 2n);
}

function div(a, b) { return mul(a, inv(b)); }

function random() {
    const bytes = crypto.randomBytes(32);
    let val = 0n;
    for (const b of bytes) val = (val << 8n) | BigInt(b);
    return mod(val);
}

function eq(a, b) { return mod(a) === mod(b); }

function toBigInt(val) {
    if (typeof val === 'bigint') return mod(val);
    if (typeof val === 'number') return mod(BigInt(val));
    if (typeof val === 'string') return mod(BigInt(val));
    throw new Error(`cannot convert ${typeof val} to field element`);
}

// hash field elements to a field element (domain-separated sha256)
function hashToField(...elements) {
    const h = crypto.createHash('sha256');
    h.update('unigroth_v1:');
    for (const e of elements) {
        const hex = mod(toBigInt(e)).toString(16).padStart(64, '0');
        h.update(hex);
    }
    const digest = h.digest();
    let val = 0n;
    for (const b of digest) val = (val << 8n) | BigInt(b);
    return mod(val);
}

module.exports = { ORDER, mod, add, sub, mul, neg, pow, inv, div, random, eq, toBigInt, hashToField };
