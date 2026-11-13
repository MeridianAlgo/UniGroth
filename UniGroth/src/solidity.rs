//! # Solidity Verifier Contract Generation
#![allow(missing_docs)]
//!
//! Generates a Solidity smart contract that verifies UniGroth/Groth16 proofs
//! on-chain. Uses BN254 precompiles (EIP-196/197).
//!
//! References:
//! - EIP-196: <https://eips.ethereum.org/EIPS/eip-196>
//! - EIP-197: <https://eips.ethereum.org/EIPS/eip-197>

use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_std::{format, string::String, vec::Vec};

use crate::VerifyingKey;

/// Gas cost estimates for on-chain verification.
#[derive(Clone, Debug)]
pub struct GasCostEstimate {
    pub ec_add_calls: usize,
    pub ec_mul_calls: usize,
    pub pairing_calls: usize,
    pub total_gas: usize,
}

/// Estimate gas cost for verifying a proof with the given number of public inputs.
pub fn estimate_gas_cost(num_public_inputs: usize) -> GasCostEstimate {
    let ec_add_calls = num_public_inputs;
    let ec_mul_calls = num_public_inputs;
    let pairing_calls = 1;

    let ec_add_gas = 150 * ec_add_calls;
    let ec_mul_gas = 6000 * ec_mul_calls;
    let pairing_gas = 45000 + 34000 * 4;
    let calldata_gas = 16 * (256 + 32 * num_public_inputs);
    let overhead = 25000;

    GasCostEstimate {
        ec_add_calls,
        ec_mul_calls,
        pairing_calls,
        total_gas: ec_add_gas + ec_mul_gas + pairing_gas + calldata_gas + overhead,
    }
}

/// A base-field element as a canonical `0x…` literal (always below q).
///
/// Taken from the field element itself, never from serialized point bytes:
/// arkworks' point encodings keep sign and infinity flags in the top bits of
/// the last coordinate, which are not part of the coordinate.
fn fq_hex(x: &Fq) -> String {
    let hex: String = x
        .into_bigint()
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("0x{}", hex)
}

/// `(x, y)`; the identity is `(0, 0)`, as the EVM precompiles encode it.
fn format_g1(p: &G1Affine) -> (String, String) {
    if p.is_zero() {
        return (fq_hex(&Fq::ZERO), fq_hex(&Fq::ZERO));
    }
    (fq_hex(&p.x), fq_hex(&p.y))
}

/// `((x.c1, x.c0), (y.c1, y.c0))`: EIP-197 puts the imaginary part first.
///
/// Each coordinate is wrapped in `uint256(…)`. These go into inline arrays
/// (`[a, b]`), whose element type Solidity deduces from the first literal's
/// smallest fitting integer type: a coordinate below 2²⁴⁸ would make the array
/// `uint248[2]` and the contract would not compile.
fn format_g2(p: &G2Affine) -> ((String, String), (String, String)) {
    let cast = |x: &Fq| format!("uint256({})", fq_hex(x));
    (
        (cast(&p.x.c1), cast(&p.x.c0)),
        (cast(&p.y.c1), cast(&p.y.c0)),
    )
}

/// Panic unless `name` is a plain identifier (`[A-Za-z_][A-Za-z0-9_]*`).
///
/// Names are spliced into generated source code; anything else could inject
/// arbitrary code into the generated verifier.
pub(crate) fn assert_identifier(name: &str) {
    let mut chars = name.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    assert!(
        ok,
        "invalid identifier {name:?}: use [A-Za-z_][A-Za-z0-9_]*"
    );
}

/// Panic unless `vk` passes [`crate::verifying_key_valid`]. A generated
/// verifier embeds the key for good, so a degenerate one must not get that far.
pub(crate) fn assert_valid_vk(vk: &VerifyingKey<Bn254>) {
    assert!(
        crate::verifying_key_valid(vk),
        "invalid verifying key: needs an IC point, non-identity alpha/beta/gamma/delta, \
         and every point on the curve in the prime-order subgroup"
    );
}

/// Generate a Solidity verifier contract for the given verifying key.
///
/// The contract checks the Groth16 equation with the EIP-196/197 precompiles.
/// Before pairing it requires that every public input is below the scalar
/// modulus, every proof coordinate is below the base-field modulus (one
/// encoding per proof), no proof point is the identity and every proof point
/// is on its curve; the pairing precompile rejects G2 points outside the
/// subgroup.
/// Malformed calldata reverts; a well-formed but wrong proof returns `false`.
///
/// `verifyProof` takes `b` in EIP-197 order, `[[x.c1, x.c0], [y.c1, y.c0]]`
/// (the same order snarkjs calldata uses).
///
/// # Panics
/// Panics if `contract_name` is not a plain identifier or `vk` fails
/// [`crate::verifying_key_valid`].
pub fn generate_solidity_verifier(vk: &VerifyingKey<Bn254>, contract_name: &str) -> String {
    assert_identifier(contract_name);
    assert_valid_vk(vk);
    let num_inputs = vk.gamma_abc_g1.len() - 1;
    let twist_b = <ark_bn254::g2::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
    // Solidity has no zero-length fixed arrays, so a circuit without public
    // inputs gets a `verifyProof(a, b, c)` with no `input` parameter.
    let (input_param, input_copy) = if num_inputs == 0 {
        (String::new(), String::new())
    } else {
        (
            format!(",\n        uint256[{num_inputs}] memory input"),
            format!(
                "        for (uint256 i = 0; i < {num_inputs}; i++) {{\n            \
                 inputValues[i] = input[i];\n        }}\n"
            ),
        )
    };

    let (alpha_x, alpha_y) = format_g1(&vk.alpha_g1);
    let ((beta_x1, beta_x0), (beta_y1, beta_y0)) = format_g2(&vk.beta_g2);
    let ((gamma_x1, gamma_x0), (gamma_y1, gamma_y0)) = format_g2(&vk.gamma_g2);
    let ((delta_x1, delta_x0), (delta_y1, delta_y0)) = format_g2(&vk.delta_g2);

    let mut ic_entries = String::new();
    for (i, point) in vk.gamma_abc_g1.iter().enumerate() {
        let (x, y) = format_g1(point);
        ic_entries.push_str(&format!(
            "        vk.IC[{}] = Pairing.G1Point({}, {});\n",
            i, x, y
        ));
    }

    format!(
        r#"// SPDX-License-Identifier: MIT
// Auto-generated by UniGroth Solidity Verifier Generator
pragma solidity ^0.8.0;

library Pairing {{
    // BN254 base-field modulus.
    uint256 internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {{
        uint256 X;
        uint256 Y;
    }}
    // EIP-197 order: X = [x.c1, x.c0], Y = [y.c1, y.c0].
    struct G2Point {{
        uint256[2] X;
        uint256[2] Y;
    }}

    // G2 curve: y^2 = x^3 + TWIST_B over Fq2, TWIST_B = TWIST_B0 + TWIST_B1 * u.
    uint256 internal constant TWIST_B0 = {twist_b0};
    uint256 internal constant TWIST_B1 = {twist_b1};

    // A proof point must have one encoding (coordinates below Q), must not be
    // the identity and must be on the curve. The pairing precompile checks the
    // curve too, but a failing precompile burns all the gas forwarded to it;
    // checking here makes a malformed proof cheap to reject. The G2 subgroup
    // check is left to the precompile.
    function requireProofG1(G1Point memory p) internal pure {{
        require(p.X < Q && p.Y < Q, "proof-g1-not-canonical");
        require(p.X != 0 || p.Y != 0, "proof-g1-identity");
        // y^2 = x^3 + 3
        require(
            mulmod(p.Y, p.Y, Q) == addmod(mulmod(mulmod(p.X, p.X, Q), p.X, Q), 3, Q),
            "proof-g1-not-on-curve"
        );
    }}

    function requireProofG2(G2Point memory p) internal pure {{
        require(p.X[0] < Q && p.X[1] < Q && p.Y[0] < Q && p.Y[1] < Q, "proof-g2-not-canonical");
        require(p.X[0] != 0 || p.X[1] != 0 || p.Y[0] != 0 || p.Y[1] != 0, "proof-g2-identity");
        require(onCurveG2(p.X[1], p.X[0], p.Y[1], p.Y[0]), "proof-g2-not-on-curve");
    }}

    // (y0 + y1*u)^2 == (x0 + x1*u)^3 + TWIST_B in Fq2 = Fq[u]/(u^2 + 1).
    function onCurveG2(uint256 x0, uint256 x1, uint256 y0, uint256 y1) internal pure returns (bool) {{
        // x^2
        uint256 s0 = addmod(mulmod(x0, x0, Q), Q - mulmod(x1, x1, Q), Q);
        uint256 s1 = mulmod(2, mulmod(x0, x1, Q), Q);
        // x^3 + TWIST_B
        uint256 r0 = addmod(addmod(mulmod(s0, x0, Q), Q - mulmod(s1, x1, Q), Q), TWIST_B0, Q);
        uint256 r1 = addmod(addmod(mulmod(s0, x1, Q), mulmod(s1, x0, Q), Q), TWIST_B1, Q);
        // y^2
        s0 = addmod(mulmod(y0, y0, Q), Q - mulmod(y1, y1, Q), Q);
        s1 = mulmod(2, mulmod(y0, y1, Q), Q);
        return s0 == r0 && s1 == r1;
    }}

    // Requires canonical coordinates (see requireProofG1).
    function negate(G1Point memory p) internal pure returns (G1Point memory) {{
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, (Q - p.Y) % Q);
    }}

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint256[4] memory input;
        input[0] = p1.X; input[1] = p1.Y;
        input[2] = p2.X; input[3] = p2.Y;
        bool success;
        assembly {{ success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40) }}
        require(success, "ec-add-failed");
    }}

    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {{
        uint256[3] memory input;
        input[0] = p.X; input[1] = p.Y; input[2] = s;
        bool success;
        assembly {{ success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40) }}
        require(success, "ec-mul-failed");
    }}

    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {{
        uint256[24] memory input;
        input[0] = a1.X; input[1] = a1.Y;
        input[2] = a2.X[0]; input[3] = a2.X[1]; input[4] = a2.Y[0]; input[5] = a2.Y[1];
        input[6] = b1.X; input[7] = b1.Y;
        input[8] = b2.X[0]; input[9] = b2.X[1]; input[10] = b2.Y[0]; input[11] = b2.Y[1];
        input[12] = c1.X; input[13] = c1.Y;
        input[14] = c2.X[0]; input[15] = c2.X[1]; input[16] = c2.Y[0]; input[17] = c2.Y[1];
        input[18] = d1.X; input[19] = d1.Y;
        input[20] = d2.X[0]; input[21] = d2.X[1]; input[22] = d2.Y[0]; input[23] = d2.Y[1];
        uint256[1] memory out;
        bool success;
        assembly {{ success := staticcall(sub(gas(), 2000), 8, input, 0x300, out, 0x20) }}
        require(success, "pairing-failed");
        return out[0] != 0;
    }}
}}

contract {contract_name} {{
    using Pairing for *;

    struct VerifyingKey {{
        Pairing.G1Point alpha_g1;
        Pairing.G2Point beta_g2;
        Pairing.G2Point gamma_g2;
        Pairing.G2Point delta_g2;
        Pairing.G1Point[] IC;
    }}

    struct Proof {{
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }}

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {{
        vk.alpha_g1 = Pairing.G1Point({alpha_x}, {alpha_y});
        vk.beta_g2 = Pairing.G2Point([{beta_x1}, {beta_x0}], [{beta_y1}, {beta_y0}]);
        vk.gamma_g2 = Pairing.G2Point([{gamma_x1}, {gamma_x0}], [{gamma_y1}, {gamma_y0}]);
        vk.delta_g2 = Pairing.G2Point([{delta_x1}, {delta_x0}], [{delta_y1}, {delta_y0}]);
        vk.IC = new Pairing.G1Point[]({num_ic});
{ic_entries}    }}

    function verify(uint256[] memory input, Proof memory proof) public view returns (bool) {{
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        Pairing.requireProofG1(proof.A);
        Pairing.requireProofG2(proof.B);
        Pairing.requireProofG1(proof.C);

        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        for (uint256 i = 0; i < input.length; i++) {{
            require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }}

        return Pairing.pairingProd4(
            Pairing.negate(proof.A), proof.B,
            vk.alpha_g1, vk.beta_g2,
            vk_x, vk.gamma_g2,
            proof.C, vk.delta_g2
        );
    }}

    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c{input_param}
    ) public view returns (bool r) {{
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        uint256[] memory inputValues = new uint256[]({num_inputs});
{input_copy}        return verify(inputValues, proof);
    }}
}}"#,
        contract_name = contract_name,
        alpha_x = alpha_x,
        alpha_y = alpha_y,
        beta_x1 = beta_x1,
        beta_x0 = beta_x0,
        beta_y1 = beta_y1,
        beta_y0 = beta_y0,
        gamma_x1 = gamma_x1,
        gamma_x0 = gamma_x0,
        gamma_y1 = gamma_y1,
        gamma_y0 = gamma_y0,
        delta_x1 = delta_x1,
        delta_x0 = delta_x0,
        delta_y1 = delta_y1,
        delta_y0 = delta_y0,
        num_ic = vk.gamma_abc_g1.len(),
        ic_entries = ic_entries,
        num_inputs = num_inputs,
        input_param = input_param,
        input_copy = input_copy,
        twist_b0 = fq_hex(&twist_b.c0),
        twist_b1 = fq_hex(&twist_b.c1),
    )
}

/// Compare gas costs across proof systems.
pub fn gas_cost_comparison(num_public_inputs: usize) -> Vec<(&'static str, GasCostEstimate)> {
    let unigroth = estimate_gas_cost(num_public_inputs);

    let plonk = GasCostEstimate {
        ec_add_calls: 20 + num_public_inputs,
        ec_mul_calls: 15 + num_public_inputs,
        pairing_calls: 1,
        total_gas: 300_000 + num_public_inputs * 6000,
    };

    let stark = GasCostEstimate {
        ec_add_calls: 0,
        ec_mul_calls: 0,
        pairing_calls: 0,
        total_gas: 2_000_000 + num_public_inputs * 1000,
    };

    vec![
        ("UniGroth/Groth16", unigroth),
        ("Plonk (estimated)", plonk),
        ("STARK (estimated)", stark),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Groth16;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_std::rand::{RngCore, SeedableRng};

    fn make_rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64())
    }

    #[derive(Clone)]
    struct MulCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for MulCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c_val = self.a.unwrap_or_default() * self.b.unwrap_or_default();
            let c = cs.new_input_variable(|| Ok(c_val))?;
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn test_solidity_generation() {
        let mut rng = make_rng();
        let (_, vk) =
            Groth16::<Bn254>::circuit_specific_setup(MulCircuit { a: None, b: None }, &mut rng)
                .unwrap();

        let sol = generate_solidity_verifier(&vk, "UniGrothVerifier");
        assert!(sol.contains("contract UniGrothVerifier"));
        assert!(sol.contains("function verify("));
        assert!(sol.contains("function verifyProof("));
        assert!(sol.contains("pairingProd4"));
        assert!(sol.contains("SPDX-License-Identifier"));
    }

    /// Parse a `0x…` literal as a canonical base-field element.
    fn parse_fq(lit: &str) -> ark_bn254::Fq {
        use ark_ff::{BigInteger, PrimeField};
        let digits = lit.strip_prefix("0x").expect("hex literal");
        assert!(digits.len() <= 64, "literal wider than 256 bits: {lit}");
        let padded = format!("{digits:0>64}");
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let x = ark_bn254::Fq::from_be_bytes_mod_order(&bytes);
        assert_eq!(
            x.into_bigint().to_bytes_be(),
            bytes,
            "coordinate {lit} is not below the base-field modulus"
        );
        x
    }

    /// Rebuild the verifying key from the constants in the generated contract.
    fn vk_from_contract(sol: &str) -> VerifyingKey<Bn254> {
        use ark_bn254::Fq2;
        use ark_ff::Zero;
        let start = sol.find("function verifyingKey()").unwrap();
        let end = sol.find("function verify(").unwrap();
        let mut lits = sol[start..end]
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| t.starts_with("0x"))
            .map(parse_fq);
        let mut g1 = || {
            let (x, y) = (lits.next().unwrap(), lits.next().unwrap());
            if x.is_zero() && y.is_zero() {
                G1Affine::zero()
            } else {
                G1Affine::new_unchecked(x, y)
            }
        };
        let alpha_g1 = g1();
        let mut ic_and_g2: Vec<ark_bn254::Fq> = lits.collect();
        let ic_coords = ic_and_g2.split_off(12);
        // Solidity order per G2 point: [x.c1, x.c0], [y.c1, y.c0].
        let g2 = |c: &[ark_bn254::Fq]| {
            G2Affine::new_unchecked(Fq2::new(c[1], c[0]), Fq2::new(c[3], c[2]))
        };
        VerifyingKey {
            alpha_g1,
            beta_g2: g2(&ic_and_g2[0..4]),
            gamma_g2: g2(&ic_and_g2[4..8]),
            delta_g2: g2(&ic_and_g2[8..12]),
            gamma_abc_g1: ic_coords
                .chunks(2)
                .map(|c| G1Affine::new_unchecked(c[0], c[1]))
                .collect(),
        }
    }

    /// arkworks' uncompressed encoding stores a sign flag in the top bits of
    /// y; copying those bytes into the contract gave coordinates ≥ q for about
    /// half of all points, which the precompiles reject.
    #[test]
    fn test_contract_constants_are_the_verifying_key() {
        use ark_std::rand::SeedableRng;
        for seed in 0..6u64 {
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
            let (_, vk) =
                Groth16::<Bn254>::circuit_specific_setup(MulCircuit { a: None, b: None }, &mut rng)
                    .unwrap();
            let sol = generate_solidity_verifier(&vk, "V");
            let parsed = vk_from_contract(&sol);
            assert!(crate::verifying_key_valid(&parsed), "seed {seed}");
            assert_eq!(parsed, vk, "seed {seed}");
            // Inline arrays must not leave their element type to deduction.
            assert_eq!(sol.matches("[uint256(0x").count(), 6, "seed {seed}");
            assert_eq!(sol.matches(", uint256(0x").count(), 6, "seed {seed}");
        }
    }

    #[test]
    #[should_panic(expected = "invalid identifier")]
    fn test_solidity_rejects_injected_name() {
        let mut rng = make_rng();
        let (_, vk) =
            Groth16::<Bn254>::circuit_specific_setup(MulCircuit { a: None, b: None }, &mut rng)
                .unwrap();
        generate_solidity_verifier(
            &vk,
            "X { function kill() public { selfdestruct(payable(msg.sender)); } } contract Y",
        );
    }

    #[test]
    fn test_gas_estimate() {
        let est = estimate_gas_cost(2);
        assert!(est.total_gas > 0);
        assert_eq!(est.pairing_calls, 1);
        assert_eq!(est.ec_mul_calls, 2);
    }

    #[test]
    fn test_gas_comparison() {
        let comparison = gas_cost_comparison(2);
        assert_eq!(comparison.len(), 3);
        let groth16_gas = comparison[0].1.total_gas;
        let plonk_gas = comparison[1].1.total_gas;
        let stark_gas = comparison[2].1.total_gas;
        assert!(groth16_gas < plonk_gas);
        assert!(plonk_gas < stark_gas);
    }
}
