// Compile the generated Solidity verifiers with solc and run them in an EVM.
//
//   UNIGROTH_EVM_FIXTURE_DIR=tests/evm/fixture \
//       cargo test --features solidity --test solidity_verifier
//   cd tests/evm && npm ci && node run.mjs fixture
//
// Exits non-zero if any case does not behave as expected.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createEVM } from '@ethereumjs/evm'
import { bytesToHex, hexToBytes } from '@ethereumjs/util'
import { Interface } from 'ethers'

const solc = createRequire(import.meta.url)('solc')

const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
const GAS = 30_000_000n

const dir = process.argv[2] ?? 'fixture'
const fixture = JSON.parse(readFileSync(join(dir, 'fixture.json'), 'utf8'))

function compile(name) {
  const file = `${name}.sol`
  const input = {
    language: 'Solidity',
    sources: { [file]: { content: readFileSync(join(dir, file), 'utf8') } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  }
  const out = JSON.parse(solc.compile(JSON.stringify(input)))
  const problems = out.errors ?? []
  for (const e of problems) console.log(`  solc ${e.severity}: ${e.formattedMessage.trim()}`)
  if (problems.some((e) => e.severity === 'error')) throw new Error(`${file} does not compile`)
  const contract = out.contracts[file][name]
  return {
    iface: new Interface(contract.abi),
    bytecode: `0x${contract.evm.bytecode.object}`,
    warnings: problems.length,
  }
}

async function deploy(evm, bytecode) {
  const res = await evm.runCall({ data: hexToBytes(bytecode), gasLimit: GAS })
  if (res.execResult.exceptionError) throw new Error('deployment reverted')
  return res.createdAddress
}

/** Returns 'true' | 'false' | 'revert: <reason>' and the gas used. */
async function call(evm, to, iface, args) {
  const data = hexToBytes(iface.encodeFunctionData('verifyProof', args))
  const res = await evm.runCall({ to, data, gasLimit: GAS })
  const gas = res.execResult.executionGasUsed
  const ret = bytesToHex(res.execResult.returnValue)
  if (res.execResult.exceptionError) {
    let reason = res.execResult.exceptionError.error
    try {
      reason = iface.parseError(ret)?.args?.[0] ?? reason
    } catch {
      // not an Error(string) payload
    }
    return { outcome: `revert: ${reason}`, gas }
  }
  return { outcome: String(iface.decodeFunctionResult('verifyProof', data.length ? ret : '0x')[0]), gas }
}

const big = (h) => BigInt(h)
const hex = (n) => `0x${n.toString(16).padStart(64, '0')}`
const clone = (p) => JSON.parse(JSON.stringify(p))

let failures = 0
function check(label, got, want) {
  const ok = typeof want === 'string' ? got.outcome === want : want(got.outcome)
  if (!ok) failures++
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}: ${got.outcome} (gas ${got.gas})`)
}
const reverts = (reason) => (o) => o === `revert: ${reason}`

const common = new Common({ chain: Mainnet, hardfork: Hardfork.Cancun })
const evm = await createEVM({ common })

// ── Two public inputs ────────────────────────────────────────────────────────
{
  console.log('ProductAndSumVerifier')
  const { iface, bytecode } = compile('ProductAndSumVerifier')
  const addr = await deploy(evm, bytecode)
  const args = (p) => [p.a, p.b, p.c, p.input]

  for (const [i, p] of fixture.proofs.entries()) {
    check(`valid proof ${i}`, await call(evm, addr, iface, args(p)), 'true')
  }
  const p = fixture.proofs[0]

  let t = clone(p)
  t.input[0] = hex(big(t.input[0]) + 1n)
  check('wrong public input', await call(evm, addr, iface, args(t)), 'false')

  t = clone(p)
  t.input[0] = hex(big(t.input[0]) + R)
  check('public input + r (alias)', await call(evm, addr, iface, args(t)), reverts('verifier-gte-snark-scalar-field'))

  t = clone(p)
  t.a[1] = hex(big(t.a[1]) + Q)
  check('A.y + q (second encoding)', await call(evm, addr, iface, args(t)), reverts('proof-g1-not-canonical'))

  t = clone(p)
  t.c[0] = hex(big(t.c[0]) + Q)
  check('C.x + q (second encoding)', await call(evm, addr, iface, args(t)), reverts('proof-g1-not-canonical'))

  t = clone(p)
  t.b[1][1] = hex(big(t.b[1][1]) + Q)
  check('B.y.c0 + q (second encoding)', await call(evm, addr, iface, args(t)), reverts('proof-g2-not-canonical'))

  t = clone(p)
  t.a = [hex(0n), hex(0n)]
  check('A = identity', await call(evm, addr, iface, args(t)), reverts('proof-g1-identity'))

  t = clone(p)
  t.c = [hex(0n), hex(0n)]
  check('C = identity', await call(evm, addr, iface, args(t)), reverts('proof-g1-identity'))

  t = clone(p)
  t.b = [[hex(0n), hex(0n)], [hex(0n), hex(0n)]]
  check('B = identity', await call(evm, addr, iface, args(t)), reverts('proof-g2-identity'))

  t = clone(p)
  t.a = [hex(1n), hex(2n)]
  check('A = generator (valid point, wrong proof)', await call(evm, addr, iface, args(t)), 'false')

  t = clone(p)
  t.c = fixture.proofs[1].c
  check('C from another proof', await call(evm, addr, iface, args(t)), 'false')

  t = clone(p)
  t.a[1] = hex(Q - big(t.a[1]))
  check('A negated', await call(evm, addr, iface, args(t)), 'false')

  t = clone(p)
  t.a[0] = hex((big(t.a[0]) + 1n) % Q)
  check('A off the curve', await call(evm, addr, iface, args(t)), reverts('proof-g1-not-on-curve'))

  t = clone(p)
  t.b = [[t.b[0][1], t.b[0][0]], [t.b[1][1], t.b[1][0]]]
  check('B with c0/c1 swapped (off the curve)', await call(evm, addr, iface, args(t)), reverts('proof-g2-not-on-curve'))

  // On the curve, outside the subgroup: only the precompile can tell.
  t = clone(p)
  t.b = fixture.offSubgroupB
  check('B outside the subgroup', await call(evm, addr, iface, args(t)), reverts('pairing-failed'))
}

// ── No public inputs ─────────────────────────────────────────────────────────
{
  console.log('NoInputsVerifier')
  const { iface, bytecode } = compile('NoInputsVerifier')
  const addr = await deploy(evm, bytecode)
  const p = fixture.noInputs
  check('valid proof', await call(evm, addr, iface, [p.a, p.b, p.c]), 'true')
  check('C replaced', await call(evm, addr, iface, [p.a, p.b, [hex(1n), hex(2n)]]), 'false')
}

console.log(failures === 0 ? 'all cases behaved as expected' : `${failures} case(s) FAILED`)
process.exit(failures === 0 ? 0 : 1)
