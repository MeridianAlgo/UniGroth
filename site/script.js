'use strict';

const benchmarks = {
  small: { baseline: 20.6, unigroth: 14.0, speedup: '1.47', action: 'faster proving', context: '4,096 constraints · BLS12-381', label: 'ark-groth16' },
  large: { baseline: 160, unigroth: 134, speedup: '1.19', action: 'faster proving', context: '65,536 constraints · BLS12-381', label: 'ark-groth16' },
  batch: { baseline: 24.9, unigroth: 7.6, speedup: '3.3', action: 'faster verification', context: '32 proofs · same verifying key', label: 'One by one' }
};

document.querySelectorAll('[data-benchmark]').forEach(button => {
  button.addEventListener('click', () => {
    const data = benchmarks[button.dataset.benchmark];
    document.querySelectorAll('[data-benchmark]').forEach(item => {
      item.classList.toggle('active', item === button);
      item.setAttribute('aria-pressed', String(item === button));
    });
    document.getElementById('speedup').replaceChildren(document.createTextNode(data.speedup), Object.assign(document.createElement('span'), { textContent: '×' }));
    document.getElementById('benchmark-action').textContent = data.action;
    document.getElementById('benchmark-context').textContent = data.context;
    document.getElementById('baseline-label').textContent = data.label;
    document.getElementById('baseline-time').textContent = `${data.baseline.toFixed(1)} ms`;
    document.getElementById('unigroth-time').textContent = `${data.unigroth.toFixed(1)} ms`;
    document.getElementById('unigroth-bar').style.width = `${data.unigroth / data.baseline * 100}%`;
    document.querySelector('.chart').setAttribute('aria-label', `${data.context}: ${data.label} ${data.baseline} milliseconds, UniGroth ${data.unigroth} milliseconds`);
  });
});

const form = document.getElementById('commitment-form');
const secret = document.getElementById('secret');
const statement = document.getElementById('statement');
const digest = document.getElementById('digest');
const verify = document.getElementById('verify');
const tamper = document.getElementById('tamper');
let storedCommitment = null;
let revision = 0;

function setStatus(state, message, kind = 'neutral') {
  document.getElementById('lab-state').textContent = state;
  document.getElementById('lab-message').textContent = message;
  document.querySelector('.lab-output').dataset.status = kind;
}

async function hashInputs() {
  // JSON encodes the two fields unambiguously, including delimiter characters.
  const bytes = new TextEncoder().encode(JSON.stringify(['UNIGROTH-WEB-DEMO-v1', secret.value, statement.value]));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const current = ++revision;
  try {
    const next = await hashInputs();
    if (current !== revision) return;
    storedCommitment = next;
    digest.textContent = storedCommitment;
    verify.disabled = false;
    tamper.disabled = false;
    setStatus('COMMITTED', 'Commitment saved. Edit an input or alter the commitment, then check.', 'valid');
  } catch {
    if (current === revision) setStatus('UNAVAILABLE', 'SHA-256 requires a browser with Web Crypto on HTTPS or localhost.');
  }
});

verify.addEventListener('click', async () => {
  if (!storedCommitment) return;
  const current = ++revision;
  try {
    const candidate = await hashInputs();
    if (current !== revision) return;
    const matches = candidate === storedCommitment;
    setStatus(matches ? 'MATCH' : 'MISMATCH', matches ? 'The current inputs match the stored commitment.' : 'The inputs and stored commitment no longer match. Create a new commitment to reset.', matches ? 'valid' : 'invalid');
  } catch {
    if (current === revision) setStatus('UNAVAILABLE', 'The browser could not calculate the hash. Try again on HTTPS or localhost.');
  }
});

tamper.addEventListener('click', () => {
  if (!storedCommitment) return;
  revision++;
  // Flip one bit in the stored digest without changing either input.
  storedCommitment = (parseInt(storedCommitment[0], 16) ^ 1).toString(16) + storedCommitment.slice(1);
  digest.textContent = storedCommitment;
  setStatus('ALTERED', 'One bit of the stored commitment changed. Check the inputs to compare.');
});

[secret, statement].forEach(input => input.addEventListener('input', () => {
  revision++;
  if (storedCommitment) setStatus('INPUT EDITED', 'The stored commitment is unchanged. Check whether your inputs still match.');
}));

document.getElementById('copy').addEventListener('click', async () => {
  const status = document.getElementById('copy-status');
  try {
    await navigator.clipboard.writeText(document.getElementById('install-code').textContent);
    status.textContent = 'COPIED';
  } catch {
    status.textContent = 'SELECT THE COMMANDS TO COPY';
    const range = document.createRange();
    range.selectNodeContents(document.getElementById('install-code'));
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
});
