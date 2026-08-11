/**
 * Proves the daemon actually runs: init, issue an agent, start it, pay a stub seller over the
 * socket. Everything here goes through the built CLI and the real socket, not the library.
 */
import { execFileSync, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signClaim } from '../dist/credential.js';

// Publicly known test key (anvil account #1). Never used with real funds.
const TEST_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;

const dir = mkdtempSync(join(tmpdir(), 'purser-smoke-'));
const db = join(dir, 'purser.db');
const sock = join(dir, 'purser.sock');
const cli = (...args) => execFileSync('node', [CLI, ...args, '--db', db], { encoding: 'utf8' });

function required(url) {
  return Buffer.from(JSON.stringify({
    x402Version: 2,
    resource: { url },
    accepts: [{
      scheme: 'exact', network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amount: '1000', payTo: '0x000000000000000000000000000000000000dEaD',
      maxTimeoutSeconds: 3600,
      extra: { credentialTypes: ['authorization'], name: 'USD Coin', version: '2' },
    }],
  })).toString('base64');
}

let sawSignature = false;
const seller = createServer((req, res) => {
  const url = `http://127.0.0.1:${seller.address().port}/thing`;
  if (!req.headers['payment-signature']) {
    res.writeHead(402, { 'PAYMENT-REQUIRED': required(url) });
    return res.end('pay first');
  }
  sawSignature = true;
  res.writeHead(200, { 'PAYMENT-RESPONSE': Buffer.from('{"ok":true}').toString('base64') });
  res.end('the goods');
});

function ask(request) {
  return new Promise((resolve, reject) => {
    const s = createConnection(sock, () => s.write(`${JSON.stringify(request)}\n`));
    let buf = '';
    s.on('data', (c) => { buf += c; if (buf.includes('\n')) { s.end(); resolve(JSON.parse(buf.split('\n')[0])); } });
    s.on('error', reject);
  });
}

let daemon;
try {
  await new Promise((r) => seller.listen(0, '127.0.0.1', r));
  const port = seller.address().port;

  console.log('1. init:', cli('init', '--allowance', '100000', '--period', '3600', '--currency', 'USDC').trim());

  const out = cli('agent', 'add', 'buyer', '--cap', '50000', '--per-tx', '5000',
    '--period', '3600', '--hosts', '127.0.0.1', '--currencies', 'USDC');
  const agentRef = out.match(/agent_ref: (\S+)/)[1];
  const privateKeyPem = out.split('give this to the agent):\n')[1].trim();
  console.log('2. issued agent:', agentRef);

  daemon = spawn('node', [CLI, 'run', '--socket', sock, '--db', db], { stdio: ['pipe', 'pipe', 'pipe'] });
  daemon.stdin.write(`${TEST_KEY}\n`);
  await new Promise((resolve, reject) => {
    daemon.stdout.on('data', (d) => { if (d.toString().includes('listening')) resolve(); });
    daemon.stderr.on('data', (d) => process.stderr.write(`  daemon: ${d}`));
    daemon.on('exit', (c) => reject(new Error(`daemon exited ${c}`)));
    setTimeout(() => reject(new Error('daemon did not start in 10s')), 10_000);
  });
  console.log('3. daemon up on', sock);

  const claim = {
    agentRef, resourceUrl: `http://127.0.0.1:${port}/thing`,
    ceilingAtomic: '2000', currency: 'USDC',
    nonce: `smoke-${port}`, timestamp: new Date().toISOString(),
  };
  const paid = await ask({ v: 1, ...claim, signature: signClaim(claim, privateKeyPem) });
  console.log('4. paid request ->', JSON.stringify(paid));

  const over = { ...claim, nonce: `smoke-over-${port}`, ceilingAtomic: '10' };
  const refused = await ask({ v: 1, ...over, signature: signClaim(over, privateKeyPem) });
  console.log('5. over-ceiling  ->', refused.status, refused.reason ?? '');

  const forged = { ...claim, nonce: `smoke-forged-${port}` };
  const bad = await ask({ v: 1, ...forged, signature: 'AAAA' });
  console.log('6. forged sig    ->', bad.status, bad.reason ?? '');

  const ok = paid.status === 'paid' && sawSignature && refused.status === 'refused' && bad.status === 'refused';
  console.log(ok ? '\nSMOKE PASS' : '\nSMOKE FAIL');
  process.exitCode = ok ? 0 : 1;
} finally {
  daemon?.kill('SIGTERM');
  seller.close();
  rmSync(dir, { recursive: true, force: true });
}
