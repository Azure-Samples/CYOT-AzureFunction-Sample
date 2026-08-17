#!/usr/bin/env node
// End-to-end nonce-echo check for the CYOT endpoint.
//
// Generates a random 16-byte nonce, builds a CyotDeliveryContext, encrypts it as a JWE
// (RSA-OAEP-256 + A256GCM) with the test certificate's PUBLIC key, wraps it in the SAS envelope, then
// verifies the endpoint echoes the nonce (proof of decryption — the same check SAS does with
// FixedTimeEquals). Evaluation mode (mode=2) by default, so nothing is actually delivered.
//
// Usage:
//   node scripts/test-nonce-echo.mjs                 # in-process self-test (uses the real decrypt code)
//   node scripts/test-nonce-echo.mjs --url=http://localhost:7071/api/SendOtp
//   node scripts/test-nonce-echo.mjs --url=https://<app>.azurewebsites.net/api/SendOtp --token=<jwt>
//   node scripts/test-nonce-echo.mjs --publicKey=scripts/.keys/cyot-jwe-public.pem --kid=cyot-poc-jwe-1
//
// With no --url it decrypts locally via ../javascript/src/functions/cyot.js and echoes — zero setup,
// always runnable. With --url it POSTs to a live endpoint (which must hold the matching private key).

import { createRequire } from 'node:module';
import { readFileSync, existsSync } from 'node:fs';
import { randomBytes, timingSafeEqual, generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const jose = require(join(here, '../javascript/node_modules/jose'));
const cyot = require(join(here, '../javascript/src/functions/cyot.js'));

const args = Object.fromEntries(process.argv.slice(2).map((a) => {
    const raw = a.replace(/^--/, '');
    const eq = raw.indexOf('=');
    return eq === -1 ? [raw, true] : [raw.slice(0, eq), raw.slice(eq + 1)];
}));

const kid = args.kid || 'cyot-poc-jwe-1';
const mode = Number(args.mode || 2); // 2 = Evaluation (no delivery)
const token = args.token || process.env.CYOT_TOKEN || null;

// Key material: use the provisioned test cert if present, else generate an ephemeral keypair so the
// self-test runs with zero setup.
let publicPem;
let privatePem;
const defaultPublic = join(here, '.keys/cyot-jwe-public.pem');
const publicKeyPath = args.publicKey ? resolve(String(args.publicKey)) : defaultPublic;
if (existsSync(publicKeyPath)) {
    publicPem = readFileSync(publicKeyPath, 'utf8');
    const privatePath = join(dirname(publicKeyPath), 'cyot-jwe-private.pem');
    if (existsSync(privatePath)) privatePem = readFileSync(privatePath, 'utf8');
    console.log(`Using test certificate: ${publicKeyPath} (kid=${kid})`);
} else {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
    privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    console.log(`No test cert found; generated an ephemeral keypair for the self-test (kid=${kid})`);
}

const nonce = randomBytes(16).toString('base64url');
const context = {
    nonce,
    phoneNumber: args.phone || '+14255551234',
    locale: 'en-US',
    message: args.message || 'Your code is 1 2 3 4 5 6',
};

const publicKey = await jose.importSPKI(publicPem, 'RSA-OAEP-256');
const encryptedDeliveryContext = await new jose.CompactEncrypt(Buffer.from(JSON.stringify(context)))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', kid })
    .encrypt(publicKey);

const envelope = {
    type: 'microsoft.mfa.otpDeliver.v1',
    tenantId: '00000000-0000-0000-0000-000000000000',
    correlationId: 'nonce-echo-' + Date.now(),
    channel: 1,
    mode,
    ttlSeconds: 60,
    encryptedDeliveryContext,
};

let status;
let echoedNonce = '';
let responseBody;

if (args.url) {
    const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Microsoft-AzureMFA-SAS-CYOT/1.0',
        'x-ms-correlation-id': envelope.correlationId,
        'x-ms-client-request-id': 'attempt-' + Date.now(),
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    console.log(`POST ${args.url}  (mode=${mode}, nonce=${nonce})`);
    const res = await fetch(String(args.url), { method: 'POST', headers, body: JSON.stringify(envelope) });
    status = res.status;
    responseBody = await res.text();
    try { echoedNonce = JSON.parse(responseBody).nonce || ''; } catch { echoedNonce = ''; }
} else {
    // In-process: decrypt with the real production code, then echo like the endpoint does.
    if (!privatePem) {
        console.error('FAIL: no private key available for the self-test (provide --url or the .keys pair).');
        process.exit(1);
    }
    console.log(`Self-test (in-process decrypt via cyot.js)  (mode=${mode}, nonce=${nonce})`);
    const parsed = cyot.parseEnvelope(envelope);
    if (parsed.error) { console.error(`FAIL: envelope rejected: ${parsed.error}`); process.exit(1); }
    const decrypted = await cyot.decryptDeliveryContext(envelope.encryptedDeliveryContext, { keyProvider: () => privatePem });
    echoedNonce = decrypted.nonce; // the endpoint echoes this back verbatim
    status = 200;
    responseBody = JSON.stringify({ nonce: echoedNonce, correlationId: envelope.correlationId, providerStatus: 'accepted' });
}

console.log(`-> ${status} ${responseBody}`);

const expected = Buffer.from(nonce);
const actual = Buffer.from(echoedNonce);
const ok = status >= 200 && status < 300 && expected.length === actual.length && timingSafeEqual(expected, actual);
console.log(ok
    ? 'PASS: nonce echoed and matches — decryption proven.'
    : 'FAIL: nonce mismatch / non-2xx — SAS would fall back to native CAPP delivery.');
process.exit(ok ? 0 : 1);
