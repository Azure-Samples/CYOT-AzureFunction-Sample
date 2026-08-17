'use strict';

// Privacy assertion: the OTP code and phone number must never appear in logs or the response body.
// (They necessarily appear in the outbound provider request — that is the delivery itself.)

const { test, mock } = require('node:test');
const assert = require('node:assert');

// The provider secret comes from Key Vault via managed identity in production; mock getSecret here.
process.env.KEY_VAULT_URL = 'https://test.vault.azure.net';
process.env.INFOBIP_ENDPOINT = 'https://api.infobip.com';
const { SecretClient } = require('@azure/keyvault-secrets');
mock.method(SecretClient.prototype, 'getSecret', async () => ({ value: 'ib' }));

const { dispatchOtp } = require('../src/functions/dispatch');

const CODE = '918273';
const PHONE = '+15551234567';

global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ messages: [{ status: { name: 'DELIVERED' }, messageId: 'x' }] }),
});

test('OTP code and phone never appear in logs or the response body', async () => {
    const logs = [];
    const ctx = { log: (m) => logs.push(String(m)) };

    const r = await dispatchOtp(
        { destination: PHONE, message: `Your code is ${CODE}`, channel: 'sms', messageId: 'm', correlationId: 'c' },
        { tenantId: 't', requestProvider: 'infobip', context: ctx, requestId: 'r' },
    );
    assert.equal(r.httpStatus, 200);

    for (const line of logs) {
        assert.ok(!line.includes(CODE), `code leaked in a log line: ${line}`);
        assert.ok(!line.includes(PHONE), `phone leaked in a log line: ${line}`);
    }

    const bodyStr = JSON.stringify(r.body);
    assert.ok(!bodyStr.includes(CODE), 'code leaked in response body');
    assert.ok(!bodyStr.includes(PHONE), 'phone leaked in response body');
});
