'use strict';

const { test, afterEach } = require('node:test');
const assert = require('node:assert');
const { validateToken } = require('../src/functions/security');

const ctx = { log() {} };
const reqWith = (headers = {}) => ({ headers: { get: (k) => headers[k.toLowerCase()] || null } });

afterEach(() => {
    delete process.env.EPP_REQUIRE_AUTH;
    delete process.env.EPP_EXPECTED_AUDIENCE;
    delete process.env.EPP_TENANT_ID;
});

test('skips validation when REQUIRE_AUTH is not true', async () => {
    const r = await validateToken(reqWith(), ctx, 'r');
    assert.equal(r.ok, true);
    assert.equal(r.skipped, true);
});

test('fails when EPP_REQUIRE_AUTH=true but audience/tenant are missing', async () => {
    process.env.EPP_REQUIRE_AUTH = 'true';
    const r = await validateToken(reqWith(), ctx, 'r');
    assert.equal(r.ok, false);
    assert.match(r.reason, /EPP_EXPECTED_AUDIENCE|EPP_TENANT_ID/);
});

test('fails when the bearer token is missing', async () => {
    process.env.EPP_REQUIRE_AUTH = 'true';
    process.env.EPP_EXPECTED_AUDIENCE = 'aud';
    process.env.EPP_TENANT_ID = 'tid';
    const r = await validateToken(reqWith(), ctx, 'r');
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'missing bearer token');
});

test('fails (generic reason) on an invalid token', async () => {
    process.env.EPP_REQUIRE_AUTH = 'true';
    process.env.EPP_EXPECTED_AUDIENCE = 'aud';
    process.env.EPP_TENANT_ID = 'tid';
    const r = await validateToken(reqWith({ authorization: 'Bearer not-a-jwt' }), ctx, 'r');
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'token validation failed');
});
