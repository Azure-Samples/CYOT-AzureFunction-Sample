// <copyright file="config.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// Every setting the endpoint reads, in one place. Names are the EPP_* app settings provisioned on the
// Function App; EPP_DECRYPTION_KEY_PEM is a Key Vault reference, so the runtime only ever sees the
// resolved PEM and never calls Key Vault itself.

const DEFAULT_TIMEOUT_MS = 1500;

// Read per call so a settings change (or a test) is picked up without a cold start.
function readConfig(env = process.env) {
    return {
        decryptionKeyPem: env.EPP_DECRYPTION_KEY_PEM || '',
        expectedKeyId: env.EPP_ENCRYPTION_KEY_ID || '',
        expectedAudience: env.EPP_EXPECTED_AUDIENCE || '',
        expectedClientId: env.EPP_EXPECTED_CLIENT_ID || '',
        tenantId: env.EPP_TENANT_ID || '',
        // PII in the log. Diagnostics only, and must stay false in production.
        logPlaintext: String(env.EPP_LOG_PLAINTEXT || '').toLowerCase() === 'true',
        requireAuth: String(env.EPP_REQUIRE_AUTH || '').toLowerCase() === 'true',
        provider: {
            name: env.EPP_PROVIDER_NAME || '',
            endpoint: env.EPP_PROVIDER_ENDPOINT || '',
            accountName: env.EPP_PROVIDER_ACCOUNT_NAME || '',
            timeoutMs: Number(env.EPP_PROVIDER_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
        },
    };
}

// Reported, never thrown: a missing provider setting still lets the delivery prove decryption.
function missingSettings(config) {
    const absent = [];
    if (!config.decryptionKeyPem) absent.push('EPP_DECRYPTION_KEY_PEM');
    if (!config.provider.name) absent.push('EPP_PROVIDER_NAME');
    if (!config.provider.endpoint) absent.push('EPP_PROVIDER_ENDPOINT');
    if (config.requireAuth && !config.expectedAudience) absent.push('EPP_EXPECTED_AUDIENCE');
    if (config.requireAuth && !config.tenantId) absent.push('EPP_TENANT_ID');
    return absent;
}

module.exports = { readConfig, missingSettings };
