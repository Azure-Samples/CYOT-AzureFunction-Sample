// <copyright file="cyot.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// SAS → CYOT envelope handling. SAS sends a cleartext routing envelope (SendCyotOtpRequest) whose PII
// (phone + rendered message, which contains the passcode) is encrypted in a JWE. This module parses the
// envelope, decrypts the JWE delivery context (RSA-OAEP-256 + A256GCM, key selected by the JOSE `kid`),
// and maps the CyotDeliveryContext onto the dispatch engine's request shape.

const crypto = require('crypto');
const { compactDecrypt } = require('jose');
const { resolveSecretValue } = require('./dispatch');

// CyotChannel: 1=Sms, 2=Voice (0=Undefined). CyotDeliveryMode: 1=Live, 2=Evaluation (do NOT deliver).
const CHANNEL_BY_CODE = Object.freeze({ 1: 'sms', 2: 'voice' });
const CHANNEL_BY_NAME = Object.freeze({ sms: 1, voice: 2 });
const MODE = Object.freeze({ LIVE: 1, EVALUATION: 2 });
const MODE_BY_NAME = Object.freeze({ live: 1, evaluation: 2 });

// channel/mode accept the int enum (1/2) or the string form ("sms"/"voice", "live"/"evaluation").
function normalizeChannel(channel) {
    if (CHANNEL_BY_CODE[channel]) return Number(channel);
    if (typeof channel === 'string' && CHANNEL_BY_NAME[channel.toLowerCase()]) return CHANNEL_BY_NAME[channel.toLowerCase()];
    return null;
}
function normalizeMode(mode) {
    if (mode === MODE.LIVE || mode === MODE.EVALUATION) return mode;
    if (typeof mode === 'string' && MODE_BY_NAME[mode.toLowerCase()]) return MODE_BY_NAME[mode.toLowerCase()];
    return null;
}

// Validates + normalizes the cleartext envelope. Returns { envelope } or { error }.
function parseEnvelope(payload) {
    if (!payload || typeof payload !== 'object') {
        return { error: 'invalid envelope' };
    }
    const { type, tenantId, correlationId, channel, mode, ttlSeconds, encryptedDeliveryContext } = payload;
    if (typeof encryptedDeliveryContext !== 'string' || !encryptedDeliveryContext) {
        return { error: 'encryptedDeliveryContext is required' };
    }
    const channelCode = normalizeChannel(channel);
    if (!channelCode) {
        return { error: `unsupported channel '${channel}'` };
    }
    const modeCode = normalizeMode(mode);
    if (!modeCode) {
        return { error: `unsupported mode '${mode}'` };
    }
    return { envelope: { type, tenantId, correlationId, channel: channelCode, mode: modeCode, ttlSeconds, encryptedDeliveryContext } };
}

// Reject oversized or structurally invalid JWEs before base64-decoding or allocating buffers.
const MAX_JWE_LENGTH = 16384;

function assertWellFormedJwe(compactJwe) {
    if (typeof compactJwe !== 'string' || compactJwe.length === 0) {
        throw new Error('malformed JWE');
    }
    if (compactJwe.length > MAX_JWE_LENGTH) {
        throw new Error('delivery context exceeds size limit');
    }
    const segments = compactJwe.split('.');
    if (segments.length !== 5 || segments.some((segment) => segment.length === 0)) {
        throw new Error('malformed JWE: expected five non-empty segments');
    }
}

// Reads the `kid` from the JWE protected (first) segment without decrypting.
function readKid(compactJwe) {
    const protectedSegment = String(compactJwe).split('.')[0] || '';
    const header = JSON.parse(Buffer.from(protectedSegment, 'base64url').toString('utf8'));
    return header.kid || null;
}

// Default key source: an inline PEM (local/dev) or a Key Vault secret (deployed). The `kid` selects the
// secret name when JWE_PRIVATE_KEY_SECRET is not set.
async function resolvePrivateKeyPem(kid, env) {
    if (env.CYOT_JWE_PRIVATE_KEY_PEM) {
        return env.CYOT_JWE_PRIVATE_KEY_PEM;
    }
    const secretName = env.JWE_PRIVATE_KEY_SECRET || kid;
    if (!secretName) {
        return '';
    }
    return resolveSecretValue(secretName);
}

// Decrypts the JWE compact serialization to the CyotDeliveryContext. `keyProvider(kid)` is injectable
// so tests can supply a local key instead of Key Vault.
async function decryptDeliveryContext(compactJwe, options = {}) {
    const env = options.env || process.env;
    assertWellFormedJwe(compactJwe);
    const keyProvider = options.keyProvider || ((kid) => resolvePrivateKeyPem(kid, env));
    const kid = readKid(compactJwe);
    const pem = await keyProvider(kid);
    if (!pem) {
        throw new Error('private key unavailable');
    }
    const privateKey = crypto.createPrivateKey(pem);
    // Pin alg/enc so a tampered header can't downgrade the crypto (contract: RSA-OAEP-256 + A256GCM).
    const { plaintext } = await compactDecrypt(compactJwe, privateKey, {
        keyManagementAlgorithms: ['RSA-OAEP-256'],
        contentEncryptionAlgorithms: ['A256GCM'],
    });
    return JSON.parse(Buffer.from(plaintext).toString('utf8'));
}

// Maps the decrypted context + envelope onto the engine's dispatch shape. The message is pre-rendered
// (already contains the passcode), so there is no separate code — the fields mirror CyotDeliveryContext.
function contextToDispatch(context, envelope, messageId) {
    return {
        destination: context.phoneNumber,
        message: context.message,
        channel: CHANNEL_BY_CODE[envelope.channel],
        messageId,
        correlationId: envelope.correlationId,
        locale: context.locale || undefined,
    };
}

module.exports = {
    parseEnvelope,
    readKid,
    decryptDeliveryContext,
    contextToDispatch,
    CHANNEL_BY_CODE,
    MODE,
};
