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
const { readConfig } = require('./config');

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

// Reads the JWE protected (first) segment without decrypting, so kid/alg/enc can be logged.
function readProtectedHeader(compactJwe) {
    const protectedSegment = String(compactJwe).split('.')[0] || '';
    return JSON.parse(Buffer.from(protectedSegment, 'base64url').toString('utf8'));
}

// The key is imported once and reused: doing it per delivery would add an RSA import inside the
// response budget and turn a bad key into a failure on every call instead of one obvious first failure.
let cachedKey;
let cachedKeyPem;

// The setup script stores the key as base64 over the PEM so its newlines survive being carried as a
// secret and then as an app setting, so accept either form.
function normalizePem(value) {
    const text = String(value || '');
    if (text.includes('-----BEGIN')) return text;
    return Buffer.from(text, 'base64').toString('utf8');
}

function loadPrivateKey(pem) {
    if (!pem) {
        throw new Error('private key unavailable (EPP_DECRYPTION_KEY_PEM is not set)');
    }
    if (cachedKey && cachedKeyPem === pem) {
        return cachedKey;
    }
    cachedKey = crypto.createPrivateKey(normalizePem(pem));
    cachedKeyPem = pem;
    return cachedKey;
}

// Decrypts the JWE compact serialization. Returns the protected header (for kid/alg logging) alongside
// the CyotDeliveryContext. `keyProvider(kid)` is injectable so tests can supply a local key.
async function decryptDeliveryContext(compactJwe, options = {}) {
    const config = options.config || readConfig(options.env || process.env);
    assertWellFormedJwe(compactJwe);
    const header = readProtectedHeader(compactJwe);
    const pem = options.keyProvider ? await options.keyProvider(header.kid) : config.decryptionKeyPem;
    const privateKey = loadPrivateKey(pem);
    // Pin alg/enc so a tampered header can't downgrade the crypto (contract: RSA-OAEP-256 + A256GCM).
    const { plaintext } = await compactDecrypt(compactJwe, privateKey, {
        keyManagementAlgorithms: ['RSA-OAEP-256'],
        contentEncryptionAlgorithms: ['A256GCM'],
    });
    return { header, context: JSON.parse(Buffer.from(plaintext).toString('utf8')) };
}

// Maps the decrypted context + envelope onto the engine's dispatch shape. The message is pre-rendered
// (already contains the passcode), so there is no separate code — the fields mirror CyotDeliveryContext.
// Voice: left alone, a TTS engine reads 641895 as "six hundred forty-one thousand eight hundred
// ninety-five", which no user can type. Spacing the digits makes it read them one at a time.
function spacePasscodeForVoice(message) {
    return String(message || '').replace(/\b\d{4,8}\b/, (digits) => digits.split('').join(' '));
}

function contextToDispatch(context, envelope, messageId) {
    const channel = CHANNEL_BY_CODE[envelope.channel];
    return {
        destination: context.phoneNumber,
        message: channel === 'voice' ? spacePasscodeForVoice(context.message) : context.message,
        channel,
        messageId,
        correlationId: envelope.correlationId,
        locale: context.locale || undefined,
    };
}

module.exports = {
    parseEnvelope,
    readProtectedHeader,
    loadPrivateKey,
    decryptDeliveryContext,
    contextToDispatch,
    CHANNEL_BY_CODE,
    MODE,
};
