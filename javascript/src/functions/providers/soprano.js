// <copyright file="soprano.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// Soprano provider: Soprano Connect API (MEMS): POST {base}/messages/{sms|voice}; base is https://<mems_domain>/cgpapi.
// Auth: X-MEMS-API-ID + X-MEMS-API-Key headers (both from Key Vault), or a Bearer JWT.
// Sender is a provisioned source endpoint (SOPRANO_SOURCE_ID), not a free-text string. Verified live (HTTP 201, ENROUTE).

const manifest = {
    id: 'soprano',
    auth: {
        mode: 'apiKey',
        keyVaultSecretName: 'soprano-api-key',
        identityKeyVaultSecretName: 'soprano-api-id',
    },
    responseMapping: {
        ENROUTE: 'Continue',
        ACCEPTED: 'Continue',
        SUBMITTED: 'Continue',
        SENT: 'Continue',
        DELIVERED: 'Continue',
        QUEUED: 'Continue',
        FAILED: 'Fail',
        REJECTED: 'Fail',
        BLOCKED: 'Block',
        default: 'Fail',
    },
};

function buildRequest({ channel, endpoint, dispatch, credential, env }) {
    const base = endpoint;
    const messageType = channel === 'voice' ? 'voice' : 'sms';

    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (credential.mode === 'oauth2') {
        headers.Authorization = `Bearer ${credential.token}`;
    } else {
        headers['X-MEMS-API-ID'] = credential.identity;
        headers['X-MEMS-API-Key'] = credential.secret;
    }

    const body = {
        messageType,
        destination: dispatch.destination,
        text: dispatch.message,
        clientReference: dispatch.correlationId || dispatch.messageId,
    };
    // Sender: a provisioned source endpoint (endpoints:[{type,id}]) is what Soprano accepts; free-text source is a fallback.
    if (env.SOPRANO_SOURCE_ID) {
        body.endpoints = [{ type: Number(env.SOPRANO_SOURCE_TYPE || 1), id: Number(env.SOPRANO_SOURCE_ID) }];
    } else if (env.SOPRANO_SENDER_ID) {
        body.source = env.SOPRANO_SENDER_ID;
    }
    // Voice: Soprano speaks the fully-rendered message via text-to-speech. `language` must be a full
    // Nexmo voice code (e.g. en-US), not a bare `en`.
    if (messageType === 'voice') {
        const voiceLanguage = env.SOPRANO_VOICE_LANGUAGE
            || (dispatch.locale && dispatch.locale.includes('-') ? dispatch.locale : 'en-US');
        delete body.text;
        body.voice = {
            text2voice: {
                beforePasswordText: dispatch.message || '',
                password: '',
                afterPasswordText: '',
                language: voiceLanguage,
                gender: Number(env.SOPRANO_VOICE_GENDER || 1),
                loop: 1,
            },
        };
    }

    return { url: `${base}/messages/${messageType}`, method: 'POST', headers, body: JSON.stringify(body) };
}

function parseResponse({ httpStatus, ok, json }) {
    const payload = (Array.isArray(json) ? json[0] : json) || {};
    const status = (payload.status || payload.state || '').toString().toUpperCase() || (ok ? 'SUBMITTED' : null);
    return {
        success: ok,
        providerHttpStatus: httpStatus,
        providerMessageId: (payload.id != null ? String(payload.id) : null) || payload.messageId || null,
        providerStatusName: status,
        providerStatusDescription: payload.errorDescription || payload.statusText || payload.description || null,
        providerResponse: json,
    };
}

module.exports = { manifest, buildRequest, parseResponse };
