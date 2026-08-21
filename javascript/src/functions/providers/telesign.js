// <copyright file="telesign.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// Telesign provider: SMS via /v1/messaging, voice via /v1/voice (form-urlencoded).
// Auth: HTTP Basic (customer_id:api_key), or a Bearer token in oauth2 mode.
// Both customer_id and api_key come from Key Vault (rotate either by replacing the secret value — no redeploy).

const manifest = {
    id: 'telesign',
    auth: {
        mode: 'apiKey',
        keyVaultSecretName: 'telesign-api-key',
        identityKeyVaultSecretName: 'telesign-customer-id',
    },
    // SMS: 200/203 delivered, 290/291/292 in progress. Voice: 100 answered, 101/102/103 placed/ringing/in progress.
    responseMapping: {
        200: 'Continue',
        203: 'Continue',
        290: 'Continue',
        291: 'Continue',
        292: 'Continue',
        100: 'Continue',
        101: 'Continue',
        102: 'Continue',
        103: 'Continue',
        default: 'Fail',
    },
};

function buildRequest({ channel, endpoint, dispatch, credential, env }) {
    const base = endpoint;
    const contentType = 'application/x-www-form-urlencoded';

    const authorization = credential.mode === 'oauth2'
        ? `Bearer ${credential.token}`
        : `Basic ${Buffer.from(`${credential.identity}:${credential.secret}`).toString('base64')}`;

    let path;
    let params;
    if (channel === 'voice') {
        path = '/v1/voice';
        params = new URLSearchParams({
            phone_number: dispatch.destination,
            message: dispatch.message,
            message_type: 'OTP',
            voice: env.TELESIGN_VOICE || 'f-en-US',
            external_id: dispatch.correlationId || dispatch.messageId,
        });
    } else {
        path = '/v1/messaging';
        params = new URLSearchParams({
            phone_number: dispatch.destination,
            message: dispatch.message,
            sender_id: env.EPP_PROVIDER_ACCOUNT_NAME || '',
            message_type: 'OTP',
            external_id: dispatch.correlationId || dispatch.messageId,
            is_primary: 'true',
        });
    }

    return {
        url: `${base}${path}`,
        method: 'POST',
        headers: {
            Authorization: authorization,
            'Content-Type': contentType,
            Accept: 'application/json',
        },
        body: params.toString(),
    };
}

function parseResponse({ httpStatus, ok, json }) {
    const status = (json && json.status) || {};
    return {
        success: ok,
        providerHttpStatus: httpStatus,
        providerMessageId: (json && json.reference_id) || null,
        providerStatusCode: status.code != null ? String(status.code) : null,
        providerStatusName: null,
        providerStatusDescription: status.description || null,
        providerResponse: json,
    };
}

module.exports = { manifest, buildRequest, parseResponse };
