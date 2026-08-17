// <copyright file="infobip.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// Infobip provider: SMS via /sms/3/messages, voice via /tts/3/advanced.
// Auth: App API key (default) or a Bearer token (oauth2 mode). Voice is unverified.

const manifest = {
    id: 'infobip',
    auth: { mode: 'apiKey', keyVaultSecretName: 'infobip-api-key' },
    // Infobip status groups (groupName): ACCEPTED/PENDING/DELIVERED = success, REJECTED/EXPIRED/UNDELIVERABLE = fail.
    responseMapping: {
        ACCEPTED: 'Continue',
        PENDING: 'Continue',
        DELIVERED: 'Continue',
        REJECTED: 'Fail',
        EXPIRED: 'Fail',
        UNDELIVERABLE: 'Fail',
        default: 'Fail',
    },
};

function buildRequest({ channel, endpoint, dispatch, credential, env }) {
    const base = endpoint;
    const senderId = env.INFOBIP_SENDER_ID || 'Verify';
    const authorization = credential.mode === 'oauth2' ? `Bearer ${credential.token}` : `App ${credential.secret}`;
    const headers = {
        Authorization: authorization,
        'Content-Type': 'application/json',
        Accept: 'application/json',
    };

    if (channel === 'voice') {
        const body = {
            messages: [{
                from: env.INFOBIP_VOICE_FROM || senderId,
                destinations: [{ to: dispatch.destination, messageId: dispatch.correlationId || dispatch.messageId }],
                text: dispatch.message,
                language: dispatch.locale || 'en',
                voice: { name: 'Joanna', gender: 'female' },
            }],
        };
        return { url: `${base}/tts/3/advanced`, method: 'POST', headers, body: JSON.stringify(body) };
    }

    const body = {
        messages: [{
            sender: senderId,
            destinations: [{ to: dispatch.destination, messageId: dispatch.correlationId || dispatch.messageId }],
            content: { text: dispatch.message },
        }],
    };
    return { url: `${base}/sms/3/messages`, method: 'POST', headers, body: JSON.stringify(body) };
}

function parseResponse({ httpStatus, ok, json }) {
    const firstMessage = json && json.messages && json.messages[0];
    const status = (firstMessage && firstMessage.status) || {};
    return {
        success: ok,
        providerHttpStatus: httpStatus,
        providerMessageId: (firstMessage && firstMessage.messageId) || null,
        providerStatusName: (status.groupName || status.name || '').toUpperCase() || null,
        providerStatusDescription: status.description || null,
        providerResponse: json,
    };
}

module.exports = { manifest, buildRequest, parseResponse };
