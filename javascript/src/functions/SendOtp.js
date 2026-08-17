// <copyright file="SendOtp.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// POST /api/SendOtp — the SAS → CYOT delivery endpoint. Validates the Entra token, parses the cleartext
// routing envelope, decrypts the JWE delivery context (PII lives there), dispatches to the provider, and
// echoes the nonce to prove decryption. Privacy: the OTP code, phone digits, and decrypted context are
// never logged (presence only); the response body is the minimal CyotEndpointResponse.

const { app } = require('@azure/functions');
const crypto = require('crypto');
const { validateToken } = require('./security');
const { dispatchOtp } = require('./dispatch');
const { parseEnvelope, decryptDeliveryContext, contextToDispatch, MODE } = require('./cyot');

app.http('SendOtp', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        const callerOid = request.headers.get('x-ms-client-principal-id') || null;
        const requestId = crypto.randomUUID();
        const clientRequestId = request.headers.get('x-ms-client-request-id') || requestId;
        const headerCorrelationId = request.headers.get('x-ms-correlation-id') || null;

        const tokenValidation = await validateToken(request, context, requestId);
        if (!tokenValidation.ok) {
            context.log(`[AUTH_REJECT] requestId=${requestId} reason=${tokenValidation.reason}`);
            return { status: 401, jsonBody: { error: 'unauthorized', reason: tokenValidation.reason, requestId } };
        }

        let payload;
        let rawBody;
        try {
            rawBody = await request.text();
            payload = JSON.parse(rawBody);
        } catch {
            context.log(`[ERROR] requestId=${requestId} invalid JSON body bytes=${rawBody ? rawBody.length : 0}`);
            return { status: 400, jsonBody: { error: 'bad_request', reason: 'invalid JSON body', requestId } };
        }

        const { envelope, error: envelopeError } = parseEnvelope(payload);
        if (envelopeError) {
            context.log(`[VALIDATION_ERROR] requestId=${requestId} ${envelopeError}`);
            return { status: 400, jsonBody: { error: 'bad_request', reason: envelopeError, requestId } };
        }
        const correlationId = envelope.correlationId || headerCorrelationId || requestId;

        let deliveryContext;
        try {
            deliveryContext = await decryptDeliveryContext(envelope.encryptedDeliveryContext, { env: process.env });
        } catch (decryptError) {
            context.log(`[DECRYPT_ERROR] requestId=${requestId} correlationId=${correlationId} reason=${decryptError.message}`);
            return { status: 400, jsonBody: { error: 'decryption_failed', correlationId, requestId } };
        }

        if (!deliveryContext || !deliveryContext.nonce || !deliveryContext.phoneNumber || !deliveryContext.message) {
            context.log(`[VALIDATION_ERROR] requestId=${requestId} correlationId=${correlationId} incomplete delivery context`);
            return { status: 400, jsonBody: { error: 'bad_request', reason: 'incomplete delivery context', correlationId, requestId } };
        }

        const nonce = deliveryContext.nonce;
        const evaluation = envelope.mode === MODE.EVALUATION;

        // Respect ttlSeconds: don't start a live delivery for an already-expired passcode (contract §7).
        if (!evaluation && typeof envelope.ttlSeconds === 'number' && envelope.ttlSeconds <= 0) {
            context.log(`[EXPIRED] requestId=${requestId} correlationId=${correlationId} ttl=${envelope.ttlSeconds}`);
            return { status: 400, jsonBody: { error: 'request_expired', correlationId, requestId } };
        }

        context.log(
            `[SENDOTP] requestId=${requestId} caller=${callerOid || 'n/a'} type=${envelope.type || 'n/a'} ` +
            `tenant=${envelope.tenantId || 'n/a'} correlationId=${correlationId} channel=${envelope.channel} mode=${envelope.mode} ` +
            `ttl=${envelope.ttlSeconds ?? 'n/a'} phone=present message=present risk=${deliveryContext.riskContext ? 'present' : 'absent'}`
        );

        const dispatch = contextToDispatch(deliveryContext, envelope, clientRequestId);

        try {
            const { httpStatus } = await dispatchOtp(dispatch, {
                tenantId: envelope.tenantId,
                requestProvider: undefined,
                shutter: evaluation,
                context,
                requestId,
            });
            // Contract: acceptance is 202 Accepted (async delivery); the engine signals acceptance as 200.
            const accepted = httpStatus === 200;
            return {
                status: accepted ? 202 : httpStatus,
                jsonBody: { nonce, correlationId, providerStatus: accepted ? 'accepted' : 'failed' },
            };
        } catch (error) {
            context.log(`[EXCEPTION] requestId=${requestId} error=${error.message} stack=${error.stack}`);
            return { status: 500, jsonBody: { nonce, correlationId, providerStatus: 'failed' } };
        }
    },
});
