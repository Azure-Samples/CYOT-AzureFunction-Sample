// <copyright file="dispatch.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// OTP delivery engine. Each provider is a manifest + adapter under ./providers/<id>.js. dispatchOtp
// resolves the provider, sends via its adapter with a timeout, then maps the provider status to an
// outcome and an HTTP status. Fail-closed: only a Continue outcome is "accepted".


const { ManagedIdentityCredential } = require('@azure/identity');
const { SecretClient } = require('@azure/keyvault-secrets');

// ─── Shared constants ────────────────────────────────────────────────────────

const OUTCOME = Object.freeze({
    CONTINUE: 'Continue',
    FAIL: 'Fail',
    BLOCK: 'Block',
    STEP_UP: 'StepUp',
});

const HTTP_STATUS = Object.freeze({
    OK: 200,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    CONFLICT: 409,
    TOO_MANY_REQUESTS: 429,
    BAD_GATEWAY: 502,
    GATEWAY_TIMEOUT: 504,
});

const RESPONSE_STATUS = Object.freeze({
    ACCEPTED: 'accepted',
    FAILED: 'failed',
    ERROR: 'error',
});

const DEFAULTS = Object.freeze({
    CHANNEL: 'sms',
    ENDPOINT_TIMEOUT_MILLISECONDS: 1500,
    CHANNELS: ['sms', 'voice'],
});

const SECRET_CACHE_TIME_TO_LIVE_MILLISECONDS = 5 * 60 * 1000; // rotated secrets picked up within this window

// ─── Provider registry ───────────────────────────────────────────────────────
// Each ./providers/<id>.js exports { manifest, buildRequest, parseResponse }. Onboarding a provider is
// a new file plus one line here — static so a broken provider fails at load, not mid-request.

const providerRegistry = new Map(
    [
        require('./providers/infobip'),
        require('./providers/sinch'),
        require('./providers/soprano'),
        require('./providers/telesign'),
    ].map((providerModule) => [
        providerModule.manifest.id.toLowerCase(),
        { manifest: providerModule.manifest, adapter: providerModule },
    ]),
);

function getProvider(providerId) {
    return providerId ? providerRegistry.get(String(providerId).toLowerCase()) || null : null;
}

// The request's Provider, else the deployment's EPP_PROVIDER_NAME (set by UX at provisioning). One
// provider is active per deployment — selection is config, not routing the endpoint performs.
function resolveProvider(requestProvider) {
    const providerId = (requestProvider || process.env.EPP_PROVIDER_NAME || '').toLowerCase();
    return getProvider(providerId);
}

// ─── Provider credentials (Key Vault via managed identity) ────────────────────────
// The manifest carries only the secret's *name*; the value is read just-in-time and never logged.

let keyVaultSecretClient = null;
const secretCache = new Map();

// Key Vault is accessed via the Function's managed identity (user-assigned when AZURE_CLIENT_ID is set,
// else system-assigned). The identity needs the Key Vault Secrets User role on the vault.
function createManagedIdentityCredential() {
    return process.env.AZURE_CLIENT_ID
        ? new ManagedIdentityCredential(process.env.AZURE_CLIENT_ID)
        : new ManagedIdentityCredential();
}

function getKeyVaultSecretClient() {
    if (!keyVaultSecretClient) {
        keyVaultSecretClient = new SecretClient(process.env.KEY_VAULT_URL, createManagedIdentityCredential());
    }
    return keyVaultSecretClient;
}

// Resolves a Key Vault secret name to its value (cached briefly so rotations are picked up).
async function resolveSecretValue(keyVaultSecretName) {
    if (!keyVaultSecretName) {
        return '';
    }
    const cachedSecret = secretCache.get(keyVaultSecretName);
    if (cachedSecret && cachedSecret.expiresAt > Date.now()) {
        return cachedSecret.value;
    }

    const secretValue = (await getKeyVaultSecretClient().getSecret(keyVaultSecretName)).value || '';

    secretCache.set(keyVaultSecretName, {
        value: secretValue,
        expiresAt: Date.now() + SECRET_CACHE_TIME_TO_LIVE_MILLISECONDS,
    });
    return secretValue;
}

// Best-effort warm-up at startup so the first request doesn't pay the cold Key Vault cost. Never throws.
async function warmUpSecretCache() {
    if (!process.env.KEY_VAULT_URL) {
        return;
    }
    const providerId = (process.env.EPP_PROVIDER_NAME || '').toLowerCase();
    const providerEntry = providerId && getProvider(providerId);
    const keyVaultSecretName = providerEntry && providerEntry.manifest.auth && providerEntry.manifest.auth.keyVaultSecretName;
    if (!keyVaultSecretName) {
        return;
    }
    try {
        await resolveSecretValue(keyVaultSecretName);
    } catch {
        // ignore
    }
}

// Resolves the outbound credential from the manifest auth block: apiKey (secret [+identity]) or oauth2 (token).
async function resolveProviderCredential(authConfiguration = {}, options = {}) {
    const authenticationMode = authConfiguration.mode || 'apiKey';

    if (authenticationMode === 'oauth2') {
        // oauth2 not wired end-to-end yet — no injected acquireProviderToken, so it fails closed.
        let bearerToken = null;
        if (typeof options.acquireProviderToken === 'function') {
            bearerToken = await options.acquireProviderToken(options.channel);
        }
        return { mode: 'oauth2', token: bearerToken };
    }

    const [secret, identity] = await Promise.all([
        resolveSecretValue(authConfiguration.keyVaultSecretName),
        authConfiguration.identityKeyVaultSecretName
            ? resolveSecretValue(authConfiguration.identityKeyVaultSecretName)
            : Promise.resolve(''),
    ]);
    return { mode: 'apiKey', secret, identity };
}

// ─── Outcome mapping ─────────────────────────────────────────────────────────────

// Translates the provider's parsed status into a normalized outcome. A recognized status wins; an
// unknown status is fail-closed; only a status-less response trusts the HTTP result.
function resolveOutcome(manifest, parsedResponse) {
    const responseMapping = manifest.responseMapping || {};
    const providerStatusKey = parsedResponse.providerStatusName || parsedResponse.providerStatusCode;
    if (providerStatusKey) {
        return responseMapping[providerStatusKey] || responseMapping.default || OUTCOME.FAIL;
    }
    return parsedResponse.success ? OUTCOME.CONTINUE : (responseMapping.default || OUTCOME.FAIL);
}

// Translates the outcome into the endpoint HTTP status. Continue 200, Block 403, StepUp 409; a Fail
// surfaces the provider's failure class — 429 rate-limit, 401 auth (its 401/403), 400 other 4xx, else 502.
function outcomeToHttpStatus(outcome, providerHttpStatus) {
    switch (outcome) {
        case OUTCOME.CONTINUE:
            return HTTP_STATUS.OK;
        case OUTCOME.BLOCK:
            return HTTP_STATUS.FORBIDDEN;
        case OUTCOME.STEP_UP:
            return HTTP_STATUS.CONFLICT;
        case OUTCOME.FAIL:
            if (providerHttpStatus === HTTP_STATUS.TOO_MANY_REQUESTS) return HTTP_STATUS.TOO_MANY_REQUESTS;
            if (providerHttpStatus === HTTP_STATUS.UNAUTHORIZED || providerHttpStatus === HTTP_STATUS.FORBIDDEN) return HTTP_STATUS.UNAUTHORIZED;
            if (providerHttpStatus >= 400 && providerHttpStatus < 500) return HTTP_STATUS.BAD_REQUEST;
            return HTTP_STATUS.BAD_GATEWAY;
        default:
            return HTTP_STATUS.BAD_GATEWAY;
    }
}

// ─── Sending ───────────────────────────────────────────────────────────────────

// POSTs the provider request with a hard timeout; throws a descriptive error on timeout/network failure.
async function fetchWithTimeout(providerRequest, timeoutMilliseconds) {
    const abortController = new AbortController();
    let timedOut = false;
    const timeoutTimer = setTimeout(() => {
        timedOut = true;
        abortController.abort();
    }, timeoutMilliseconds);

    try {
        return await fetch(providerRequest.url, {
            method: providerRequest.method || 'POST',
            headers: providerRequest.headers,
            body: providerRequest.body,
            signal: abortController.signal,
        });
    } catch (error) {
        throw new Error(timedOut ? `endpoint timeout after ${timeoutMilliseconds}ms` : error.message);
    } finally {
        clearTimeout(timeoutTimer);
    }
}

const errorBody = (providerId, reason, requestId) =>
    ({ status: RESPONSE_STATUS.ERROR, provider: providerId, reason, requestId });
const failBody = (providerId, channel, reason, dispatch, requestId) =>
    ({ status: RESPONSE_STATUS.FAILED, outcome: OUTCOME.FAIL, provider: providerId, channel, reason, correlationId: dispatch.correlationId, messageId: dispatch.messageId, requestId });

async function sendViaProvider(providerEntry, dispatch, options) {
    const { shutter, context, requestId } = options;
    const writeLog = (logMessage) => context && context.log(logMessage);

    const { manifest, adapter } = providerEntry;
    const providerId = manifest.id;
    const channel = (dispatch.channel || DEFAULTS.CHANNEL).toLowerCase();

    if (!(manifest.channels || DEFAULTS.CHANNELS).includes(channel)) {
        writeLog(`[DISPATCH_ERROR] requestId=${requestId} provider=${providerId} channel=${channel} not supported`);
        return { httpStatus: HTTP_STATUS.BAD_REQUEST, body: errorBody(providerId, `channel '${channel}' not supported`, requestId) };
    }

    // Resolve the outbound credential; fail closed (502) if missing — this is our credential, not the
    // caller's token. A declared identity secret is also required.
    let credential = null;
    try {
        credential = await resolveProviderCredential(manifest.auth, { channel, acquireProviderToken: options.acquireProviderToken });
    } catch (error) {
        writeLog(`[DISPATCH_ERROR] requestId=${requestId} provider=${providerId} channel=${channel} credential error=${error.message}`);
    }
    const identityRequired = credential && credential.mode === 'apiKey' && !!manifest.auth.identityKeyVaultSecretName;
    const credentialUnavailable = !credential
        || (credential.mode === 'oauth2' && !credential.token)
        || (credential.mode === 'apiKey' && !credential.secret)
        || (identityRequired && !credential.identity);
    if (credentialUnavailable) {
        writeLog(`[DISPATCH_ERROR] requestId=${requestId} provider=${providerId} channel=${channel} provider credential unavailable`);
        return { httpStatus: HTTP_STATUS.BAD_GATEWAY, body: failBody(providerId, channel, 'provider credential unavailable', dispatch, requestId) };
    }

    const endpointBaseUrl = process.env.EPP_PROVIDER_ENDPOINT;
    if (!endpointBaseUrl) {
        writeLog(`[DISPATCH_ERROR] requestId=${requestId} provider=${providerId} channel=${channel} endpoint not configured`);
        return { httpStatus: HTTP_STATUS.BAD_GATEWAY, body: failBody(providerId, channel, 'provider endpoint not configured', dispatch, requestId) };
    }

    const providerRequest = adapter.buildRequest({
        channel,
        endpoint: endpointBaseUrl,
        dispatch,
        credential,
        env: process.env,
    });

    writeLog(`[DISPATCH] requestId=${requestId} provider=${providerId} channel=${channel} correlationId=${dispatch.correlationId} shutter=${!!shutter}`);

    // Shutter mode: everything runs except the actual send.
    if (shutter) {
        writeLog(`[SHUTTER] requestId=${requestId} provider=${providerId} channel=${channel} processed but NOT sending`);
        return {
            httpStatus: HTTP_STATUS.OK,
            body: { status: RESPONSE_STATUS.ACCEPTED, shutterProcessed: true, provider: providerId, channel, correlationId: dispatch.correlationId, messageId: dispatch.messageId, requestId },
        };
    }

    // Endpoint timeout is a provisioned app setting (EPP_PROVIDER_TIMEOUT_MS).
    const timeoutMilliseconds = Number(process.env.EPP_PROVIDER_TIMEOUT_MS) || DEFAULTS.ENDPOINT_TIMEOUT_MILLISECONDS;
    let providerResponse;
    try {
        providerResponse = await fetchWithTimeout(providerRequest, timeoutMilliseconds);
    } catch (error) {
        const isTimeout = typeof error.message === 'string' && error.message.startsWith('endpoint timeout');
        const httpStatus = isTimeout ? HTTP_STATUS.GATEWAY_TIMEOUT : HTTP_STATUS.BAD_GATEWAY;
        writeLog(`[${isTimeout ? 'DISPATCH_TIMEOUT' : 'DISPATCH_ERROR'}] requestId=${requestId} provider=${providerId} channel=${channel} reason=${error.message}`);
        return { httpStatus, body: failBody(providerId, channel, error.message, dispatch, requestId) };
    }

    const responseText = await providerResponse.text();
    let responseJson;
    try {
        responseJson = JSON.parse(responseText);
    } catch {
        // Non-JSON body (e.g. an HTML error page): keep it raw so the adapter's parseResponse still runs.
        responseJson = { raw: responseText };
    }

    const parsedResponse = adapter.parseResponse({
        channel,
        httpStatus: providerResponse.status,
        ok: providerResponse.ok,
        text: responseText,
        json: responseJson,
    });
    const outcome = resolveOutcome(manifest, parsedResponse);
    const httpStatus = outcomeToHttpStatus(outcome, parsedResponse.providerHttpStatus);

    writeLog(`[DISPATCH_RESULT] requestId=${requestId} provider=${providerId} channel=${channel} outcome=${outcome} providerStatus=${parsedResponse.providerStatusName || parsedResponse.providerStatusCode || 'n/a'} httpStatus=${httpStatus} correlationId=${dispatch.correlationId}`);

    return {
        httpStatus,
        body: {
            status: outcome === OUTCOME.CONTINUE ? RESPONSE_STATUS.ACCEPTED : RESPONSE_STATUS.FAILED,
            outcome,
            provider: providerId,
            channel,
            messageId: dispatch.messageId,
            correlationId: dispatch.correlationId,
            providerMessageId: parsedResponse.providerMessageId || null,
            providerStatus: parsedResponse.providerStatusName || parsedResponse.providerStatusCode || null,
            providerStatusDescription: parsedResponse.providerStatusDescription || null,
            requestId,
        },
    };
}

// Public entry: resolve the provider, then send.
async function dispatchOtp(dispatch, options) {
    const { requestProvider, context, requestId } = options;
    const writeLog = (logMessage) => context && context.log(logMessage);

    const providerEntry = resolveProvider(requestProvider);
    if (!providerEntry) {
        writeLog(`[DISPATCH_ERROR] requestId=${requestId} unknown provider=${requestProvider || 'n/a'}`);
        return {
            httpStatus: HTTP_STATUS.BAD_REQUEST,
            body: { status: RESPONSE_STATUS.ERROR, reason: 'unknown provider', requestId },
        };
    }
    return sendViaProvider(providerEntry, dispatch, options);
}

// Fire-and-forget warm-up at module load.
warmUpSecretCache();

module.exports = {
    dispatchOtp,
    getProvider,
    resolveSecretValue,
    DEFAULTS,
};
