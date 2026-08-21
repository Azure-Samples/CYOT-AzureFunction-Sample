// <copyright file="security.js" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

'use strict';

// Endpoint security: optional inbound bearer-token validation — anonymous unless REQUIRE_AUTH=true,
// which validates a Microsoft JWT (iss/aud/exp/RS256). 'jose' is lazy-loaded.

const jwksByTenant = new Map();

// Gets (and caches per issuer tenant) the remote JWKS used to verify inbound tokens.
function getJwks(issuerTenantId) {
    if (!jwksByTenant.has(issuerTenantId)) {
        const { createRemoteJWKSet } = require('jose');
        jwksByTenant.set(
            issuerTenantId,
            createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${issuerTenantId}/discovery/v2.0/keys`)),
        );
    }
    return jwksByTenant.get(issuerTenantId);
}

// Validates the inbound bearer token when REQUIRE_AUTH is enabled (issuer, audience, expiry, RS256).
async function validateToken(request, context, requestId) {
    if (String(process.env.EPP_REQUIRE_AUTH || 'false').toLowerCase() !== 'true') {
        return { ok: true, skipped: true };
    }

    const audience = process.env.EPP_EXPECTED_AUDIENCE;
    const tenantId = process.env.EPP_TENANT_ID;
    if (!audience || !tenantId) {
        return { ok: false, reason: 'EPP_REQUIRE_AUTH is set but EPP_EXPECTED_AUDIENCE / EPP_TENANT_ID are missing' };
    }

    const authorizationHeader = (request.headers.get('authorization') || '').trim();
    const bearerToken = authorizationHeader.slice(0, 7).toLowerCase() === 'bearer '
        ? authorizationHeader.slice(7).trim()
        : '';
    if (!bearerToken) return { ok: false, reason: 'missing bearer token' };

    try {
        const { jwtVerify } = require('jose');
        // Accept both the v2 (login.microsoftonline.com/.../v2.0) and v1 (sts.windows.net/.../) issuers,
        // unless EPP_EXPECTED_ISSUER pins one explicitly.
        const issuers = process.env.EPP_EXPECTED_ISSUER
            ? [process.env.EPP_EXPECTED_ISSUER]
            : [
                `https://login.microsoftonline.com/${tenantId}/v2.0`,
                `https://sts.windows.net/${tenantId}/`,
            ];
        await jwtVerify(bearerToken, getJwks(tenantId), {
            audience,
            issuer: issuers,
            algorithms: ['RS256'],
        });
        return { ok: true };
    } catch (error) {
        context.log(`[AUTH_FAIL] requestId=${requestId} reason=${error.message}`);
        return { ok: false, reason: 'token validation failed' };
    }
}

module.exports = { validateToken };
