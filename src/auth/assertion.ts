import crypto from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { DEFAULT_AUDIENCE, DEFAULT_JWT_EXPIRY_SECONDS, DEFAULT_SCOPE } from '../config/defaults';
import { TruistError } from '../errors/TruistError';
import { TruistClientOptions } from '../types';

function assertRequired(value: string | undefined, name: string): void {
    if (!value || !value.trim()) {
        throw new TruistError(`Missing required Truist config: ${name}`);
    }
}

/**
 * Generates a signed RS256 JWT (client_assertion) per the Truist 2-legged OAuth flow.
 * Claims match exactly what the Truist token API expects (Section 3.2 of the playbook).
 */
export async function generateClientAssertion(options: TruistClientOptions): Promise<string> {
    assertRequired(options.clientId, 'clientId');
    assertRequired(options.clientSecret, 'clientSecret');
    assertRequired(options.companyId, 'companyId');
    assertRequired(options.userId, 'userId');
    assertRequired(options.privateKey, 'privateKey');
    assertRequired(options.issuer, 'issuer');

    // subject must identify the client application — default to clientId per spec
    const subject = options.subject || options.clientId;
    const audience = options.audience || DEFAULT_AUDIENCE;
    const scope = options.scope || DEFAULT_SCOPE;
    const expirySeconds = options.jwtExpirySeconds ?? DEFAULT_JWT_EXPIRY_SECONDS;

    if (expirySeconds < 60 || expirySeconds > 600) {
        throw new TruistError('jwtExpirySeconds must be between 60 and 600.');
    }

    const now = Math.floor(Date.now() / 1000);

    let privateKey;
    try {
        privateKey = await importPKCS8(options.privateKey, 'RS256');
    } catch {
        throw new TruistError('Failed to parse privateKey — ensure it is a valid PKCS#8 PEM.');
    }

    const protectedHeader: { alg: string; kid?: string } = { alg: 'RS256' };
    if (options.kid) {
        protectedHeader.kid = options.kid;
    }

    return new SignJWT({
        client_id: options.clientId,
        client_secret: options.clientSecret,
        companyid: options.companyId,
        userid: options.userId,
        scope
    })
        .setProtectedHeader(protectedHeader)
        .setIssuer(options.issuer)
        .setSubject(subject)
        .setAudience(audience)
        .setJti(crypto.randomUUID())
        .setIssuedAt(now)
        .setExpirationTime(now + expirySeconds)
        .sign(privateKey);
}