/**
 * Auth module tests
 * Tests JWT assertion generation, token cache behaviour, and PEM validation.
 */
import { generateClientAssertion } from '../src/auth/assertion';
import { TokenCache } from '../src/auth/token';
import { TruistClient } from '../src/client/TruistClient';
import { TruistError } from '../src/errors/TruistError';
import type { TruistClientOptions } from '../src/types';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Minimal valid PKCS#8 RSA key (2048-bit) generated for tests only — NOT a real credential.
const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYL9QSWu0+LWeL
lPzQlluYPaDiKkjHMuAC76qHLsnzGdoTJLRhNGTV2JyuSR7yWCuHZtI9H+7WQP4Y
v1i6aROAXOcRzfCuMsrC/n5V4mq6gpw0lTurS99xAECB0GeA26AVvtvkoIbCIZpY
Ea5UwT8NMw96ViurNOMJTNvAkuDee2OIFMbLE0aatmU/pMZauJm4gcgc1+tEz276
+vB9k/yAAT3WicoOua1SHRFjbbtY+uuhaEGrzvzCiDCIGuKs3ZM08bRZ08ycqOyU
0BE0qROsW2rwkeBcYs23l0cJ3W6Rly1QSfyWTVApmNmmgY+4Pyx4ECtPjzT9Crts
25Rz0WtDAgMBAAECggEARvpLkNH6gvy/JbDzZj8x8eOQVNr+vXTjWEs5/7lZM7mz
ZSlBvXInszrG/FwbBFEN4CUa2ao6hI+kUptvgOU/1Ka/mCSx4zTKLz5tYpXqTBld
TALr5NzKldPVwhWWKFmGJI4y1ULvBryQVRHN+jZ0ty3AwsBMtplAaBaCCSMXoHs4
ljT3WggZCao4eGfNfcOqaLJ6bMHy5WgH/CPxmwihkB1bN+hCo7LfML/0oehs2RyG
o+VXvvreMkq/Bw3F4k77oiwpZ9PZfEmsozLJN5SZfXg2VNnz6PUIHvfMPu743BV7
A4Cr9F/iiDR33aCVZL2GY3f2fGGHFnYkgY4hIbwXjQKBgQDG04pnyeGNLxHdCf0Q
C4GK68XRggeGKlvDyohDW12Woa0jFBQsOD/JvgoLj6bs4GStO+vKgH5BsiAuY3Ie
Q0DPCi2g2vjOYLOE5ad5feQuPmmKX3iZ5C4ZOYr0aLT1J8OMBf1eq5fg2VFt7EL3
MKgBsxj2gv4BGirz/+pFyKur3wKBgQDD8vQ3J33ObZihITREBpk6sUWlemTKO+Za
0BBVdaWUz5NqfvUnRnKPtsXJCP95BBXZnpG6xwF46MHh+YkjSf3wVW6lVmIS8yMK
EH6b+Va6o4ER4pf+ZTPUQ8FxxHz2omVWR6A/A590R4wts8iEujQ9Qh39OrAFOxhW
tyO/Ne9tHQKBgE6+CqtuHaDPinCS+yE2nVhKZe7CY350GiGhfXPHpHn6j9o7on2c
zU51r/7CJqbbe6PL/mcVmmskQ3B7u/9WPT2B125EKpN5Yr94QGpyPENAPoYpp1az
MrqUun5vVXNeCyjSWnT62kyXZJN3JVJGd9Msfe9rE3OWTHqT2NFIVwzbAoGAek+Q
+UyBTvVCLHHZegzUYLp+ysgXWdUB+PWe/HkvHjBjyDnvNNDYebSQyOgA770JFonQ
VVIbLSm8vB1S6OAqznXFVxcQqNtzp7icDygYZu/ghRV34qexLnIMscMAbcL4ll6n
PC46vg5bBbwPEipYqVQ3+/VCIkG884PloFk+VlECgYEAji3cTATe7ZzeZ5sbgpU5
5xwGb9PDhZ2/9KGGmkfC1QUyJCh5tTWvMATe9c7OEO3xZGYX59HWlGL/9z904gP0
iVZUZL5URSsFYpvD38+1Oi07nkqKZP7tXc+Fy3XIKqS/Q8d3ay8WaKP7oH9uHbKy
UVDvfn6qz5iOPJo9fKPV6Ng=
-----END PRIVATE KEY-----`;

const BASE_OPTIONS: TruistClientOptions = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    companyId: 'test-company-id',
    userId: 'test-user-id',
    privateKey: TEST_PRIVATE_KEY,
    issuer: 'test-issuer',
    scope: 'verify:accounts verify:accountsandowners',
    mtls: {
        cert: 'cert-pem',
        key: 'key-pem'
    }
};

// ---------------------------------------------------------------------------
// generateClientAssertion
// ---------------------------------------------------------------------------

describe('generateClientAssertion', () => {
    it('returns a three-part dot-separated JWT string', async () => {
        const jwt = await generateClientAssertion(BASE_OPTIONS);
        expect(typeof jwt).toBe('string');
        const parts = jwt.split('.');
        expect(parts).toHaveLength(3);
    });

    it('throws TruistError when privateKey is missing', async () => {
        await expect(
            generateClientAssertion({ ...BASE_OPTIONS, privateKey: '' })
        ).rejects.toThrow(TruistError);
    });

    it('throws TruistError when clientId is missing', async () => {
        await expect(
            generateClientAssertion({ ...BASE_OPTIONS, clientId: '  ' })
        ).rejects.toThrow(TruistError);
    });

    it('throws TruistError when jwtExpirySeconds is out of range', async () => {
        await expect(
            generateClientAssertion({ ...BASE_OPTIONS, jwtExpirySeconds: 30 })
        ).rejects.toThrow(TruistError);
    });

    it('defaults subject to clientId when subject is not set', async () => {
        const jwt = await generateClientAssertion(BASE_OPTIONS);
        // Decode the payload (second part) without verifying signature
        const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
        expect(payload.sub).toBe(BASE_OPTIONS.clientId);
    });

    it('includes required Truist claims in the payload', async () => {
        const jwt = await generateClientAssertion(BASE_OPTIONS);
        const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
        expect(payload.client_id).toBe(BASE_OPTIONS.clientId);
        expect(payload.client_secret).toBe(BASE_OPTIONS.clientSecret);
        expect(payload.companyId).toBe(BASE_OPTIONS.companyId);
        expect(payload.userid).toBe(BASE_OPTIONS.userId);
        expect(typeof payload.jti).toBe('string');
        expect(payload.aud).toBe('truist');
    });
});

// ---------------------------------------------------------------------------
// TokenCache
// ---------------------------------------------------------------------------

describe('TokenCache', () => {
    const makeTokenResponse = (scope = 'verify:accounts verify:accountsandowners', expiresIn = 899) => ({
        access_token: 'test-token-' + Date.now(),
        token_type: 'Bearer' as const,
        expires_in: expiresIn,
        scope
    });

    it('returns cached token on subsequent calls without re-fetching', async () => {
        const cache = new TokenCache();
        let fetchCount = 0;
        const fetcher = jest.fn(async () => { fetchCount++; return makeTokenResponse(); });

        const t1 = await cache.getOrRefresh(fetcher);
        const t2 = await cache.getOrRefresh(fetcher);
        expect(t1).toBe(t2);
        expect(fetchCount).toBe(1);
    });

    it('re-fetches after invalidate()', async () => {
        const cache = new TokenCache();
        const fetcher = jest.fn(async () => makeTokenResponse());

        await cache.getOrRefresh(fetcher);
        cache.invalidate();
        await cache.getOrRefresh(fetcher);
        expect(fetcher).toHaveBeenCalledTimes(2);
    });

    it('throws TruistError when fetcher returns empty access_token', async () => {
        const cache = new TokenCache();
        const fetcher = jest.fn(async () => ({ ...makeTokenResponse(), access_token: '' }));
        await expect(cache.getOrRefresh(fetcher)).rejects.toThrow(TruistError);
    });

    it('throws TruistError when fetcher returns zero expires_in', async () => {
        const cache = new TokenCache();
        const fetcher = jest.fn(async () => ({ ...makeTokenResponse(), expires_in: 0 }));
        await expect(cache.getOrRefresh(fetcher)).rejects.toThrow(TruistError);
    });

    it('deduplicates concurrent refresh calls', async () => {
        const cache = new TokenCache();
        const fetcher = jest.fn(async () => {
            await new Promise((r) => setTimeout(r, 10));
            return makeTokenResponse();
        });

        const [t1, t2, t3] = await Promise.all([
            cache.getOrRefresh(fetcher),
            cache.getOrRefresh(fetcher),
            cache.getOrRefresh(fetcher)
        ]);
        expect(fetcher).toHaveBeenCalledTimes(1);
        expect(t1).toBe(t2);
        expect(t2).toBe(t3);
    });
});

// ---------------------------------------------------------------------------
// TruistClient PEM validation
// ---------------------------------------------------------------------------

// Minimal self-signed cert PEM (real structure, not a CA-trusted cert) for unit tests
const DUMMY_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
-----END CERTIFICATE-----`;

function makeClientOptions(overrides: Partial<TruistClientOptions> = {}): TruistClientOptions {
    return {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        companyId: 'test-company',
        userId: 'test-user',
        privateKey: TEST_PRIVATE_KEY,
        issuer: 'test-issuer',
        mtls: { cert: DUMMY_CERT_PEM, key: TEST_PRIVATE_KEY },
        ...overrides
    };
}

describe('TruistClient PEM validation', () => {
    it('constructs successfully with valid PEM strings', () => {
        expect(() => new TruistClient(makeClientOptions())).not.toThrow();
    });

    it('accepts PEM passed as a Buffer', () => {
        expect(() => new TruistClient(makeClientOptions({
            mtls: {
                cert: Buffer.from(DUMMY_CERT_PEM),
                key: Buffer.from(TEST_PRIVATE_KEY)
            }
        }))).not.toThrow();
    });

    it('normalises collapsed newlines (env-var \\\\n sequences) in mtls.cert', () => {
        // Simulate a PEM that was stored as a single-line env var with literal \n
        const collapsed = DUMMY_CERT_PEM.replace(/\n/g, '\\n');
        expect(() => new TruistClient(makeClientOptions({
            mtls: { cert: collapsed, key: TEST_PRIVATE_KEY }
        }))).not.toThrow();
    });

    it('normalises Windows CRLF line endings in mtls.cert', () => {
        const crlf = DUMMY_CERT_PEM.replace(/\n/g, '\r\n');
        expect(() => new TruistClient(makeClientOptions({
            mtls: { cert: crlf, key: TEST_PRIVATE_KEY }
        }))).not.toThrow();
    });

    it('throws TruistError with clear message when mtls.cert has no PEM headers', () => {
        expect(() => new TruistClient(makeClientOptions({
            mtls: { cert: 'not-a-pem-string', key: TEST_PRIVATE_KEY }
        }))).toThrow(/Invalid PEM format for mtls\.cert/);
    });

    it('throws TruistError when mtls.key has no PEM headers', () => {
        expect(() => new TruistClient(makeClientOptions({
            mtls: { cert: DUMMY_CERT_PEM, key: 'bad-base64===!!@@' }
        }))).toThrow(/Invalid PEM format for mtls\.key/);
    });

    it('throws TruistError when privateKey has invalid base64 in body', () => {
        const badKey = `-----BEGIN PRIVATE KEY-----\nNOT!VALID!BASE64!!!!\n-----END PRIVATE KEY-----`;
        expect(() => new TruistClient(makeClientOptions({
            privateKey: badKey,
            mtls: { cert: DUMMY_CERT_PEM, key: TEST_PRIVATE_KEY }
        }))).toThrow(/invalid base64 characters/);
    });

    it('throws TruistError when mtls.cert is an empty string', () => {
        expect(() => new TruistClient(makeClientOptions({
            mtls: { cert: '', key: TEST_PRIVATE_KEY }
        }))).toThrow(TruistError);
    });

    it('throws TruistError when required clientId is missing', () => {
        expect(() => new TruistClient(makeClientOptions({ clientId: '' }))).toThrow(TruistError);
    });
});
