/**
 * Crypto module tests
 * Validates JWE encryption and JWKS key selection logic.
 */
import { encryptPayloadAsJwe } from '../src/crypto/jwe';
import { fetchEncryptionJwk } from '../src/crypto/jwks';
import { TruistError } from '../src/errors/TruistError';
import type { JWK } from 'jose';
import axios from 'axios';

// ---------------------------------------------------------------------------
// JWE Encryption
// ---------------------------------------------------------------------------

describe('encryptPayloadAsJwe', () => {
    // Real 2048-bit RSA public key (generated for tests only — NOT a real credential)
    const TEST_PUBLIC_JWK: JWK = {
        kty: 'RSA',
        use: 'enc',
        alg: 'RSA-OAEP-256',
        n: '2i_B6AxQtk4B-j3hVxKgWx1p3_hg3R020loyPZIEPYKa9srPCj_8gTecYYdKCmJU3DHzlBCZ_g8CnPklTm9rGwHZ3b0luBNRYDGK9P34GsNB2sxOxL49luSZYJyVuJ_Dzih1c-7mH54IKPbdoXqU_W4xvXabinAgnuddfEaxyELcV32YfXVona0L2xLlnivcV_uT9ZBFdrwFNHyJKo31cnsXDv0AuOXBUJ5P2HEt8KV3JJbBtgk8EoyK_iPDh7DrZdkI_zB15PbGwOR_0SpOWbtNACmRghA7NQqOheV1dFgz0iGoZ3AsH_xzjq2ECMmRgmVdgF5VddNk0exhfbkG8Q',
        e: 'AQAB'
    };

    it('returns a compact JWE string with 5 dot-separated parts', async () => {
        const jwe = await encryptPayloadAsJwe({ verifyAccounts: [] }, TEST_PUBLIC_JWK);
        expect(typeof jwe).toBe('string');
        expect(jwe.split('.')).toHaveLength(5);
    });

    it('produces a JWE whose header specifies RSA-OAEP-256 / A256GCM', async () => {
        const jwe = await encryptPayloadAsJwe({ test: true }, TEST_PUBLIC_JWK);
        const headerB64 = jwe.split('.')[0];
        const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
        expect(header.alg).toBe('RSA-OAEP-256');
        expect(header.enc).toBe('A256GCM');
    });

    it('includes kid in the JWE header when the JWK has a kid', async () => {
        const jwkWithKid = { ...TEST_PUBLIC_JWK, kid: 'test-key-id' };
        const jwe = await encryptPayloadAsJwe({ test: true }, jwkWithKid);
        const header = JSON.parse(Buffer.from(jwe.split('.')[0], 'base64url').toString());
        expect(header.kid).toBe('test-key-id');
    });

    it('produces a different ciphertext on every call (non-deterministic GCM)', async () => {
        const jwe1 = await encryptPayloadAsJwe({ same: 'payload' }, TEST_PUBLIC_JWK);
        const jwe2 = await encryptPayloadAsJwe({ same: 'payload' }, TEST_PUBLIC_JWK);
        expect(jwe1).not.toBe(jwe2);
    });
});

// ---------------------------------------------------------------------------
// fetchEncryptionJwk / JwksCache
// ---------------------------------------------------------------------------

describe('fetchEncryptionJwk', () => {
    it('selects the RSA enc key matching RSA-OAEP-256', async () => {
        const encKey: JWK = { kty: 'RSA', use: 'enc', alg: 'RSA-OAEP-256', n: 'abc', e: 'AQAB', kid: 'enc-1' };
        const sigKey: JWK = { kty: 'RSA', use: 'sig', alg: 'RS256', n: 'def', e: 'AQAB', kid: 'sig-1' };
        const mockHttp = { get: jest.fn().mockResolvedValue({ data: { keys: [sigKey, encKey] } }) } as any;

        const key = await fetchEncryptionJwk(mockHttp, 'https://example.com/jwks', 0, 0);
        expect(key.kid).toBe('enc-1');
    });

    it('falls back to first RSA key when no enc-specific key is present', async () => {
        const rsaKey: JWK = { kty: 'RSA', n: 'abc', e: 'AQAB', kid: 'only-rsa' };
        const mockHttp = { get: jest.fn().mockResolvedValue({ data: { keys: [rsaKey] } }) } as any;

        const key = await fetchEncryptionJwk(mockHttp, 'https://example.com/jwks', 0, 0);
        expect(key.kid).toBe('only-rsa');
    });

    it('throws TruistError when JWKS contains no RSA keys', async () => {
        const ecKey: JWK = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' };
        const mockHttp = { get: jest.fn().mockResolvedValue({ data: { keys: [ecKey] } }) } as any;

        await expect(fetchEncryptionJwk(mockHttp, 'https://example.com/jwks', 0, 0))
            .rejects.toThrow(TruistError);
    });

    it('throws TruistError when JWKS keys array is empty', async () => {
        const mockHttp = { get: jest.fn().mockResolvedValue({ data: { keys: [] } }) } as any;

        await expect(fetchEncryptionJwk(mockHttp, 'https://example.com/jwks', 0, 0))
            .rejects.toThrow(TruistError);
    });
});
