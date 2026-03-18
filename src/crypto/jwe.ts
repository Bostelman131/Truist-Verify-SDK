import { CompactEncrypt, JWK, importJWK, type CompactJWEHeaderParameters } from 'jose';

export async function encryptPayloadAsJwe(payload: unknown, jwk: JWK): Promise<string> {
    const key = await importJWK(jwk, 'RSA-OAEP-256');
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const protectedHeader: CompactJWEHeaderParameters = {
        alg: 'RSA-OAEP-256',
        enc: 'A128CBC-HS256',
        ...(jwk.kid ? { kid: jwk.kid } : {})
    };

    return new CompactEncrypt(plaintext)
        .setProtectedHeader(protectedHeader)
        .encrypt(key);
}