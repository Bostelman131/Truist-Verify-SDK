import { AxiosInstance } from 'axios';
import { JWK } from 'jose';
import { TruistError } from '../errors/TruistError';
import { withRetry } from '../http/httpClient';

interface JwksResponse {
    keys: JWK[];
}

export class JwksCache {
    private cachedKey?: JWK;
    private expiresAtMs = 0;
    private inflight?: Promise<JWK>;

    constructor(private readonly ttlMs: number) {}

    async getOrRefresh(fetcher: () => Promise<JWK>): Promise<JWK> {
        if (this.cachedKey && Date.now() < this.expiresAtMs) {
            return this.cachedKey;
        }

        if (!this.inflight) {
            this.inflight = (async () => {
                const key = await fetcher();
                this.cachedKey = key;
                this.expiresAtMs = Date.now() + this.ttlMs;
                return key;
            })().finally(() => {
                this.inflight = undefined;
            });
        }

        return this.inflight;
    }
}

export async function fetchEncryptionJwk(http: AxiosInstance, jwksUrl: string, retries: number, retryDelayMs: number): Promise<JWK> {
    const response = await withRetry(() => http.get<JwksResponse>(jwksUrl), retries, retryDelayMs);
    const keys = response.data?.keys || [];
    const rsaKeys = keys.filter((key) => key.kty === 'RSA');

    if (!rsaKeys.length) {
        throw new TruistError('No Truist RSA JWKS encryption keys available.');
    }

    return rsaKeys.find((key) => key.use === 'enc' && (!key.alg || key.alg === 'RSA-OAEP-256'))
        || rsaKeys.find((key) => key.alg === 'RSA-OAEP-256')
        || rsaKeys[0];
}