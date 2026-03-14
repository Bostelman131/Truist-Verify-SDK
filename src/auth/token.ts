import { TruistError } from '../errors/TruistError';
import { TOKEN_EXPIRY_PAYMENT_SECONDS, TOKEN_EXPIRY_VERIFY_SECONDS } from '../config/defaults';
import { TokenResponse } from '../types';

/**
 * Detects whether the granted scope is payment-related.
 * Payment tokens expire after 8 minutes; verify tokens expire after 15 minutes.
 * Per Truist API Playbook §3.2 Step 4.
 */
function isPaymentScope(scope: string): boolean {
    return /payment/i.test(scope);
}

/**
 * Resolves the effective token lifetime in milliseconds.
 * Truist returns expires_in in the response; however, we also enforce the
 * scope-based caps documented in the playbook so the cache never holds a
 * stale token if the server returns an unexpectedly large value.
 */
function resolveExpiryMs(token: TokenResponse): number {
    const serverExpiry = token.expires_in * 1000;
    const scope = token.scope || '';
    const capMs = isPaymentScope(scope)
        ? TOKEN_EXPIRY_PAYMENT_SECONDS * 1000
        : TOKEN_EXPIRY_VERIFY_SECONDS * 1000;
    // Use the lesser of the server-reported expiry and the documented cap
    return Math.min(serverExpiry, capMs);
}

export class TokenCache {
    private token?: string;
    private expiresAtMs = 0;
    private inflight?: Promise<string>;
    /**
     * Clock-skew buffer — tokens are considered expired this many milliseconds
     * before their stated expiry to avoid races with the Truist clock.
     */
    private readonly skewMs: number;

    constructor(skewMs = 60_000) {
        this.skewMs = skewMs;
    }

    /** Clears the cached token immediately (e.g. after a 401 response). */
    invalidate(): void {
        this.token = undefined;
        this.expiresAtMs = 0;
    }

    private getValidToken(): string | undefined {
        if (!this.token) {
            return undefined;
        }
        if (Date.now() + this.skewMs >= this.expiresAtMs) {
            return undefined;
        }
        return this.token;
    }

    async getOrRefresh(fetchToken: () => Promise<TokenResponse>): Promise<string> {
        const cached = this.getValidToken();
        if (cached) {
            return cached;
        }

        if (!this.inflight) {
            this.inflight = (async () => {
                const tokenResponse = await fetchToken();

                if (!tokenResponse.access_token) {
                    throw new TruistError('Truist token response missing access_token.', 500, 'INVALID_TOKEN_RESPONSE');
                }
                if (!tokenResponse.expires_in || tokenResponse.expires_in <= 0) {
                    throw new TruistError('Truist token response has invalid expires_in.', 500, 'INVALID_TOKEN_RESPONSE');
                }

                this.token = tokenResponse.access_token;
                this.expiresAtMs = Date.now() + resolveExpiryMs(tokenResponse);
                return this.token;
            })().finally(() => {
                this.inflight = undefined;
            });
        }

        return this.inflight;
    }
}