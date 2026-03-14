import { Buffer } from 'node:buffer';
import type { AxiosInstance } from 'axios';
import {
    CLIENT_ASSERTION_TYPE,
    DEFAULT_JWKS_CACHE_TTL_MS,
    DEFAULT_RETRIES,
    DEFAULT_RETRY_DELAY_MS,
    DEFAULT_TIMEOUT_MS,
    ENDPOINTS
} from '../config/defaults';
import { generateClientAssertion } from '../auth/assertion';
import { TokenCache } from '../auth/token';
import { fetchEncryptionJwk, JwksCache } from '../crypto/jwks';
import { encryptPayloadAsJwe } from '../crypto/jwe';
import { createHttpClient, withRetry } from '../http/httpClient';
import { TruistError, toTruistError } from '../errors/TruistError';
import { parseOrThrow, VerifyAccountOwnersRequestSchema, VerifyAccountsRequestSchema } from '../services/schemas';
import {
    TokenResponse,
    TruistClientOptions,
    TruistEndpointSet,
    VerifyAccountOwnersRequest,
    VerifyAccountOwnersResponse,
    VerifyAccountsRequest,
    VerifyAccountsResponse
} from '../types';

function assertNonEmpty(value: unknown, name: string): void {
    if (typeof value === 'string' && value.trim()) {
        return;
    }

    if (Buffer.isBuffer(value) && value.length > 0) {
        return;
    }

    throw new TruistError(`Missing required Truist config: ${name}`);
}

/**
 * Normalises a PEM string that may have had its newlines collapsed (a common
 * issue when PEMs are stored in environment variables or JSON configs).
 *
 * Handles these real-world encoding problems:
 *   - Literal '\n' escape sequences instead of actual newlines
 *   - Windows CRLF line endings
 *   - Base64 body run together with no line breaks at all
 */
function normalizePem(value: string | Buffer): string {
    if (Buffer.isBuffer(value)) {
        return value.toString('utf8');
    }

    // Replace literal \n escape sequences with real newlines
    let pem = value.replace(/\\n/g, '\n');

    // Normalise CRLF → LF
    pem = pem.replace(/\r\n/g, '\n');

    // If the base64 body has no line breaks at all, reformat it so OpenSSL
    // can parse it. PEM requires 64-char wrapped lines.
    pem = pem.replace(
        /(-{5}BEGIN [^-]+-{5})([A-Za-z0-9+/=]+)(-{5}END [^-]+-{5})/g,
        (_, header, body, footer) => {
            const wrapped = (body as string).match(/.{1,64}/g)!.join('\n');
            return `${header}\n${wrapped}\n${footer}`;
        }
    );

    return pem.trim();
}

/** Validates that a PEM string has the expected header/footer structure. */
function assertValidPem(value: string | Buffer, name: string): string {
    const pem = normalizePem(value);
    const hasBoundary = /^-{5}BEGIN [A-Z0-9 ]+-{5}[\s\S]+-{5}END [A-Z0-9 ]+-{5}\s*$/.test(pem);

    if (!hasBoundary) {
        throw new TruistError(
            `Invalid PEM format for ${name}. ` +
            'Ensure the value includes the -----BEGIN/END----- headers and that ' +
            'newlines have not been stripped (use \\n or actual line breaks).'
        );
    }

    // Verify the base64 body decodes without error
    const bodyMatch = pem.match(/-{5}BEGIN [^-]+-{5}([\s\S]+?)-{5}END/);
    if (bodyMatch) {
        const body = bodyMatch[1].replace(/\s+/g, '');
        if (!/^[A-Za-z0-9+/]+=*$/.test(body)) {
            throw new TruistError(
                `${name} PEM contains invalid base64 characters. ` +
                'Check that the certificate/key was not corrupted during storage or transport.'
            );
        }
    }

    return pem;
}

function resolveEndpoints(options: TruistClientOptions): TruistEndpointSet {
    const environment = options.environment || 'cert';
    return {
        ...ENDPOINTS[environment],
        ...(options.urls || {})
    };
}

export class TruistClient {
    private readonly options: TruistClientOptions;
    private readonly endpoints: TruistEndpointSet;
    private readonly http;
    private readonly tokenCache: TokenCache;
    private readonly jwksCache: JwksCache;

    constructor(options: TruistClientOptions) {
        assertNonEmpty(options.clientId, 'clientId');
        assertNonEmpty(options.clientSecret, 'clientSecret');
        assertNonEmpty(options.companyId, 'companyId');
        assertNonEmpty(options.userId, 'userId');
        assertNonEmpty(options.privateKey, 'privateKey');
        assertNonEmpty(options.issuer, 'issuer');

        // Validate and normalise all PEM values eagerly so bad encoding is caught
        // at construction time with a clear message, not at the first HTTP request
        // as a cryptic OpenSSL base64 decode error.
        let normalizedCert: string | undefined;
        let normalizedKey: string | undefined;
        let normalizedCa: string | undefined;

        if (options.mtls) {
            if (options.mtls.cert) normalizedCert = assertValidPem(options.mtls.cert, 'mtls.cert');
            if (options.mtls.key)  normalizedKey  = assertValidPem(options.mtls.key,  'mtls.key');
            if (options.mtls.ca)   normalizedCa   = assertValidPem(options.mtls.ca,   'mtls.ca');
        }

        const normalizedPrivateKey = assertValidPem(options.privateKey, 'privateKey');

        this.options = {
            ...options,
            privateKey: normalizedPrivateKey,
            environment: options.environment || 'cert',
            timeoutMs: options.timeoutMs || DEFAULT_TIMEOUT_MS,
            retries: options.retries ?? DEFAULT_RETRIES,
            retryDelayMs: options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS,
            jwksCacheTtlMs: options.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS
        };
        this.endpoints = resolveEndpoints(this.options);
        this.http = createHttpClient({
            timeoutMs: this.options.timeoutMs!,
            mtls: normalizedCert && normalizedKey ? {
                ...options.mtls,
                cert: normalizedCert,
                key:  normalizedKey,
                ca:   normalizedCa
            } : undefined
        });
        this.tokenCache = new TokenCache();
        this.jwksCache = new JwksCache(this.options.jwksCacheTtlMs!);
    }

    private async fetchAccessToken(): Promise<TokenResponse> {
        const clientAssertion = await generateClientAssertion(this.options);
        /**
         * The Truist token endpoint requires:
         *   grant_type=client_credentials
         *   client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer  (RFC 7521)
         *   client_assertion=<signed JWT>
         * Reference: Truist API Playbook §3.2 Step 3
         */
        const body = new URLSearchParams({
            grant_type: 'client_credentials',
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: clientAssertion
        });

        const response = await withRetry(
            () => this.http.post<TokenResponse>(this.endpoints.tokenUrl, body.toString(), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }),
            this.options.retries!,
            this.options.retryDelayMs!
        );

        if (!response.data?.access_token) {
            throw new TruistError('Truist token response did not include access_token.');
        }

        return response.data;
    }

    private async getAccessToken(): Promise<string> {
        return this.tokenCache.getOrRefresh(() => this.fetchAccessToken());
    }

    private async getEncryptionJwk() {
        return this.jwksCache.getOrRefresh(() => fetchEncryptionJwk(this.http, this.endpoints.jwksUrl, this.options.retries!, this.options.retryDelayMs!));
    }

    private async postEncrypted<T>(path: string, payload: unknown): Promise<T> {
        try {
            const token = await this.getAccessToken();
            const jwk = await this.getEncryptionJwk();
            const jwe = await encryptPayloadAsJwe(payload, jwk);
            const body = new URLSearchParams({ jwe });

            const response = await withRetry(
                () => this.http.post<T>(`${this.endpoints.verifyBaseUrl}${path}`, body.toString(), {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }),
                this.options.retries!,
                this.options.retryDelayMs!
            );

            return response.data;
        } catch (error) {
            const truistError = toTruistError(error);
            // Invalidate the cached token on auth failures so the next call
            // will obtain a fresh token rather than reusing a revoked one.
            if (truistError.status === 401 || truistError.status === 403) {
                this.tokenCache.invalidate();
            }
            throw truistError;
        }
    }

    async verifyAccounts(payload: VerifyAccountsRequest): Promise<VerifyAccountsResponse> {
        const validated = parseOrThrow(VerifyAccountsRequestSchema, payload, 'Invalid verifyAccounts payload.');
        return this.postEncrypted<VerifyAccountsResponse>('/account-verifications', validated);
    }

    async verifyAccount(payload: VerifyAccountsRequest): Promise<VerifyAccountsResponse> {
        return this.verifyAccounts(payload);
    }

    async verifyAccountOwners(payload: VerifyAccountOwnersRequest): Promise<VerifyAccountOwnersResponse> {
        const validated = parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'Invalid verifyAccountOwners payload.');
        return this.postEncrypted<VerifyAccountOwnersResponse>('/account-verifications/owners', validated);
    }

    getActiveEndpoints(): TruistEndpointSet {
        return { ...this.endpoints };
    }
}