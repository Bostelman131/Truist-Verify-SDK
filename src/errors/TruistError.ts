import axios, { type AxiosError } from 'axios';

/**
 * Truist API error code registry.
 * Source: Truist Embedded Finance API Playbook §6.1
 */
export const TRUIST_ERROR_CODES: Readonly<Record<string, string>> = {
    // Account Verification errors — HTTP 206
    '8004': 'Invalid Account Number',
    '8005': 'Invalid Routing Number',
    // Account Owner Verification errors — HTTP 206
    '8006': 'Invalid First Name',
    '8007': 'Invalid Last Name',
    '8008': 'Invalid Middle Name',
    '8009': 'Invalid Business Name',
    '8010': 'Invalid SSNTIN Number',
    '8011': 'Invalid Phone Number',
    '8012': 'Invalid Date of Birth',
    '8013': 'Invalid Address Line',
    '8014': 'Invalid City',
    '8015': 'Invalid State Code',
    '8016': 'Invalid Zip Code',
    '8017': 'Invalid Document ID Type',
    '8018': 'Invalid Document ID',
    '8019': 'Invalid Document ID Place',
    '8020': 'Invalid Type',
    '8021': 'Invalid Data Format',
    '8022': 'Invalid Response',
    // Registration errors
    '8025': 'Company not registered',
    // OAuth / authorization errors
    'invalid_scope': 'The requested scope is invalid or unknown',
    'Invalid JWT': 'The JWT bearer is invalid',
    'access_denied': 'The resource owner or authorization server denied the request',
};

export class TruistError extends Error {
    public readonly status?: number;
    public readonly code?: string;
    public readonly details?: unknown;

    constructor(message: string, status?: number, code?: string, details?: unknown) {
        super(message);
        this.name = 'TruistError';
        this.status = status;
        this.code = code;
        this.details = details;
    }

    /** Returns true when this error carries a recognized Truist API error code. */
    isApiError(): boolean {
        return !!this.code && this.code in TRUIST_ERROR_CODES;
    }

    /**
     * Returns true for HTTP 206 partial-content responses that contain
     * per-account validation errors (codes 8004–8022).
     */
    isPartialContent(): boolean {
        return this.status === 206;
    }
}

export function toTruistError(error: unknown): TruistError {
    if (error instanceof TruistError) {
        return error;
    }

    if (axios.isAxiosError(error)) {
        const axiosErr = error as AxiosError;
        const status = axiosErr.response?.status;
        const data = axiosErr.response?.data as Record<string, unknown> | undefined;
        const fallbackMsg = axiosErr.message;

        // 401 — surface auth error detail when present
        if (status === 401) {
            const msg = (data as any)?.error_description
                || (data as any)?.message
                || 'Truist authentication failed (401). Check clientId, clientSecret, and assertion.';
            const code = (data as any)?.error || (data as any)?.code;
            return new TruistError(msg, status, code, data);
        }

        // 400 — bad request with OAuth error payload
        if (status === 400) {
            const oauthError = (data as any)?.error;
            const msg = oauthError
                ? `${oauthError}: ${(data as any)?.error_description || TRUIST_ERROR_CODES[oauthError] || 'Bad request'}`
                : ((data as any)?.message || fallbackMsg);
            return new TruistError(msg, status, oauthError || (data as any)?.code, data);
        }

        // 206 — partial content: one or more accounts had validation errors
        if (status === 206) {
            const msg = 'One or more accounts returned validation errors (HTTP 206).';
            return new TruistError(msg, status, 'PARTIAL_CONTENT', data);
        }

        // Array-body error format
        if (Array.isArray(data) && data.length > 0) {
            const first = data[0] as any;
            return new TruistError(first.description || first.message || fallbackMsg, status, String(first.code ?? ''), data);
        }

        // Object-body error format
        if (data && typeof data === 'object') {
            const anyData = data as any;
            const code = String(anyData.code || anyData.error || '');
            const msg = anyData.message || anyData.error_description || fallbackMsg;
            return new TruistError(msg, status, code || undefined, data);
        }

        return new TruistError(fallbackMsg, status, undefined, data);
    }

    if (error instanceof Error) {
        return new TruistError(error.message);
    }

    return new TruistError('Unknown Truist SDK error.');
}