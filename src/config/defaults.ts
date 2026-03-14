import { TruistEndpointSet, TruistEnvironment } from '../types';

export const DEFAULT_AUDIENCE = 'truist';
/** @deprecated Set options.subject to your actual client_id or service identifier. */
export const DEFAULT_SUBJECT = '';
export const DEFAULT_SCOPE = 'verify:accounts verify:accountsandowners';
export const DEFAULT_TIMEOUT_MS = 15000;
export const DEFAULT_RETRIES = 2;
export const DEFAULT_RETRY_DELAY_MS = 500;
export const DEFAULT_JWKS_CACHE_TTL_MS = 15 * 60 * 1000;
/** JWT assertion lifetime in seconds (5 minutes is well within any token expiry window). */
export const DEFAULT_JWT_EXPIRY_SECONDS = 300;
/**
 * RFC 7521 client_assertion_type value required by Truist token endpoint.
 * Must be sent alongside client_assertion on every token request.
 */
export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
/**
 * Truist Verify API tokens (information-reporting / verify scope) are valid for 15 minutes.
 * Payment-credential tokens are valid for 8 minutes.
 * These constants are used by the token cache to set correct expiry.
 */
export const TOKEN_EXPIRY_VERIFY_SECONDS = 15 * 60;   // 900 s
export const TOKEN_EXPIRY_PAYMENT_SECONDS = 8 * 60;   // 480 s

export const ENDPOINTS: Record<TruistEnvironment, TruistEndpointSet> = {
    cert: {
        tokenUrl: 'https://apicert.truist.com/commercial/v3/oauth/token',
        jwksUrl: 'https://apicert.truist.com/commercial/v1/.well-known/jwks.json',
        verifyBaseUrl: 'https://apicert.truist.com/commercial/v1'
    },
    prod: {
        tokenUrl: 'https://api.truist.com/commercial/v3/oauth/token',
        jwksUrl: 'https://api.truist.com/commercial/v1/.well-known/jwks.json',
        verifyBaseUrl: 'https://api.truist.com/commercial/v1'
    }
};