import { Buffer } from 'node:buffer';

export type TruistEnvironment = 'cert' | 'prod';

export interface MtlsOptions {
    cert: string | Buffer;
    key: string | Buffer;
    ca?: string | Buffer;
    passphrase?: string;
}

export interface TruistEndpointSet {
    tokenUrl: string;
    jwksUrl: string;
    verifyBaseUrl: string;
}

export interface TruistClientOptions {
    /** Unique application ID provided during Truist onboarding. */
    clientId: string;
    /** Client secret provided during Truist onboarding. */
    clientSecret: string;
    /** Company/organization identifier associated with the application. */
    companyId: string;
    /** User identifier within the client application. */
    userId: string;
    /** PKCS#8 PEM-encoded RSA private key used to sign the JWT assertion (RS256). */
    privateKey: string;
    /** JWT `iss` claim — typically the client application identifier. */
    issuer: string;
    /** Mutual TLS certificate material. Required for production; optional for cert environment. */
    mtls?: MtlsOptions;
    /** Target environment. Defaults to 'cert' (certification). */
    environment?: TruistEnvironment;
    /** JWT `aud` claim. Defaults to 'truist' per the playbook. */
    audience?: string;
    /** JWT `sub` claim. Defaults to clientId when not set. */
    subject?: string;
    /** OAuth scopes to request. Defaults to 'verify:accounts verify:accountsandowners'. */
    scope?: string;
    /** Optional key ID (`kid`) to include in the JWT protected header. */
    kid?: string;
    /** HTTP request timeout in milliseconds. Defaults to 15000. */
    timeoutMs?: number;
    /** Number of retry attempts for transient errors. Defaults to 2. */
    retries?: number;
    /** Base retry delay in milliseconds (exponential back-off is applied). Defaults to 500. */
    retryDelayMs?: number;
    /** JWKS cache TTL in milliseconds. Defaults to 15 minutes. */
    jwksCacheTtlMs?: number;
    /** JWT assertion lifetime in seconds (60–600). Defaults to 300. */
    jwtExpirySeconds?: number;
    /** Override individual endpoint URLs (useful for testing/proxies). */
    urls?: Partial<TruistEndpointSet>;
}

// ---------------------------------------------------------------------------
// Account Verification
// ---------------------------------------------------------------------------

export interface VerifyAccountItem {
    /** Caller-assigned correlation ID returned verbatim in the response. */
    id: number;
    /** Bank account number (up to 17 digits). */
    accountNumber: string;
    /** 9-digit ABA routing transit number. */
    routingNumber: string;
}

export interface VerifyAccountsRequest {
    /** Maximum 5 accounts per request (Truist API limit). */
    verifyAccounts: VerifyAccountItem[];
}

// ---------------------------------------------------------------------------
// Account Owner Verification
// ---------------------------------------------------------------------------

export interface VerifyAddress {
    addressLine: string;
    city: string;
    state: string;
    /** 5-digit or 9-digit (ZIP+4) postal code. */
    zipCode: string;
}

/** Supported document ID types for owner verification. */
export type DocumentIdType =
    | 'DRIVERS_LICENSE'
    | 'STATE_ID'
    | 'PASSPORT'
    | 'RESIDENT_ALIEN_ID'
    | 'OTHER';

export interface VerifyOwnerProfile {
    firstName: string;
    lastName: string;
    middleName?: string;
    businessName?: string;
    /** Social Security Number or Tax Identification Number. */
    ssnTIN: string;
    homePhoneNumber: string;
    workPhoneNumber: string;
    /** ISO-8601 date of birth (YYYY-MM-DD). Optional. */
    dateOfBirth?: string;
    /**
     * Document fields must all be supplied together or all omitted.
     * Per Truist API Playbook §5.2.
     */
    documentId?: string;
    documentIdState?: string;
    documentIdType?: DocumentIdType | string;
    /** Address fields must all be supplied together or all omitted. */
    address?: VerifyAddress;
}

export interface VerifyAccountOwnerItem {
    id: number;
    accountNumber: string;
    routingNumber: string;
    profile: VerifyOwnerProfile;
}

export interface VerifyAccountOwnersRequest {
    /** Maximum 5 accounts per request (Truist API limit). */
    verifyAccountOwners: VerifyAccountOwnerItem[];
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/** Possible Truist account verification statuses. */
export type AccountVerificationStatus =
    | 'OPENED_AND_VALID'
    | 'CLOSED'
    | 'DATA_UNAVAILABLE'
    | 'INVALID_DATA';

/** Possible Truist owner verification statuses. */
export type OwnerVerificationStatus =
    | 'COMPLETE_MATCH'
    | 'PARTIAL_MATCH'
    | 'NOT_MATCH'
    | 'DATA_UNAVAILABLE';

export interface TruistStatus {
    status: AccountVerificationStatus | OwnerVerificationStatus | string;
    description: string;
    /** Truist error/status code (e.g. '0000' for success, '8004'–'8022' for errors). */
    code: string;
}

export interface VerifiedAccountResult {
    id: number;
    accountVerificationStatus: TruistStatus;
}

export interface VerifiedAccountOwnerResult {
    id: number;
    accountVerificationStatus: TruistStatus;
    ownerVerificationStatus: TruistStatus;
}

export interface VerifyAccountsResponse {
    verifiedAccounts: VerifiedAccountResult[];
}

export interface VerifyAccountOwnersResponse {
    verifiedAccountOwners: VerifiedAccountOwnerResult[];
}

export interface TokenResponse {
    access_token: string;
    token_type: 'Bearer';
    /** Token lifetime in seconds. 899 (~15 min) for verify; 480 (8 min) for payment. */
    expires_in: number;
    /** Granted scopes — present in all Truist token responses per the playbook. */
    scope: string;
}