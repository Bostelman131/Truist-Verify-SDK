# Truist Verify SDK

## Overview

Node.js / TypeScript SDK for the Truist Verify APIs. Handles the full request lifecycle — OAuth 2.0 client-credentials token exchange via RS256 JWT assertion, JWKS-based JWE payload encryption (`RSA-OAEP-256` / `A128CBC-HS256`), mutual TLS, access-token caching, JWKS caching, automatic retries with exponential back-off, and Zod-based request validation — so consuming applications only need to supply credentials and a payload.

---

## Features

- **CERT & PROD environments** — switch with a single `environment` option
- **Mutual TLS (mTLS)** — pass PEM cert/key/CA directly or via `Buffer`; PEM normalisation handles collapsed newlines from environment variables
- **RS256 JWT client assertion** — auto-generated per Truist playbook §3.2
- **Access-token cache** — tokens reused until near-expiry, then refreshed automatically
- **JWKS cache** — Truist encryption key fetched once and cached (default 15 min TTL)
- **JWE payload encryption** — `RSA-OAEP-256` key wrapping + `A128CBC-HS256` content encryption, matching Truist's required cipher suite
- **Request validation** — Zod schemas enforce field formats before any network call, with clear error messages that mirror Truist error codes
- **Payload normalisation** — `id` auto-assigned (1-based) to account items that omit it
- **Exponential back-off retries** — configurable retry count and base delay; non-retryable 4xx errors surfaced immediately

---

## Installation

```bash
npm install truist-sdk
```

---

## Quick Start

```typescript
import fs from 'node:fs';
import { TruistClient } from 'truist-sdk';

const client = new TruistClient({
    environment: 'cert',                             // 'cert' | 'prod'
    clientId:     process.env.TRUIST_CLIENT_ID!,
    clientSecret: process.env.TRUIST_CLIENT_SECRET!,
    companyId:    process.env.TRUIST_COMPANY_ID!,
    userId:       process.env.TRUIST_USER_ID!,
    issuer:       process.env.TRUIST_ISSUER!,
    kid:          process.env.TRUIST_KID,
    privateKey:   fs.readFileSync('keys/truist-private-key.pem', 'utf8'),
    mtls: {
        cert: fs.readFileSync('certs/client-cert.pem'),
        key:  fs.readFileSync('certs/client-key.pem'),
        ca:   fs.readFileSync('certs/ca.pem')        // optional
    }
});
```

---

## Account Verification

Verify up to **5 bank accounts** per request.

```typescript
const result = await client.verifyAccounts({
    verifyAccounts: [
        { id: 1, accountNumber: '1236511211235999', routingNumber: '061000104' },
        { id: 2, accountNumber: '1236511211235900', routingNumber: '061000104' }
    ]
});

console.log(result.verifiedAccounts);
// [
//   { id: 1, accountVerificationStatus: { status: 'OPENED_AND_VALID', description: 'Successful Verification', code: '0000' } },
//   { id: 2, accountVerificationStatus: { status: 'CLOSED',           description: 'Successful Verification', code: '0000' } }
// ]
```

### `VerifyAccountItem` fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | `number` | ✅ | Caller-assigned correlation ID; returned verbatim in the response. Auto-assigned (1-based) by the backend normaliser if omitted by the caller. |
| `accountNumber` | `string` | ✅ | 1–17 numeric digits |
| `routingNumber` | `string` | ✅ | Exactly 9 digits; must pass ABA checksum |

### Account verification status codes

| Status | Meaning |
|---|---|
| `OPENED_AND_VALID` | Account is open and valid |
| `CLOSED` | Account exists but is closed |
| `DATA_UNAVAILABLE` | Data provider has no record for this account |
| `INVALID_DATA` | Field-level error — see `code` for details |

---

## Account Owner Verification

Verify up to **5 account owners** per request.

```typescript
const result = await client.verifyAccountOwners({
    verifyAccountOwners: [
        {
            id: 1,
            accountNumber: '200001',
            routingNumber: '122199983',
            profile: {
                firstName:       'KARA',
                lastName:        'AANEMONE',
                ssnTIN:          '666648368',
                homePhoneNumber: '8087531234',
                workPhoneNumber: '8087531234',
                dateOfBirth:     '1950-05-06',   // optional — YYYY-MM-DD
                address: {
                    addressLine: '9384 POODLE LN',
                    city:        'KAILAU',
                    state:       'HI',
                    zipCode:     '96734'
                }
            }
        }
    ]
});

console.log(result.verifiedAccountOwners);
```

### `VerifyOwnerProfile` fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `firstName` | `string` | ✅ | |
| `lastName` | `string` | ✅ | |
| `middleName` | `string` | ❌ | |
| `businessName` | `string` | ❌ | |
| `ssnTIN` | `string` | ✅ | `###-##-####` or 9–10 digits |
| `homePhoneNumber` | `string` | ✅ | 10 digits or E.164 (`+1XXXXXXXXXX`) |
| `workPhoneNumber` | `string` | ✅ | 10 digits or E.164 (`+1XXXXXXXXXX`) |
| `dateOfBirth` | `string` | ❌ | `YYYY-MM-DD` format when provided |
| `documentId` | `string` | ❌ | Must be provided with `documentIdState` + `documentIdType`, or all three omitted |
| `documentIdState` | `string` | ❌ | 2-letter US state abbreviation |
| `documentIdType` | `string` | ❌ | e.g. `DRIVERS_LICENSE`, `PASSPORT`, `STATE_ID` |
| `address.addressLine` | `string` | ❌¹ | Required when `address` is provided |
| `address.city` | `string` | ❌¹ | Required when `address` is provided |
| `address.state` | `string` | ❌¹ | 2-letter US state abbreviation |
| `address.zipCode` | `string` | ❌¹ | 5-digit or ZIP+4 (`XXXXX-XXXX`) |

> ¹ All `address` sub-fields are required together if the `address` object is included.  
> `documentId`, `documentIdState`, and `documentIdType` must all be supplied together or all omitted.

---

## Client Options

| Option | Type | Required | Default | Notes |
|---|---|---|---|---|
| `clientId` | `string` | ✅ | — | Provided during Truist onboarding |
| `clientSecret` | `string` | ✅ | — | Provided during Truist onboarding |
| `companyId` | `string` | ✅ | — | Organisation identifier |
| `userId` | `string` | ✅ | — | User identifier |
| `privateKey` | `string` | ✅ | — | PKCS#8 PEM RSA private key for RS256 assertion signing |
| `issuer` | `string` | ✅ | — | JWT `iss` claim |
| `environment` | `'cert' \| 'prod'` | ❌ | `'cert'` | |
| `mtls.cert` | `string \| Buffer` | ❌ | — | Required for production |
| `mtls.key` | `string \| Buffer` | ❌ | — | Required for production |
| `mtls.ca` | `string \| Buffer` | ❌ | — | |
| `mtls.passphrase` | `string` | ❌ | — | |
| `audience` | `string` | ❌ | `'truist'` | JWT `aud` claim |
| `subject` | `string` | ❌ | `clientId` | JWT `sub` claim |
| `scope` | `string` | ❌ | `'verify:accounts verify:accountsandowners'` | |
| `kid` | `string` | ❌ | — | JWT protected header `kid` |
| `timeoutMs` | `number` | ❌ | `15000` | HTTP request timeout in ms |
| `retries` | `number` | ❌ | `2` | Retry attempts for transient errors |
| `retryDelayMs` | `number` | ❌ | `500` | Base retry delay in ms (exponential back-off applied) |
| `jwksCacheTtlMs` | `number` | ❌ | `900000` (15 min) | JWKS cache TTL in ms |
| `jwtExpirySeconds` | `number` | ❌ | `300` | JWT assertion lifetime in seconds (60–600) |
| `urls` | `Partial<TruistEndpointSet>` | ❌ | — | Override individual endpoint URLs |

---

## Validation

All payloads are validated by Zod schemas before being encrypted and sent. Errors are thrown as `TruistError` with `status: 400` and `code: 'SDK_VALIDATION_ERROR'`, with a message listing every failing field path and reason — e.g.:

```
Invalid verifyAccounts payload. verifyAccounts.0.routingNumber: Routing number must be exactly 9 digits (ABA format).
```

Routing numbers are validated against the **ABA checksum algorithm** in addition to the 9-digit format check, catching invalid numbers before they reach Truist's data provider (Truist error code `8005`).

---

## Environments & Endpoints

| Environment | Token URL | JWKS URL | Verify Base URL |
|---|---|---|---|
| `cert` | `https://apicert.truist.com/commercial/v3/oauth/token` | `https://apicert.truist.com/commercial/v1/.well-known/jwks.json` | `https://apicert.truist.com/commercial/v1` |
| `prod` | `https://api.truist.com/commercial/v3/oauth/token` | `https://api.truist.com/commercial/v1/.well-known/jwks.json` | `https://api.truist.com/commercial/v1` |

---

## Error Handling

All errors are thrown as `TruistError` instances:

```typescript
import { TruistError } from 'truist-sdk';

try {
    const result = await client.verifyAccounts({ verifyAccounts: [...] });
} catch (err) {
    if (err instanceof TruistError) {
        console.error(err.message);  // human-readable description
        console.error(err.status);   // HTTP status code
        console.error(err.code);     // e.g. 'SDK_VALIDATION_ERROR', 'TRUIST_API_ERROR'
    }
}
```

---

## Security Notes

- Never log `privateKey`, `clientSecret`, `access_token`, or any customer PII (`ssnTIN`, `accountNumber`, `dateOfBirth`, etc.)
- mTLS is required for the production environment
- JWT assertions expire in 5 minutes by default; access tokens are cached and reused until near-expiry
- The SDK uses `rejectUnauthorized: true` — never disable TLS certificate verification