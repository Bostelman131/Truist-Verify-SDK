# Truist SDK

## Overview

Node.js and TypeScript SDK for Truist Verify APIs with built-in support for CERT and PROD environments, mutual TLS authentication, RS256 client assertions, access-token caching, JWKS caching, and JWE request encryption.

## Features

- CERT and PROD endpoint support
- Mutual TLS (mTLS) support out of the box
- RS256 JWT client assertion generation
- Access token caching with early refresh
- JWKS caching for Truist encryption keys
- JWE encryption using `RSA-OAEP-256` and `A256GCM`
- Strict request validation for account and ownership verification

## Installation

```bash
npm install truist-sdk
```

## Usage

```typescript
import fs from 'node:fs';
import { TruistClient } from 'truist-sdk';

const client = new TruistClient({
    environment: 'cert',
    clientId: process.env.TRUIST_CLIENT_ID!,
    clientSecret: process.env.TRUIST_CLIENT_SECRET!,
    companyId: process.env.TRUIST_COMPANY_ID!,
    userId: process.env.TRUIST_USER_ID!,
    issuer: process.env.TRUIST_ISSUER!,
    privateKey: fs.readFileSync('keys/truist-private-key.pem', 'utf8'),
    mtls: {
        cert: fs.readFileSync('certs/client-cert.pem'),
        key: fs.readFileSync('certs/client-key.pem'),
        ca: fs.readFileSync('certs/ca.pem')
    }
});

const accountResult = await client.verifyAccounts({
    verifyAccounts: [
        {
            id: 1,
            accountNumber: '0000001053085039',
            routingNumber: '031204710'
        }
    ]
});

const ownerResult = await client.verifyAccountOwners({
    verifyAccountOwners: [
        {
            id: 1,
            accountNumber: '200001',
            routingNumber: '122199983',
            profile: {
                firstName: 'KARA',
                lastName: 'AANEMONE',
                ssnTIN: '666648368',
                homePhoneNumber: '8087531234',
                workPhoneNumber: '8087531234',
                dateOfBirth: '1950-05-06',
                documentId: '324648368',
                documentIdState: 'HI',
                documentIdType: 'DRIVERS_LICENSE_USA',
                address: {
                    addressLine: '9384 POODLE LN',
                    city: 'KAILAU',
                    state: 'HI',
                    zipCode: '96734'
                }
            }
        }
    ]
});

console.log(accountResult, ownerResult);
```

## Notes

- `environment: 'cert'` uses `apicert.truist.com`
- `environment: 'prod'` uses `api.truist.com`
- mTLS is required
- verification requests support a maximum of 5 items per call
- request payloads are validated before encryption and transmission
- do not log private keys, access tokens, or customer PII