/**
 * Services / schema validation tests
 * Validates that the Zod schemas correctly enforce Truist API data rules.
 */
import { parseOrThrow, VerifyAccountsRequestSchema, VerifyAccountOwnersRequestSchema } from '../src/services/schemas';
import { TruistError } from '../src/errors/TruistError';

// ---------------------------------------------------------------------------
// Account Verification schema
// ---------------------------------------------------------------------------

describe('VerifyAccountsRequestSchema', () => {
    const validPayload = {
        verifyAccounts: [
            { id: 1, accountNumber: '1236511211235999', routingNumber: '101010101' }
        ]
    };

    it('accepts a valid single-account payload', () => {
        const result = parseOrThrow(VerifyAccountsRequestSchema, validPayload, 'fail');
        expect(result.verifyAccounts).toHaveLength(1);
    });

    it('accepts up to 5 accounts (API maximum)', () => {
        const payload = {
            verifyAccounts: Array.from({ length: 5 }, (_, i) => ({
                id: i + 1,
                accountNumber: `123456789${i}`,
                routingNumber: '101010101'
            }))
        };
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, payload, 'fail')).not.toThrow();
    });

    it('rejects more than 5 accounts (Truist API limit)', () => {
        const payload = {
            verifyAccounts: Array.from({ length: 6 }, (_, i) => ({
                id: i + 1,
                accountNumber: `12345678${i}0`,
                routingNumber: '101010101'
            }))
        };
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects empty accounts array', () => {
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, { verifyAccounts: [] }, 'fail')).toThrow(TruistError);
    });

    it('rejects invalid routing number (not 9 digits) — error code 8005', () => {
        const payload = { verifyAccounts: [{ id: 1, accountNumber: '123456789', routingNumber: '12345678' }] };
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects non-numeric routing number', () => {
        const payload = { verifyAccounts: [{ id: 1, accountNumber: '123456789', routingNumber: 'ABCDEFGHI' }] };
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects account number longer than 17 digits — error code 8004', () => {
        const payload = { verifyAccounts: [{ id: 1, accountNumber: '123456789012345678', routingNumber: '101010101' }] };
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects non-numeric account number', () => {
        const payload = { verifyAccounts: [{ id: 1, accountNumber: 'ACCT-001', routingNumber: '101010101' }] };
        expect(() => parseOrThrow(VerifyAccountsRequestSchema, payload, 'fail')).toThrow(TruistError);
    });
});

// ---------------------------------------------------------------------------
// Account Owner Verification schema
// ---------------------------------------------------------------------------

const validOwner = {
    id: 1,
    accountNumber: '1236511211235999',
    routingNumber: '101010101',
    profile: {
        firstName: 'John',
        lastName: 'Doe',
        ssnTIN: '123-34-8974',
        homePhoneNumber: '+19493489740',
        workPhoneNumber: '+19493489740',
        dateOfBirth: '1987-11-29'
    }
};

describe('VerifyAccountOwnersRequestSchema', () => {
    it('accepts a valid single-owner payload', () => {
        const result = parseOrThrow(VerifyAccountOwnersRequestSchema, { verifyAccountOwners: [validOwner] }, 'fail');
        expect(result.verifyAccountOwners).toHaveLength(1);
    });

    it('accepts optional document fields when all three are supplied together', () => {
        const payload = {
            verifyAccountOwners: [{
                ...validOwner,
                profile: {
                    ...validOwner.profile,
                    documentId: 'SAMP19387654',
                    documentIdState: 'NC',
                    documentIdType: 'RESIDENT_ALIEN_ID'
                }
            }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).not.toThrow();
    });

    it('rejects partial document fields (documentId without documentIdState/Type) — §5.2 rule', () => {
        const payload = {
            verifyAccountOwners: [{
                ...validOwner,
                profile: { ...validOwner.profile, documentId: 'SAMP19387654' }
            }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects invalid dateOfBirth format', () => {
        const payload = {
            verifyAccountOwners: [{ ...validOwner, profile: { ...validOwner.profile, dateOfBirth: '11-29-1987' } }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects phone number not in E.164 format — error code 8011', () => {
        const payload = {
            verifyAccountOwners: [{ ...validOwner, profile: { ...validOwner.profile, homePhoneNumber: '555-1234' } }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects invalid ssnTIN format — error code 8010', () => {
        const payload = {
            verifyAccountOwners: [{ ...validOwner, profile: { ...validOwner.profile, ssnTIN: '12-3456' } }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('rejects more than 5 account owners', () => {
        const payload = {
            verifyAccountOwners: Array.from({ length: 6 }, (_, i) => ({ ...validOwner, id: i + 1 }))
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).toThrow(TruistError);
    });

    it('accepts valid address when all address sub-fields are provided', () => {
        const payload = {
            verifyAccountOwners: [{
                ...validOwner,
                profile: {
                    ...validOwner.profile,
                    address: { addressLine: '1st Street', city: 'Chicago', state: 'IL', zipCode: '10001' }
                }
            }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).not.toThrow();
    });

    it('rejects invalid zip code format — error code 8016', () => {
        const payload = {
            verifyAccountOwners: [{
                ...validOwner,
                profile: {
                    ...validOwner.profile,
                    address: { addressLine: '1st Street', city: 'Chicago', state: 'IL', zipCode: 'ABCDE' }
                }
            }]
        };
        expect(() => parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'fail')).toThrow(TruistError);
    });
});
