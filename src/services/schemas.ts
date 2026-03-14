import { z, type RefinementCtx } from 'zod';
import { TruistError } from '../errors/TruistError';

// ---------------------------------------------------------------------------
// Reusable field validators matching Truist API data dictionary (Appendix §8)
// ---------------------------------------------------------------------------

/**
 * ABA routing transit number — exactly 9 numeric digits.
 * Error code 8005 is returned by Truist for invalid routing numbers.
 */
const RoutingNumberSchema = z
    .string()
    .regex(/^\d{9}$/, 'Routing number must be exactly 9 digits (ABA format).');

/**
 * Bank account number — 1 to 17 numeric digits.
 * Error code 8004 is returned by Truist for invalid account numbers.
 */
const AccountNumberSchema = z
    .string()
    .min(1, 'Account number is required.')
    .max(17, 'Account number must not exceed 17 digits.')
    .regex(/^\d+$/, 'Account number must contain only numeric digits.');

/**
 * SSN/TIN — accepts ###-##-#### or ########## formats.
 * Error code 8010 is returned by Truist for invalid SSN/TIN values.
 */
const SsnTinSchema = z
    .string()
    .regex(/^\d{3}-?\d{2}-?\d{4}$|^\d{9,10}$/, 'ssnTIN must be a valid SSN (###-##-####) or TIN (9–10 digits).');

/**
 * Phone number — accepts E.164 format (+1XXXXXXXXXX) or plain 10-digit (XXXXXXXXXX).
 * Truist test data uses plain 10-digit numbers; E.164 is also accepted.
 * Error code 8011 is returned by Truist for invalid phone numbers.
 */
const PhoneNumberSchema = z
    .string()
    .regex(/^\+[1-9]\d{7,14}$|^\d{10}$/, 'Phone number must be 10 digits or E.164 format (e.g. +19493489740).');

/**
 * US ZIP code — 5 digits or ZIP+4 (XXXXX-XXXX).
 * Error code 8016 is returned by Truist for invalid zip codes.
 */
const ZipCodeSchema = z
    .string()
    .regex(/^\d{5}(-\d{4})?$/, 'zipCode must be a 5-digit or ZIP+4 (XXXXX-XXXX) postal code.');

/**
 * 2-letter US state abbreviation.
 * Error codes 8015 / 8019 are returned by Truist for invalid state codes.
 */
const StateCodeSchema = z
    .string()
    .length(2, 'State must be a 2-letter US state abbreviation.')
    .toUpperCase();

// ---------------------------------------------------------------------------
// Account Verification
// ---------------------------------------------------------------------------

const VerifyAccountItemSchema = z.object({
    id: z.number().int().nonnegative(),
    accountNumber: AccountNumberSchema,
    routingNumber: RoutingNumberSchema
}).strict();

export const VerifyAccountsRequestSchema = z.object({
    /** Truist enforces a maximum of 5 accounts per request. */
    verifyAccounts: z.array(VerifyAccountItemSchema).min(1, 'At least one account is required.').max(5, 'A maximum of 5 accounts are allowed per request.')
}).strict();

// ---------------------------------------------------------------------------
// Account Owner Verification
// ---------------------------------------------------------------------------

const AddressSchema = z.object({
    addressLine: z.string().min(1, 'addressLine is required.'),
    city: z.string().min(1, 'city is required.'),
    state: StateCodeSchema,
    zipCode: ZipCodeSchema
}).strict();

const OwnerProfileSchema = z.object({
    firstName: z.string().min(1, 'firstName is required.'),
    lastName: z.string().min(1, 'lastName is required.'),
    middleName: z.string().optional(),
    businessName: z.string().optional(),
    ssnTIN: SsnTinSchema,
    homePhoneNumber: PhoneNumberSchema,
    workPhoneNumber: PhoneNumberSchema,
    /** ISO-8601 date (YYYY-MM-DD). */
    dateOfBirth: z.string().regex(/^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/, 'dateOfBirth must be in YYYY-MM-DD format.'),
    documentId: z.string().optional(),
    documentIdState: StateCodeSchema.optional(),
    documentIdType: z.string().optional(),
    address: AddressSchema.optional()
}).strict().superRefine((value: unknown, ctx: RefinementCtx) => {
    const profile = value as Record<string, unknown>;
    // All three document fields must be supplied together or all omitted (§5.2 note)
    const docValues = [profile.documentId, profile.documentIdState, profile.documentIdType];
    const presentCount = docValues.filter(Boolean).length;
    if (presentCount > 0 && presentCount < 3) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'documentId, documentIdState, and documentIdType must all be provided together or all omitted.'
        });
    }
});

const VerifyAccountOwnerItemSchema = z.object({
    id: z.number().int().nonnegative(),
    accountNumber: AccountNumberSchema,
    routingNumber: RoutingNumberSchema,
    profile: OwnerProfileSchema
}).strict();

export const VerifyAccountOwnersRequestSchema = z.object({
    /** Truist enforces a maximum of 5 accounts per request. */
    verifyAccountOwners: z.array(VerifyAccountOwnerItemSchema).min(1, 'At least one account owner is required.').max(5, 'A maximum of 5 accounts are allowed per request.')
}).strict();

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

export function parseOrThrow<T>(schema: z.ZodSchema<T>, payload: unknown, message: string): T {
    const result = schema.safeParse(payload);

    if (result.success) {
        return result.data;
    }

    const details = result.error.issues.map((issue: z.ZodIssue) => {
        const path = issue.path.length ? issue.path.join('.') : 'root';
        return `${path}: ${issue.message}`;
    });

    throw new TruistError(`${message} ${details.join('; ')}`, 400, 'SDK_VALIDATION_ERROR');
}