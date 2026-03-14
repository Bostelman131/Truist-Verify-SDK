import { VerifyAccountsRequest } from '../types';
import { parseOrThrow, VerifyAccountsRequestSchema } from './schemas';

export function validateVerifyAccountsPayload(payload: unknown): VerifyAccountsRequest {
    return parseOrThrow(VerifyAccountsRequestSchema, payload, 'Invalid verifyAccounts payload.');
}