import { VerifyAccountOwnersRequest } from '../types';
import { parseOrThrow, VerifyAccountOwnersRequestSchema } from './schemas';

export function validateVerifyAccountOwnersPayload(payload: unknown): VerifyAccountOwnersRequest {
    return parseOrThrow(VerifyAccountOwnersRequestSchema, payload, 'Invalid verifyAccountOwners payload.');
}