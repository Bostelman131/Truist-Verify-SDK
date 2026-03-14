import axios, { AxiosInstance } from 'axios';
import https from 'node:https';
import { MtlsOptions } from '../types';
import { toTruistError } from '../errors/TruistError';

/**
 * HTTP status codes that should NEVER be retried.
 * Authentication/authorization errors must be surfaced immediately so the
 * caller can correct credentials rather than hammering the auth server.
 */
const NON_RETRYABLE_STATUSES = new Set([400, 401, 403, 404, 405, 422]);

export function createHttpClient(options: { timeoutMs: number; mtls?: MtlsOptions }): AxiosInstance {
    const httpsAgent = new https.Agent({
        cert: options.mtls?.cert,
        key: options.mtls?.key,
        ca: options.mtls?.ca,
        passphrase: options.mtls?.passphrase,
        keepAlive: true,
        /**
         * Never disable TLS verification in production.
         * Truist requires mutual TLS — the CA bundle must be trusted.
         */
        rejectUnauthorized: true
    });

    return axios.create({
        timeout: options.timeoutMs,
        httpsAgent,
        headers: {
            Accept: 'application/json'
        }
    });
}

/**
 * Retries transient failures with exponential back-off + jitter.
 * Authentication errors (4xx) are NOT retried — only 408, 429, and 5xx.
 */
export async function withRetry<T>(operation: () => Promise<T>, retries: number, retryDelayMs: number): Promise<T> {
    let attempt = 0;

    while (true) {
        try {
            return await operation();
        } catch (error) {
            const axiosError = axios.isAxiosError(error) ? error : undefined;
            const status = axiosError?.response?.status;

            const isRetryable = !axiosError  // network-level error
                || status === 408            // request timeout
                || status === 429            // rate limited
                || (typeof status === 'number' && status >= 500 && !NON_RETRYABLE_STATUSES.has(status));

            if (!isRetryable || attempt >= retries) {
                throw toTruistError(error);
            }

            // Exponential back-off with ±100 ms jitter to avoid thundering herd
            const backoff = retryDelayMs * Math.pow(2, attempt) + Math.floor(Math.random() * 100);
            await new Promise((resolve) => setTimeout(resolve, backoff));
            attempt += 1;
        }
    }
}