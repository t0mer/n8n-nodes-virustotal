import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	IHttpRequestOptions,
	IPollFunctions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, sleep } from 'n8n-workflow';

export const BASE_URL = 'https://www.virustotal.com/api/v3';
export const CREDENTIAL_NAME = 'virusTotalApi';

export type VtContext = IExecuteFunctions | IPollFunctions;

/** Anything that can delay a request, e.g. the per-execution throttle. */
export interface Waiter {
	wait(): Promise<void>;
}

export interface VtRequestOptions {
	method?: IHttpRequestMethods;
	/** Path below the v3 base URL, or a full URL when `absolute` is set. */
	path: string;
	absolute?: boolean;
	qs?: IDataObject;
	body?: IHttpRequestOptions['body'];
	headers?: IDataObject;
	/** Send the body as application/x-www-form-urlencoded. */
	form?: boolean;
	/** Skip the credential header (used for pre-authorized upload URLs). */
	unauthenticated?: boolean;
	/** Status codes returned to the caller instead of thrown. */
	acceptStatus?: number[];
	throttle?: Waiter;
}

export interface VtResponse<T = IDataObject> {
	statusCode: number;
	body: T;
}

export type RetryKind = 'none' | 'backoff' | 'quota';

export interface MappedError {
	message: string;
	description?: string;
	retry: RetryKind;
}

export const BACKOFF_MS = [2000, 4000, 8000];
export const QUOTA_WAIT_MS = 60_000;
export const QUOTA_RETRIES = 2;

function errorField(body: unknown, field: 'code' | 'message'): string {
	const error = (body as { error?: Record<string, unknown> } | undefined)?.error;
	const value = error?.[field];
	return typeof value === 'string' ? value : '';
}

/** Maps a VirusTotal error response onto an actionable message and a retry policy. */
export function mapError(statusCode: number, body: unknown): MappedError {
	const code = errorField(body, 'code');
	const vtMessage = errorField(body, 'message');

	if (
		statusCode === 401 ||
		['WrongCredentialsError', 'AuthenticationRequiredError', 'UserNotActiveError'].includes(code)
	) {
		return {
			message: 'Invalid or inactive VirusTotal API key',
			description: 'Check the API key in the VirusTotal API credential.',
			retry: 'none',
		};
	}
	if (statusCode === 403 || code === 'ForbiddenError') {
		return {
			message: 'VirusTotal refused this request (forbidden)',
			description:
				(vtMessage ? `${vtMessage}. ` : '') +
				'This operation or relationship may require a Premium API key.',
			retry: 'none',
		};
	}
	if (statusCode === 404 || code === 'NotFoundError') {
		return { message: vtMessage || 'Not found on VirusTotal', retry: 'none' };
	}
	if (statusCode === 409 || code === 'AlreadyExistsError') {
		return { message: vtMessage || 'Already exists on VirusTotal', retry: 'none' };
	}
	if (statusCode === 429 || code === 'QuotaExceededError' || code === 'TooManyRequestsError') {
		return {
			message: 'VirusTotal quota exceeded',
			description:
				'The per-minute or daily quota is exhausted. Lower "Requests per Minute" in the credential, wait for the quota to reset, or use a Premium key.' +
				(vtMessage ? ` VirusTotal said: ${vtMessage}` : ''),
			retry: 'quota',
		};
	}
	if (statusCode === 400 && code === 'NotAvailableYet') {
		return {
			message: vtMessage || 'The result is not available yet',
			description: 'The analysis is still running. Try again shortly.',
			retry: 'backoff',
		};
	}
	if (
		statusCode === 503 ||
		statusCode === 504 ||
		code === 'TransientError' ||
		code === 'DeadlineExceededError'
	) {
		return {
			message: vtMessage || 'VirusTotal is temporarily unavailable',
			description: 'VirusTotal returned a transient error. Try again later.',
			retry: 'backoff',
		};
	}
	return {
		message: vtMessage || `VirusTotal request failed with status ${statusCode}`,
		retry: 'none',
	};
}

function buildOptions(opts: VtRequestOptions): IHttpRequestOptions {
	const request: IHttpRequestOptions = {
		method: opts.method ?? 'GET',
		url: opts.absolute ? opts.path : `${BASE_URL}${opts.path}`,
		json: true,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
	};
	if (opts.qs) request.qs = opts.qs;
	if (opts.body !== undefined) request.body = opts.body;
	if (opts.headers) request.headers = opts.headers;
	if (opts.form) {
		request.headers = { ...request.headers, 'content-type': 'application/x-www-form-urlencoded' };
	}
	return request;
}

/**
 * Performs one VirusTotal request with retries and error mapping.
 * The API key is injected by the credential and never appears in errors.
 */
export async function vtRequestRaw<T = IDataObject>(
	ctx: VtContext,
	opts: VtRequestOptions,
): Promise<VtResponse<T>> {
	let backoffAttempt = 0;
	let quotaAttempt = 0;

	for (;;) {
		if (opts.throttle) await opts.throttle.wait();

		const request = buildOptions(opts);
		const response = (
			opts.unauthenticated
				? await ctx.helpers.httpRequest(request)
				: await ctx.helpers.httpRequestWithAuthentication.call(ctx, CREDENTIAL_NAME, request)
		) as {
			statusCode: number;
			body: T;
		};

		const { statusCode, body } = response;
		if (statusCode >= 200 && statusCode < 300) return { statusCode, body };
		if (opts.acceptStatus?.includes(statusCode)) return { statusCode, body };

		const mapped = mapError(statusCode, body);
		if (mapped.retry === 'backoff' && backoffAttempt < BACKOFF_MS.length) {
			await sleep(BACKOFF_MS[backoffAttempt++]);
			continue;
		}
		if (mapped.retry === 'quota' && quotaAttempt < QUOTA_RETRIES) {
			quotaAttempt++;
			await sleep(QUOTA_WAIT_MS);
			continue;
		}

		throw new NodeApiError(ctx.getNode(), { statusCode, error: body } as unknown as JsonObject, {
			message: mapped.message,
			description: mapped.description,
			httpCode: String(statusCode),
		});
	}
}

/** Like vtRequestRaw but returns only the body. */
export async function vtRequest<T = IDataObject>(
	ctx: VtContext,
	opts: VtRequestOptions,
): Promise<T> {
	return (await vtRequestRaw<T>(ctx, opts)).body;
}

/** Fetches a lookup; returns null when VirusTotal has no such object (404). */
export async function vtLookup<T = IDataObject>(
	ctx: VtContext,
	opts: VtRequestOptions,
): Promise<T | null> {
	const res = await vtRequestRaw<T>(ctx, {
		...opts,
		acceptStatus: [...(opts.acceptStatus ?? []), 404],
	});
	return res.statusCode === 404 ? null : res.body;
}
