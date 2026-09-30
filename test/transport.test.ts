import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeContext } from './helpers';

const sleepMock = vi.hoisted(() => vi.fn<(ms: number) => Promise<void>>(async () => {}));
vi.mock('n8n-workflow', async (importOriginal) => ({
	...(await importOriginal<typeof import('n8n-workflow')>()),
	sleep: sleepMock,
}));

import { mapError, vtLookup, vtRequest } from '../shared/transport';

const err = (code: string, message = 'msg') => ({ error: { code, message } });

beforeEach(() => sleepMock.mockClear());

describe('mapError', () => {
	it.each([
		[400, 'BadRequestError', 'none'],
		[400, 'InvalidArgumentError', 'none'],
		[400, 'NotAvailableYet', 'backoff'],
		[401, 'WrongCredentialsError', 'none'],
		[401, 'AuthenticationRequiredError', 'none'],
		[401, 'UserNotActiveError', 'none'],
		[403, 'ForbiddenError', 'none'],
		[404, 'NotFoundError', 'none'],
		[409, 'AlreadyExistsError', 'none'],
		[429, 'QuotaExceededError', 'quota'],
		[429, 'TooManyRequestsError', 'quota'],
		[503, 'TransientError', 'backoff'],
		[504, 'DeadlineExceededError', 'backoff'],
	])('%i %s -> retry %s', (status, code, retry) => {
		expect(mapError(status, err(code)).retry).toBe(retry);
	});

	it('shows the VirusTotal message verbatim for 400', () => {
		expect(mapError(400, err('BadRequestError', 'Bad thing')).message).toBe('Bad thing');
	});

	it('uses the actionable key message for 401', () => {
		expect(mapError(401, err('WrongCredentialsError')).message).toBe(
			'Invalid or inactive VirusTotal API key',
		);
	});

	it('mentions Premium for 403', () => {
		expect(mapError(403, err('ForbiddenError')).description).toContain('Premium');
	});
});

describe('vtRequest', () => {
	it('returns the body on success and targets the v3 base URL', async () => {
		const { ctx, calls } = fakeContext([{ statusCode: 200, body: { data: { id: 'x' } } }]);
		const body = await vtRequest(ctx, { path: '/files/abc' });
		expect(body).toEqual({ data: { id: 'x' } });
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/files/abc');
	});

	it('does not retry 400 BadRequestError and throws', async () => {
		const { ctx, calls } = fakeContext([{ statusCode: 400, body: err('BadRequestError', 'nope') }]);
		await expect(vtRequest(ctx, { path: '/x' })).rejects.toThrow('nope');
		expect(calls).toHaveLength(1);
	});

	it('does not retry 401', async () => {
		const { ctx, calls } = fakeContext([{ statusCode: 401, body: err('WrongCredentialsError') }]);
		await expect(vtRequest(ctx, { path: '/x' })).rejects.toThrow(
			'Invalid or inactive VirusTotal API key',
		);
		expect(calls).toHaveLength(1);
	});

	it('retries NotAvailableYet with backoff then succeeds', async () => {
		const { ctx } = fakeContext([
			{ statusCode: 400, body: err('NotAvailableYet') },
			{ statusCode: 200, body: { ok: true } },
		]);
		expect(await vtRequest(ctx, { path: '/x' })).toEqual({ ok: true });
		expect(sleepMock.mock.calls.map((c) => c[0])).toEqual([2000]);
	});

	it('backs off 2s, 4s, 8s on 503 and gives up after 3 retries', async () => {
		const { ctx, calls } = fakeContext(
			Array(4).fill({ statusCode: 503, body: err('TransientError') }),
		);
		await expect(vtRequest(ctx, { path: '/x' })).rejects.toThrow();
		expect(calls).toHaveLength(4);
		expect(sleepMock.mock.calls.map((c) => c[0])).toEqual([2000, 4000, 8000]);
	});

	it('waits one minute on 429 and retries at most twice', async () => {
		const { ctx, calls } = fakeContext(
			Array(3).fill({ statusCode: 429, body: err('QuotaExceededError') }),
		);
		await expect(vtRequest(ctx, { path: '/x' })).rejects.toThrow('VirusTotal quota exceeded');
		expect(calls).toHaveLength(3);
		expect(sleepMock.mock.calls.map((c) => c[0])).toEqual([60000, 60000]);
	});

	it('passes the execution cancel signal to retry waits so they can be cancelled', async () => {
		const { ctx } = fakeContext([
			{ statusCode: 429, body: err('QuotaExceededError') },
			{ statusCode: 503, body: err('TransientError') },
			{ statusCode: 200, body: {} },
		]);
		const controller = new AbortController();
		(ctx as unknown as Record<string, unknown>).getExecutionCancelSignal = () => controller.signal;
		await vtRequest(ctx, { path: '/x' });
		expect(sleepMock.mock.calls.map((c) => c[1])).toEqual([controller.signal, controller.signal]);
	});

	it('recovers when the retry after 429 succeeds', async () => {
		const { ctx } = fakeContext([
			{ statusCode: 429, body: err('TooManyRequestsError') },
			{ statusCode: 200, body: { ok: 1 } },
		]);
		expect(await vtRequest(ctx, { path: '/x' })).toEqual({ ok: 1 });
	});

	it('returns accepted statuses instead of throwing (409)', async () => {
		const { ctx } = fakeContext([{ statusCode: 409, body: err('AlreadyExistsError') }]);
		const { vtRequestRaw } = await import('../shared/transport');
		const res = await vtRequestRaw(ctx, { path: '/x', acceptStatus: [409] });
		expect(res.statusCode).toBe(409);
	});

	it('uses plain httpRequest for unauthenticated calls', async () => {
		const { ctx } = fakeContext([{ statusCode: 200, body: {} }]);
		await vtRequest(ctx, {
			path: 'https://upload.example/u',
			absolute: true,
			unauthenticated: true,
		});
		expect(ctx.helpers.httpRequest).toHaveBeenCalledTimes(1);
		expect(ctx.helpers.httpRequestWithAuthentication).not.toHaveBeenCalled();
	});

	it('calls the throttle before every attempt', async () => {
		const { ctx } = fakeContext([
			{ statusCode: 503, body: err('TransientError') },
			{ statusCode: 200, body: {} },
		]);
		const wait = vi.fn(async () => {});
		await vtRequest(ctx, { path: '/x', throttle: { wait } });
		expect(wait).toHaveBeenCalledTimes(2);
	});
});

describe('vtLookup', () => {
	it('returns null on 404', async () => {
		const { ctx } = fakeContext([{ statusCode: 404, body: err('NotFoundError') }]);
		expect(await vtLookup(ctx, { path: '/files/zzz' })).toBeNull();
	});

	it('still throws on other errors', async () => {
		const { ctx } = fakeContext([{ statusCode: 403, body: err('ForbiddenError') }]);
		await expect(vtLookup(ctx, { path: '/x' })).rejects.toThrow('forbidden');
	});
});
