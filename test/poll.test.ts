import { describe, expect, it, vi } from 'vitest';
import { analysedObjectId, defaultPollIntervalSeconds, waitForAnalysis } from '../shared/poll';
import { fakeContext } from './helpers';
import { fixtures } from './fixtures';

const res = (body: unknown) => ({ statusCode: 200, body });

function clock() {
	let t = 0;
	return {
		now: () => t,
		sleepFn: vi.fn(async (ms: number) => {
			t += ms;
		}),
	};
}

describe('defaultPollIntervalSeconds', () => {
	it('is 20 s on the public tier and scales with the rate', () => {
		expect(defaultPollIntervalSeconds(4)).toBe(22.5);
		expect(defaultPollIntervalSeconds(100)).toBe(20);
		expect(defaultPollIntervalSeconds(1)).toBe(90);
	});
});

describe('waitForAnalysis', () => {
	it('polls through queued and in-progress until completed', async () => {
		const { ctx, calls } = fakeContext([
			res(fixtures.analysisQueued),
			res(fixtures.analysisInProgress),
			res(fixtures.analysisCompleted),
		]);
		const c = clock();
		const wait = vi.fn(async () => {});
		const body = await waitForAnalysis(ctx, {
			analysisId: 'MjAx-1790000000',
			intervalMs: 20000,
			timeoutMs: 600000,
			throttle: { wait },
			...c,
		});
		expect(body.data?.attributes?.status).toBe('completed');
		expect(calls).toHaveLength(3);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/analyses/MjAx-1790000000');
		expect(c.sleepFn.mock.calls.map((x) => x[0])).toEqual([20000, 20000]);
		expect(wait).toHaveBeenCalledTimes(3);
	});

	it('times out with the analysis id in the message', async () => {
		const { ctx } = fakeContext(Array(10).fill(res(fixtures.analysisQueued)));
		await expect(
			waitForAnalysis(ctx, {
				analysisId: 'ABC123',
				intervalMs: 60000,
				timeoutMs: 180000,
				...clock(),
			}),
		).rejects.toThrow('Analysis ID: ABC123');
	});

	it('stops when the execution is cancelled before polling', async () => {
		const { ctx, calls } = fakeContext([]);
		const controller = new AbortController();
		controller.abort();
		await expect(
			waitForAnalysis(ctx, {
				analysisId: 'X',
				intervalMs: 1,
				timeoutMs: 1000,
				signal: controller.signal,
				...clock(),
			}),
		).rejects.toThrow('cancelled');
		expect(calls).toHaveLength(0);
	});

	it('stops cleanly when cancelled while waiting', async () => {
		const { ctx, calls } = fakeContext([
			res(fixtures.analysisQueued),
			res(fixtures.analysisQueued),
		]);
		await expect(
			waitForAnalysis(ctx, {
				analysisId: 'X',
				intervalMs: 1000,
				timeoutMs: 600000,
				now: () => 0,
				sleepFn: async () => {
					throw new Error('aborted');
				},
			}),
		).rejects.toThrow('cancelled');
		expect(calls).toHaveLength(1);
	});
});

describe('analysedObjectId', () => {
	it('reads the file SHA-256 or the URL id', () => {
		expect(analysedObjectId(fixtures.analysisCompleted)).toBe(
			'275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
		);
		expect(analysedObjectId(fixtures.analysisCompletedUrl)).toBe(
			'f5e8b8c3d0a7c2e6a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901234ab',
		);
		expect(analysedObjectId(fixtures.analysisQueued)).toBeUndefined();
	});
});
