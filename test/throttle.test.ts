import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Throttle, createThrottle } from '../shared/throttle';
import type { VtContext } from '../shared/transport';

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

async function stamps(throttle: Throttle, count: number): Promise<number[]> {
	const start = Date.now();
	const out: number[] = [];
	const tasks = Array.from({ length: count }, async () => {
		await throttle.wait();
		out.push(Date.now() - start);
	});
	await vi.advanceTimersByTimeAsync(10 * 60_000);
	await Promise.all(tasks);
	return out;
}

describe('Throttle', () => {
	it('sends the first request immediately and spaces the rest at 15 s for 4/min', async () => {
		expect(await stamps(new Throttle(4), 4)).toEqual([0, 15000, 30000, 45000]);
	});

	it('honours a higher rate (60/min -> 1 s)', async () => {
		expect(await stamps(new Throttle(60), 3)).toEqual([0, 1000, 2000]);
	});

	it('does not delay when calls are already further apart than the interval', async () => {
		const throttle = new Throttle(4);
		await throttle.wait();
		await vi.advanceTimersByTimeAsync(20_000);
		const before = Date.now();
		await throttle.wait();
		expect(Date.now() - before).toBe(0);
	});

	it('falls back to 4/min on an invalid rate', () => {
		expect(new Throttle(0).intervalMs).toBe(15000);
		expect(new Throttle(Number.NaN).intervalMs).toBe(15000);
	});

	it('rejects a pending wait when the execution is cancelled', async () => {
		const controller = new AbortController();
		const throttle = new Throttle(4, controller.signal);
		await throttle.wait();
		const pending = throttle.wait();
		const assertion = expect(pending).rejects.toBeDefined();
		controller.abort();
		await vi.advanceTimersByTimeAsync(1);
		await assertion;
	});
});

describe('createThrottle', () => {
	it('reads requestsPerMinute from the credential', async () => {
		const ctx = { getCredentials: async () => ({ requestsPerMinute: 10 }) } as unknown as VtContext;
		expect((await createThrottle(ctx)).intervalMs).toBe(6000);
	});
});
