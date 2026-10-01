import { describe, expect, it } from 'vitest';
import { NodeOperationError } from 'n8n-workflow';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';

const ok = (body: unknown) => ({ statusCode: 200, body });

/** Quota response whose daily counter has `used` of 500 spent. */
const quotas = (used: number) => ({
	data: { api_requests_daily: { user: { allowed: 500, used } } },
});

const lookup = { resource: 'account', operation: 'getPopularThreatCategories' };

function batch(count: number, extra: Record<string, unknown>, responses: ReturnType<typeof ok>[]) {
	return fakeExecute({
		params: Array.from({ length: count }, () => ({ ...lookup, ...extra })),
		responses,
	});
}

const quotaCalls = (calls: Array<Record<string, unknown>>) =>
	calls.filter((c) => String(c.url).includes('/overall_quotas'));

describe('Check Quota Before Batch', () => {
	const on = { batchOptions: { checkQuotaBeforeBatch: true } };
	const categories = ok({ data: [] });

	it('makes no quota call when the option is off, even for a large batch', async () => {
		const { fn, calls } = batch(12, {}, Array(12).fill(categories));
		await new VirusTotal().execute.call(fn);
		expect(quotaCalls(calls)).toHaveLength(0);
	});

	it('skips the check when the estimate is 10 requests or fewer', async () => {
		const { fn, calls } = batch(10, on, Array(10).fill(categories));
		await new VirusTotal().execute.call(fn);
		expect(quotaCalls(calls)).toHaveLength(0);
	});

	it('reads the quota once and runs the batch when the budget is enough', async () => {
		const { fn, calls } = batch(11, on, [ok(quotas(100)), ...Array(11).fill(categories)]);
		const [items] = await new VirusTotal().execute.call(fn);
		expect(quotaCalls(calls)).toHaveLength(1);
		expect(String(calls[0].url)).toBe(
			'https://www.virustotal.com/api/v3/users/test-key/overall_quotas',
		);
		expect(items).toHaveLength(11);
	});

	it('fails early without processing items when the daily budget is too small', async () => {
		const { fn, calls } = batch(11, on, [ok(quotas(495))]);
		const run = new VirusTotal().execute.call(fn);
		await expect(run).rejects.toBeInstanceOf(NodeOperationError);
		await expect(run).rejects.toThrow(/needs about 11 requests but 5 remain/);
		expect(calls).toHaveLength(1);
	});

	it('counts waiting scans as several requests each', async () => {
		const { fn, calls } = fakeExecute({
			params: [
				{ resource: 'url', operation: 'scan', mode: 'wait', ...on },
				{ resource: 'url', operation: 'scan', mode: 'wait', ...on },
				{ resource: 'url', operation: 'scan', mode: 'wait', ...on },
			],
			responses: [ok(quotas(490))],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow(/needs about 15 requests/);
		expect(quotaCalls(calls)).toHaveLength(1);
	});

	it('does not block when no daily quota is reported', async () => {
		const { fn } = batch(11, on, [ok({ data: {} }), ...Array(11).fill(categories)]);
		const [items] = await new VirusTotal().execute.call(fn);
		expect(items).toHaveLength(11);
	});
});
