import { describe, expect, it, vi } from 'vitest';
import { paginate } from '../shared/paginate';
import { fakeContext } from './helpers';
import { fixtures } from './fixtures';

const pages = () => [
	{ statusCode: 200, body: fixtures.relationshipPage1 },
	{ statusCode: 200, body: fixtures.relationshipPage2 },
];

describe('paginate', () => {
	it('follows meta.cursor until the last page when returning all', async () => {
		const { ctx, calls } = fakeContext(pages());
		const items = await paginate(ctx, { path: '/domains/example.com/subdomains', returnAll: true });
		expect(items.map((i) => i.id)).toEqual(['a.example.com', 'b.example.com', 'c.example.com']);
		expect(calls).toHaveLength(2);
		expect(calls[0].qs).toEqual({ limit: 40 });
		expect(calls[1].qs).toEqual({ limit: 40, cursor: 'CURSOR2' });
	});

	it('stops at the limit and asks for no more than needed', async () => {
		const { ctx, calls } = fakeContext(pages());
		const items = await paginate(ctx, { path: '/x', returnAll: false, limit: 2 });
		expect(items).toHaveLength(2);
		expect(calls).toHaveLength(1);
		expect(calls[0].qs).toEqual({ limit: 2 });
	});

	it('trims the final page to the limit', async () => {
		const { ctx } = fakeContext(pages());
		const items = await paginate(ctx, { path: '/x', returnAll: false, limit: 3 });
		expect(items.map((i) => i.id)).toEqual(['a.example.com', 'b.example.com', 'c.example.com']);
	});

	it('sends each page through the throttle', async () => {
		const { ctx } = fakeContext(pages());
		const wait = vi.fn(async () => {});
		await paginate(ctx, { path: '/x', returnAll: true, throttle: { wait } });
		expect(wait).toHaveBeenCalledTimes(2);
	});

	it('returns an empty list for an empty collection', async () => {
		const { ctx } = fakeContext([{ statusCode: 200, body: { data: [] } }]);
		expect(await paginate(ctx, { path: '/x', returnAll: true })).toEqual([]);
	});

	it('passes extra query parameters on every page', async () => {
		const { ctx, calls } = fakeContext(pages());
		await paginate(ctx, { path: '/x', returnAll: true, qs: { query: 'q' } });
		expect(calls.every((c) => (c.qs as { query: string }).query === 'q')).toBe(true);
	});
});
