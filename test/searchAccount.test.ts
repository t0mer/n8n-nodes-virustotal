import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { flattenQuotas } from '../nodes/VirusTotal/resources/account';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const ok = (body: unknown) => ({ statusCode: 200, body });

async function run(
	params: Record<string, unknown>,
	responses: Array<{ statusCode: number; body: unknown }>,
) {
	const { fn, calls } = fakeExecute({ params: [params], responses });
	const [items] = await new VirusTotal().execute.call(fn);
	return { items, calls };
}

describe('Search', () => {
	it('sends the query and summarizes indicator hits, flattening comments', async () => {
		const { items, calls } = await run(
			{ resource: 'search', operation: 'search', query: ' eicar ', returnAll: false, limit: 3 },
			[ok(fixtures.searchResults)],
		);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/search');
		expect(calls[0].qs).toEqual({ query: 'eicar', limit: 3 });
		expect(items[0].json).toMatchObject({
			found: true,
			type: 'file',
			verdict: 'malicious',
			meaningfulName: 'eicar.com',
		});
		expect(items[1].json).toMatchObject({ type: 'domain', verdict: 'clean' });
		expect(items[2].json).toEqual({
			id: 'c1',
			type: 'comment',
			text: 'eicar sample',
			date: 1790000000,
		});
	});

	it('Raw output leaves objects unchanged', async () => {
		const { items } = await run(
			{
				resource: 'search',
				operation: 'search',
				query: 'x',
				returnAll: false,
				limit: 3,
				output: 'raw',
			},
			[ok(fixtures.searchResults)],
		);
		expect(items[0].json).toEqual(fixtures.searchResults.data[0]);
	});
});

describe('Account', () => {
	it('flattens overall_quotas, preferring user counters', () => {
		expect(flattenQuotas(fixtures.overallQuotas.data)).toEqual([
			{ quota: { name: 'api_requests_hourly', used: 3, allowed: 240, remaining: 237 } },
			{ quota: { name: 'api_requests_daily', used: 120, allowed: 500, remaining: 380 } },
			{ quota: { name: 'api_requests_monthly', used: 2100, allowed: 15500, remaining: 13400 } },
			{ quota: { name: 'intelligence_downloads_monthly', used: 0, allowed: 0, remaining: 0 } },
		]);
	});

	it('Get Quotas reads /users/{apikey}/overall_quotas', async () => {
		const { items, calls } = await run({ resource: 'account', operation: 'getQuotas' }, [
			ok(fixtures.overallQuotas),
		]);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/users/test-key/overall_quotas');
		expect(items).toHaveLength(4);
		expect(items.every((i) => (i.pairedItem as { item: number }).item === 0)).toBe(true);
	});

	it('Get Popular Threat Categories returns one item with the list', async () => {
		const { items } = await run({ resource: 'account', operation: 'getPopularThreatCategories' }, [
			ok(fixtures.popularThreatCategories),
		]);
		expect(items[0].json).toEqual({
			categories: ['trojan', 'ransomware', 'downloader', 'dropper', 'worm'],
		});
	});
});
