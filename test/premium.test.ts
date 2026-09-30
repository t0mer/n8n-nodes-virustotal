import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const ok = (body: unknown) => ({ statusCode: 200, body });

function exec(
	params: Record<string, unknown>,
	tier: string,
	responses: Array<{ statusCode: number; body: unknown }> = [],
) {
	const { fn, calls } = fakeExecute({ params: [params], responses, credentials: { tier } });
	return { promise: new VirusTotal().execute.call(fn), calls };
}

const download = { resource: 'file', operation: 'getDownloadUrl', hash: SHA256 };
const intel = {
	resource: 'search',
	operation: 'intelligenceSearch',
	query: 'positives:5+',
	order: 'last_submission_date-',
	returnAll: false,
	limit: 3,
};

describe('Premium gating', () => {
	it('Get Download URL is refused on the public tier without any request', async () => {
		const { promise, calls } = exec(download, 'public');
		await expect(promise).rejects.toThrow('Get Download URL requires a VirusTotal Premium API key');
		expect(calls).toHaveLength(0);
	});

	it('Intelligence Search is refused on the public tier without any request', async () => {
		const { promise, calls } = exec(intel, 'public');
		await expect(promise).rejects.toThrow(
			'Intelligence Search requires a VirusTotal Premium API key',
		);
		expect(calls).toHaveLength(0);
	});

	it('Get Download URL returns the URL and never downloads', async () => {
		const { promise, calls } = exec(download, 'premium', [
			ok({ data: 'https://download.example/abc' }),
		]);
		const [[item]] = await promise;
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe(`https://www.virustotal.com/api/v3/files/${SHA256}/download_url`);
		expect(item.json).toEqual({ hash: SHA256, downloadUrl: 'https://download.example/abc' });
	});

	it('Intelligence Search sends query and order', async () => {
		const { promise, calls } = exec(intel, 'premium', [ok(fixtures.searchResults)]);
		const [items] = await promise;
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/intelligence/search');
		expect(calls[0].qs).toEqual({
			query: 'positives:5+',
			order: 'last_submission_date-',
			limit: 3,
		});
		expect(items).toHaveLength(3);
	});

	it('Intelligence Search omits an empty order', async () => {
		const { promise, calls } = exec({ ...intel, order: '' }, 'premium', [
			ok(fixtures.searchResults),
		]);
		await promise;
		expect(calls[0].qs).not.toHaveProperty('order');
	});

	it('the basic Search works on the public tier', async () => {
		const { promise } = exec(
			{ resource: 'search', operation: 'search', query: 'x', returnAll: false, limit: 3 },
			'public',
			[ok(fixtures.searchResults)],
		);
		await expect(promise).resolves.toBeDefined();
	});
});
