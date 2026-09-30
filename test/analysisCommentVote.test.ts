import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const ok = (body: unknown, statusCode = 200) => ({ statusCode, body });

async function run(
	params: Record<string, unknown>,
	responses: Array<{ statusCode: number; body: unknown }>,
) {
	const { fn, calls } = fakeExecute({ params: [params], responses });
	const [items] = await new VirusTotal().execute.call(fn);
	return { items, calls };
}

describe('Analysis > Get', () => {
	it('returns status and stats for a running analysis', async () => {
		const { items, calls } = await run(
			{ resource: 'analysis', operation: 'get', analysisId: 'MjAx-1790000000' },
			[ok(fixtures.analysisInProgress)],
		);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/analyses/MjAx-1790000000');
		expect(items[0].json).toMatchObject({ status: 'in-progress', completed: false });
		expect(items[0].json).not.toHaveProperty('itemId');
	});

	it('adds the analysed file id once completed', async () => {
		const { items } = await run({ resource: 'analysis', operation: 'get', analysisId: 'A' }, [
			ok(fixtures.analysisCompleted),
		]);
		expect(items[0].json).toMatchObject({
			status: 'completed',
			completed: true,
			itemType: 'file',
			itemId: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
			stats: { malicious: 62 },
		});
	});

	it('adds the analysed URL id for URL analyses', async () => {
		const { items } = await run({ resource: 'analysis', operation: 'get', analysisId: 'A' }, [
			ok(fixtures.analysisCompletedUrl),
		]);
		expect(items[0].json).toMatchObject({
			itemType: 'url',
			itemId: expect.stringMatching(/^f5e8/),
		});
	});
});

const commentPage = {
	data: [
		{
			id: 'c1',
			type: 'comment',
			attributes: {
				text: 'bad',
				date: 1790000000,
				votes: { positive: 1, negative: 0, abuse: 0 },
				tags: ['malware'],
			},
		},
		{ id: 'c2', type: 'comment', attributes: { text: 'ok' } },
	],
};

describe('Comment', () => {
	it('Get Many lists comments of a URL using its encoded id', async () => {
		const { items, calls } = await run(
			{
				resource: 'comment',
				operation: 'getAll',
				objectType: 'url',
				objectId: 'http://www.example.com/',
				returnAll: false,
				limit: 10,
			},
			[ok(commentPage)],
		);
		expect(calls[0].url).toBe(
			'https://www.virustotal.com/api/v3/urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8/comments',
		);
		expect(items.map((i) => i.json.id)).toEqual(['c1', 'c2']);
		expect(items[0].json).toMatchObject({
			text: 'bad',
			date: new Date(1790000000 * 1000).toISOString(),
			tags: ['malware'],
		});
		expect(items[1].json).not.toHaveProperty('date');
	});

	it('Create posts the JSON:API body', async () => {
		const { items, calls } = await run(
			{
				resource: 'comment',
				operation: 'create',
				objectType: 'domain',
				objectId: 'Example.com',
				text: '  Phishing kit  ',
			},
			[
				ok({
					data: {
						id: 'c9',
						type: 'comment',
						attributes: { text: 'Phishing kit', date: 1790000000 },
					},
				}),
			],
		);
		expect(calls[0]).toMatchObject({
			method: 'POST',
			url: 'https://www.virustotal.com/api/v3/domains/example.com/comments',
			body: { data: { type: 'comment', attributes: { text: 'Phishing kit' } } },
		});
		expect(items[0].json).toMatchObject({
			id: 'c9',
			text: 'Phishing kit',
			objectType: 'domain',
			objectId: 'example.com',
		});
	});

	it('rejects an object id that does not match the object type', async () => {
		const { fn } = fakeExecute({
			params: [
				{
					resource: 'comment',
					operation: 'getAll',
					objectType: 'ip_address',
					objectId: 'example.com',
					returnAll: true,
				},
			],
			responses: [],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow('Not a valid IP address');
	});
});

describe('Vote', () => {
	it('Get Many lists votes', async () => {
		const { items } = await run(
			{
				resource: 'vote',
				operation: 'getAll',
				objectType: 'file',
				objectId: 'd41d8cd98f00b204e9800998ecf8427e',
				returnAll: false,
				limit: 5,
			},
			[
				ok({
					data: [
						{
							id: 'v1',
							type: 'vote',
							attributes: { verdict: 'malicious', date: 1790000000, value: -1 },
						},
					],
				}),
			],
		);
		expect(items[0].json).toMatchObject({ id: 'v1', verdict: 'malicious', value: -1 });
	});

	it('Create posts the vote body', async () => {
		const { items, calls } = await run(
			{
				resource: 'vote',
				operation: 'create',
				objectType: 'ip_address',
				objectId: '1.2.3.4',
				verdict: 'malicious',
			},
			[ok({ data: { id: 'v2', type: 'vote', attributes: { verdict: 'malicious' } } })],
		);
		expect(calls[0]).toMatchObject({
			method: 'POST',
			url: 'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/votes',
			body: { data: { type: 'vote', attributes: { verdict: 'malicious' } } },
		});
		expect(items[0].json).toMatchObject({ created: true, verdict: 'malicious' });
	});

	it('treats a duplicate vote (409) as success', async () => {
		const { items, calls } = await run(
			{
				resource: 'vote',
				operation: 'create',
				objectType: 'domain',
				objectId: 'example.com',
				verdict: 'harmless',
			},
			[ok({ error: { code: 'AlreadyExistsError', message: 'dup' } }, 409)],
		);
		expect(calls).toHaveLength(1);
		expect(items[0].json).toMatchObject({
			created: false,
			alreadyVoted: true,
			verdict: 'harmless',
		});
	});
});
