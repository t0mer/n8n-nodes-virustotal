import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const pages = () => [
	{ statusCode: 200, body: fixtures.relationshipPage1 },
	{ statusCode: 200, body: fixtures.relationshipPage2 },
];

async function run(
	params: Record<string, unknown>,
	responses: Array<{ statusCode: number; body: unknown }>,
) {
	const { fn, calls } = fakeExecute({ params: [params], responses });
	const [items] = await new VirusTotal().execute.call(fn);
	return { items, calls };
}

describe('Get Related', () => {
	it('returns all pages as summarized items, all paired with the input item', async () => {
		const { items, calls } = await run(
			{
				resource: 'domain',
				operation: 'getRelated',
				domain: 'example.com',
				relationship: 'subdomains',
				returnAll: true,
			},
			pages(),
		);
		expect(items.map((i) => i.json.id)).toEqual([
			'a.example.com',
			'b.example.com',
			'c.example.com',
		]);
		expect(items[0].json).toMatchObject({ found: true, type: 'domain' });
		expect(items.every((i) => i.pairedItem && (i.pairedItem as { item: number }).item === 0)).toBe(
			true,
		);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/domains/example.com/subdomains');
		expect(calls).toHaveLength(2);
	});

	it('honours Limit', async () => {
		const { items, calls } = await run(
			{
				resource: 'domain',
				operation: 'getRelated',
				domain: 'example.com',
				relationship: 'subdomains',
				returnAll: false,
				limit: 1,
			},
			pages(),
		);
		expect(items).toHaveLength(1);
		expect(calls).toHaveLength(1);
	});

	it('Raw output leaves objects unchanged', async () => {
		const { items } = await run(
			{
				resource: 'domain',
				operation: 'getRelated',
				domain: 'example.com',
				relationship: 'subdomains',
				returnAll: true,
				output: 'raw',
			},
			pages(),
		);
		expect(items[0].json).toEqual(fixtures.relationshipPage1.data[0]);
	});

	it('flattens non-indicator objects such as resolutions', async () => {
		const { items } = await run(
			{
				resource: 'domain',
				operation: 'getDnsResolutions',
				domain: 'example.com',
				returnAll: false,
				limit: 5,
			},
			[
				{
					statusCode: 200,
					body: {
						data: [
							{ id: 'r1', type: 'resolution', attributes: { ip_address: '1.2.3.4', date: 1 } },
						],
					},
				},
			],
		);
		expect(items[0].json).toEqual({ id: 'r1', type: 'resolution', ip_address: '1.2.3.4', date: 1 });
	});

	it('addresses the right collection for files, URLs and IPs', async () => {
		const empty = { statusCode: 200, body: { data: [] } };
		const f = await run(
			{
				resource: 'file',
				operation: 'getRelated',
				hash: 'd41d8cd98f00b204e9800998ecf8427e',
				relationship: 'contacted_domains',
				returnAll: false,
				limit: 5,
			},
			[empty],
		);
		expect(f.calls[0].url).toBe(
			'https://www.virustotal.com/api/v3/files/d41d8cd98f00b204e9800998ecf8427e/contacted_domains',
		);
		const u = await run(
			{
				resource: 'url',
				operation: 'getRelated',
				url: 'http://www.example.com/',
				relationship: 'downloaded_files',
				returnAll: false,
				limit: 5,
			},
			[empty],
		);
		expect(u.calls[0].url).toBe(
			'https://www.virustotal.com/api/v3/urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8/downloaded_files',
		);
		const ip = await run(
			{
				resource: 'ip',
				operation: 'getRelated',
				ip: '1.2.3.4',
				relationship: 'resolutions',
				returnAll: false,
				limit: 5,
			},
			[empty],
		);
		expect(ip.calls[0].url).toBe(
			'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/resolutions',
		);
	});

	it('explains that a forbidden relationship needs Premium', async () => {
		const { fn } = fakeExecute({
			params: [
				{
					resource: 'file',
					operation: 'getRelated',
					hash: 'd41d8cd98f00b204e9800998ecf8427e',
					relationship: 'similar_files',
					returnAll: false,
					limit: 5,
				},
			],
			responses: [{ statusCode: 403, body: { error: { code: 'ForbiddenError', message: 'no' } } }],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow(
			'The "similar_files" relationship requires a Premium VirusTotal API key',
		);
	});

	it('still surfaces other API errors', async () => {
		const { fn } = fakeExecute({
			params: [
				{
					resource: 'ip',
					operation: 'getRelated',
					ip: '1.2.3.4',
					relationship: 'resolutions',
					returnAll: false,
					limit: 5,
				},
			],
			responses: [
				{ statusCode: 401, body: { error: { code: 'WrongCredentialsError', message: 'x' } } },
			],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow(
			'Invalid or inactive VirusTotal API key',
		);
	});
});
