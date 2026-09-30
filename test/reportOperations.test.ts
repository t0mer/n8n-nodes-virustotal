import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

async function run(params: Record<string, unknown>, body: unknown, statusCode = 200) {
	const { fn, calls } = fakeExecute({ params: [params], responses: [{ statusCode, body }] });
	const [[item]] = await new VirusTotal().execute.call(fn);
	return { json: item.json, calls };
}

describe('Get Report operations', () => {
	it('File: GET /files/{hash}', async () => {
		const { json, calls } = await run(
			{ resource: 'file', operation: 'getReport', hash: SHA256.toUpperCase() },
			fixtures.fileMalicious,
		);
		expect(calls[0].url).toBe(`https://www.virustotal.com/api/v3/files/${SHA256}`);
		expect(json).toMatchObject({ type: 'file', verdict: 'malicious', sha256: SHA256 });
	});

	it('File: rejects a non-hash', async () => {
		const { fn } = fakeExecute({
			params: [{ resource: 'file', operation: 'getReport', hash: 'example.com' }],
			responses: [],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow(
			'Not a valid MD5, SHA-1 or SHA-256 hash',
		);
	});

	it('URL: computes the base64url id', async () => {
		const { json, calls } = await run(
			{ resource: 'url', operation: 'getReport', url: 'hxxps://example[.]com/' },
			fixtures.urlClean,
		);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8');
		expect(json).toMatchObject({
			type: 'url',
			verdict: 'clean',
			indicator: 'https://example.com/',
		});
	});

	it('Domain: GET /domains/{domain}', async () => {
		const { json, calls } = await run(
			{ resource: 'domain', operation: 'getReport', domain: 'Example.com' },
			fixtures.domain,
		);
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/domains/example.com');
		expect(json).toMatchObject({ type: 'domain', registrar: expect.any(String) });
	});

	it('IP: supports IPv6', async () => {
		const { json, calls } = await run(
			{ resource: 'ip', operation: 'getReport', ip: '2606:4700:4700::1111' },
			fixtures.ipV6,
		);
		expect(calls[0].url).toBe(
			'https://www.virustotal.com/api/v3/ip_addresses/2606%3A4700%3A4700%3A%3A1111',
		);
		expect(json).toMatchObject({ type: 'ip_address', asOwner: 'CLOUDFLARENET' });
	});

	it('IP: rejects a domain', async () => {
		const { fn } = fakeExecute({
			params: [{ resource: 'ip', operation: 'getReport', ip: 'example.com' }],
			responses: [],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow('Not a valid IP address');
	});

	it('an unseen object returns an unknown item', async () => {
		const { json } = await run(
			{ resource: 'domain', operation: 'getReport', domain: 'nothing-here.example' },
			fixtures.errorNotFound,
			404,
		);
		expect(json).toEqual({
			found: false,
			type: 'domain',
			indicator: 'nothing-here.example',
			verdict: 'unknown',
		});
	});
});
