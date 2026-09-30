import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const run = (opts: Parameters<typeof fakeExecute>[0]) => {
	const { fn, calls } = fakeExecute(opts);
	return { promise: new VirusTotal().execute.call(fn), calls };
};

const base = { resource: 'indicator', operation: 'lookup', forceType: 'auto' };

describe('Indicator > Lookup', () => {
	it('detects a domain, calls the domain endpoint and returns a Summary', async () => {
		const { promise, calls } = run({
			params: [{ ...base, indicator: 'Example[.]com' }],
			responses: [{ statusCode: 200, body: fixtures.domain }],
		});
		const [[item]] = await promise;
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/domains/example.com');
		expect(item.json).toMatchObject({
			found: true,
			type: 'domain',
			indicator: 'example.com',
			verdict: 'clean',
		});
		expect(item.pairedItem).toEqual({ item: 0 });
	});

	it('looks up a URL by its base64url id', async () => {
		const { promise, calls } = run({
			params: [{ ...base, indicator: 'https://example.com/' }],
			responses: [{ statusCode: 200, body: fixtures.urlClean }],
		});
		await promise;
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8');
	});

	it('returns an unknown item for an unseen hash by default', async () => {
		const hash = 'd41d8cd98f00b204e9800998ecf8427e';
		const { promise } = run({
			params: [{ ...base, indicator: hash }],
			responses: [{ statusCode: 404, body: fixtures.errorNotFound }],
		});
		const [[item]] = await promise;
		expect(item.json).toEqual({ found: false, type: 'file', indicator: hash, verdict: 'unknown' });
	});

	it('throws when On Not Found is Throw Error', async () => {
		const { promise } = run({
			params: [
				{
					...base,
					indicator: 'd41d8cd98f00b204e9800998ecf8427e',
					options: { onNotFound: 'error' },
				},
			],
			responses: [{ statusCode: 404, body: fixtures.errorNotFound }],
		});
		await expect(promise).rejects.toThrow('was not found on VirusTotal');
	});

	it('returns the raw VirusTotal object when Output is Raw', async () => {
		const { promise } = run({
			params: [{ ...base, indicator: 'example.com', options: { output: 'raw' } }],
			responses: [{ statusCode: 200, body: fixtures.domain }],
		});
		const [[item]] = await promise;
		expect(item.json).toEqual(fixtures.domain.data);
	});

	it('honours Force Type', async () => {
		const { promise, calls } = run({
			params: [{ ...base, indicator: 'https://Sub.Example.com/x', forceType: 'domain' }],
			responses: [{ statusCode: 200, body: fixtures.domain }],
		});
		await promise;
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/domains/sub.example.com');
	});

	it('rejects input that is not an indicator without calling the API', async () => {
		const { promise, calls } = run({
			params: [{ ...base, indicator: 'not an ioc' }],
			responses: [],
		});
		await expect(promise).rejects.toThrow('is not a hash, URL, IP address or domain');
		expect(calls).toHaveLength(0);
	});

	it('turns per-item errors into items with continueOnFail and keeps pairing', async () => {
		const { promise } = run({
			params: [
				{ ...base, indicator: 'not an ioc' },
				{ ...base, indicator: 'example.com' },
			],
			responses: [{ statusCode: 200, body: fixtures.domain }],
			continueOnFail: true,
		});
		const [items] = await promise;
		expect(items[0].json).toMatchObject({ indicator: 'not an ioc' });
		expect(items[0].json.error).toContain('is not a hash');
		expect(items[0].pairedItem).toEqual({ item: 0 });
		expect(items[1].json).toMatchObject({ found: true });
		expect(items[1].pairedItem).toEqual({ item: 1 });
	});

	it('processes several items sequentially and includes the status code for API errors', async () => {
		const { promise } = run({
			params: [{ ...base, indicator: 'example.com' }],
			responses: [
				{ statusCode: 401, body: { error: { code: 'WrongCredentialsError', message: 'x' } } },
			],
			continueOnFail: true,
		});
		const [[item]] = await promise;
		expect(item.json).toMatchObject({
			error: 'Invalid or inactive VirusTotal API key',
			statusCode: 401,
		});
	});
});
