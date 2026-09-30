import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const EICAR = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const ok = (body: unknown) => ({ statusCode: 200, body });
const notFound = { statusCode: 404, body: fixtures.errorNotFound };
const submitted = ok({ data: { type: 'analysis', id: 'ANALYSIS1' } });
const fast = { pollIntervalSeconds: 0.001 };

async function run(
	params: Record<string, unknown>,
	responses: Array<{ statusCode: number; body: unknown }>,
	binary?: Record<string, Buffer>,
) {
	const { fn, calls } = fakeExecute({ params: [params], responses, binary });
	const [[item]] = await new VirusTotal().execute.call(fn);
	return { json: item.json, calls };
}

describe('URL > Scan', () => {
	const params = { resource: 'url', operation: 'scan', url: 'https://example.com/' };

	it('submits form-encoded, waits for completion and returns the report', async () => {
		const { json, calls } = await run({ ...params, mode: 'wait', scanOptions: fast }, [
			submitted,
			ok(fixtures.analysisQueued),
			ok(fixtures.analysisCompletedUrl),
			ok(fixtures.urlClean),
		]);
		expect(calls[0]).toMatchObject({
			method: 'POST',
			url: 'https://www.virustotal.com/api/v3/urls',
			body: { url: 'https://example.com/' },
		});
		expect((calls[0].headers as Record<string, string>)['content-type']).toBe(
			'application/x-www-form-urlencoded',
		);
		expect(calls[1].url).toBe('https://www.virustotal.com/api/v3/analyses/ANALYSIS1');
		expect(calls[3].url).toBe(
			'https://www.virustotal.com/api/v3/urls/f5e8b8c3d0a7c2e6a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901234ab',
		);
		expect(json).toMatchObject({
			found: true,
			type: 'url',
			verdict: 'clean',
			analysisId: 'ANALYSIS1',
		});
	});

	it('Submit Only returns the analysis id at once', async () => {
		const { json, calls } = await run({ ...params, mode: 'submit' }, [submitted]);
		expect(calls).toHaveLength(1);
		expect(json).toMatchObject({ type: 'url', analysisId: 'ANALYSIS1', status: 'submitted' });
		expect(json.permalink).toMatch(/^https:\/\/www\.virustotal\.com\/gui\/url\/[a-f0-9]{64}$/);
	});
});

describe('URL > Rescan', () => {
	it('POSTs to /urls/{id}/analyse', async () => {
		const { json, calls } = await run(
			{ resource: 'url', operation: 'rescan', url: 'http://www.example.com/', mode: 'submit' },
			[submitted],
		);
		expect(calls[0]).toMatchObject({
			method: 'POST',
			url: 'https://www.virustotal.com/api/v3/urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8/analyse',
		});
		expect(json.analysisId).toBe('ANALYSIS1');
	});
});

describe('File > Scan', () => {
	const params = {
		resource: 'file',
		operation: 'scan',
		binaryPropertyName: 'data',
		checkHashFirst: true,
	};

	it('skips the upload for a known hash and says so', async () => {
		const { json, calls } = await run({ ...params, mode: 'wait' }, [ok(fixtures.fileMalicious)], {
			data: EICAR,
		});
		expect(calls).toHaveLength(1);
		expect(json).toMatchObject({
			found: true,
			verdict: 'malicious',
			uploaded: false,
			analysisId: null,
		});
	});

	it('Submit Only on a known file keeps the same keys, with analysisId null', async () => {
		const { json, calls } = await run({ ...params, mode: 'submit' }, [ok(fixtures.fileMalicious)], {
			data: EICAR,
		});
		expect(calls).toHaveLength(1);
		expect(json).toMatchObject({ uploaded: false, analysisId: null, verdict: 'malicious' });
	});

	it('uploads an unknown file, waits and returns the report', async () => {
		const { json, calls } = await run(
			{ ...params, mode: 'wait', scanOptions: fast },
			[notFound, submitted, ok(fixtures.analysisCompleted), ok(fixtures.fileMalicious)],
			{ data: EICAR },
		);
		expect(calls[1]).toMatchObject({
			method: 'POST',
			url: 'https://www.virustotal.com/api/v3/files',
		});
		expect(calls[3].url).toBe(`https://www.virustotal.com/api/v3/files/${EICAR_SHA256}`);
		expect(json).toMatchObject({ verdict: 'malicious', uploaded: true, analysisId: 'ANALYSIS1' });
	});

	it('Submit Only returns the analysis id and hash', async () => {
		const { json } = await run({ ...params, mode: 'submit', checkHashFirst: false }, [submitted], {
			data: EICAR,
		});
		expect(json).toMatchObject({
			type: 'file',
			indicator: EICAR_SHA256,
			analysisId: 'ANALYSIS1',
			uploaded: true,
			status: 'submitted',
		});
	});

	it('fails clearly when the binary property is missing', async () => {
		const { fn } = fakeExecute({
			params: [{ ...params, mode: 'submit', binaryPropertyName: 'nope' }],
			responses: [],
		});
		await expect(new VirusTotal().execute.call(fn)).rejects.toThrow('no binary data "nope"');
	});
});

describe('File > Rescan', () => {
	it('POSTs to /files/{hash}/analyse', async () => {
		const { json, calls } = await run(
			{ resource: 'file', operation: 'rescan', hash: EICAR_SHA256, mode: 'submit' },
			[submitted],
		);
		expect(calls[0]).toMatchObject({
			method: 'POST',
			url: `https://www.virustotal.com/api/v3/files/${EICAR_SHA256}/analyse`,
		});
		expect(json).toMatchObject({ analysisId: 'ANALYSIS1', indicator: EICAR_SHA256 });
	});
});
