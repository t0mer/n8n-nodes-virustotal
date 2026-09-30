import { describe, expect, it } from 'vitest';
import {
	DIRECT_UPLOAD_LIMIT,
	MAX_UPLOAD_SIZE,
	buildMultipart,
	sha256Hex,
	uploadFile,
	uploadRoute,
} from '../shared/upload';
import { fakeContext } from './helpers';
import { fixtures } from './fixtures';

const EICAR = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const submitted = { statusCode: 200, body: { data: { type: 'analysis', id: 'ANALYSIS1' } } };
const notFound = { statusCode: 404, body: fixtures.errorNotFound };

describe('uploadRoute', () => {
	it('picks the route by size', () => {
		expect(uploadRoute(1)).toBe('direct');
		expect(uploadRoute(DIRECT_UPLOAD_LIMIT)).toBe('direct');
		expect(uploadRoute(DIRECT_UPLOAD_LIMIT + 1)).toBe('upload_url');
		expect(uploadRoute(MAX_UPLOAD_SIZE)).toBe('upload_url');
		expect(uploadRoute(MAX_UPLOAD_SIZE + 1)).toBe('too_large');
	});
});

describe('sha256Hex', () => {
	it('hashes the EICAR test file to its well-known digest', () => {
		expect(sha256Hex(EICAR)).toBe(EICAR_SHA256);
	});
});

describe('buildMultipart', () => {
	const m = buildMultipart(
		{ field: 'file', fileName: 'a"b.txt', data: Buffer.from('HELLO') },
		{ password: 'pw' },
		'BOUND',
	);

	it('declares the boundary in the content type', () => {
		expect(m.contentType).toBe('multipart/form-data; boundary=BOUND');
	});

	it('has a well-formed body with the password field and the file part', () => {
		const text = m.body.toString();
		expect(text).toBe(
			[
				'--BOUND',
				'Content-Disposition: form-data; name="password"',
				'',
				'pw',
				'--BOUND',
				'Content-Disposition: form-data; name="file"; filename="a_b.txt"',
				'Content-Type: application/octet-stream',
				'',
				'HELLO',
				'--BOUND--',
				'',
			].join('\r\n'),
		);
	});

	it('keeps binary data intact', () => {
		const bytes = Buffer.from([0, 255, 13, 10, 1, 2]);
		const b = buildMultipart({ field: 'file', fileName: 'x', data: bytes }, {}, 'B').body;
		expect(b.includes(bytes)).toBe(true);
	});
});

describe('uploadFile', () => {
	it('skips the upload when the hash is already known (hash-first)', async () => {
		const { ctx, calls } = fakeContext([{ statusCode: 200, body: fixtures.fileMalicious }]);
		const result = await uploadFile(ctx, {
			data: EICAR,
			fileName: 'eicar.com',
			checkHashFirst: true,
		});
		expect(result).toMatchObject({ kind: 'existing', sha256: EICAR_SHA256 });
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe(`https://www.virustotal.com/api/v3/files/${EICAR_SHA256}`);
	});

	it('uploads directly when the hash is unknown', async () => {
		const { ctx, calls } = fakeContext([notFound, submitted]);
		const result = await uploadFile(ctx, {
			data: EICAR,
			fileName: 'eicar.com',
			checkHashFirst: true,
		});
		expect(result).toEqual({ kind: 'submitted', sha256: EICAR_SHA256, analysisId: 'ANALYSIS1' });
		expect(calls[1]).toMatchObject({
			method: 'POST',
			url: 'https://www.virustotal.com/api/v3/files',
		});
		expect((calls[1].headers as Record<string, string>)['content-type']).toMatch(
			/^multipart\/form-data; boundary=/,
		);
		expect(Buffer.isBuffer(calls[1].body)).toBe(true);
	});

	it('uploads without a lookup when hash-first is off', async () => {
		const { ctx, calls } = fakeContext([submitted]);
		await uploadFile(ctx, { data: EICAR, fileName: 'e', checkHashFirst: false });
		expect(calls).toHaveLength(1);
		expect(calls[0].method).toBe('POST');
	});

	it('sends the password for zipped samples', async () => {
		const { ctx, calls } = fakeContext([submitted]);
		await uploadFile(ctx, {
			data: EICAR,
			fileName: 'e.zip',
			password: 'infected',
			checkHashFirst: false,
		});
		expect((calls[0].body as Buffer).toString()).toContain('name="password"\r\n\r\ninfected');
	});

	it('uses the pre-authorized upload_url flow above 32 MB, without the API key', async () => {
		const big = Buffer.alloc(DIRECT_UPLOAD_LIMIT + 1);
		const { ctx, calls } = fakeContext([
			{ statusCode: 200, body: { data: 'https://upload.virustotal.example/once/abc' } },
			submitted,
		]);
		const result = await uploadFile(ctx, { data: big, fileName: 'big.bin', checkHashFirst: false });
		expect(result).toMatchObject({ kind: 'submitted', analysisId: 'ANALYSIS1' });
		expect(calls[0].url).toBe('https://www.virustotal.com/api/v3/files/upload_url');
		expect(calls[1].url).toBe('https://upload.virustotal.example/once/abc');
		expect(ctx.helpers.httpRequest).toHaveBeenCalledTimes(1);
		expect(ctx.helpers.httpRequestWithAuthentication).toHaveBeenCalledTimes(1);
	});

	it('rejects files over 650 MB before uploading', async () => {
		const { ctx, calls } = fakeContext([]);
		const huge = Buffer.alloc(MAX_UPLOAD_SIZE + 1);
		await expect(
			uploadFile(ctx, { data: huge, fileName: 'huge', checkHashFirst: false }),
		).rejects.toThrow('larger than 650 MB');
		expect(calls).toHaveLength(0);
	}, 30000);

	it('fails clearly when no analysis id comes back', async () => {
		const { ctx } = fakeContext([{ statusCode: 200, body: { data: {} } }]);
		await expect(
			uploadFile(ctx, { data: EICAR, fileName: 'e', checkHashFirst: false }),
		).rejects.toThrow('analysis ID');
	});
});
