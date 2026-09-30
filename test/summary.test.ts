import { describe, expect, it } from 'vitest';
import { isoFromEpoch, summarize, unknownItem } from '../shared/summary';
import { fixtures } from './fixtures';

// 2026-01-30T00:00:00Z
const NOW = Date.UTC(2026, 0, 30);
const opts = (indicator: string, extra = {}) => ({ indicator, now: () => NOW, ...extra });

describe('summarize: common fields', () => {
	const s = summarize('file', fixtures.fileMalicious, opts('275a'));

	it('builds the normalized shape', () => {
		expect(s).toMatchObject({
			found: true,
			type: 'file',
			indicator: '275a',
			id: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
			verdict: 'malicious',
			detectionRatio: '62/71',
			reputation: -42,
			votes: { harmless: 3, malicious: 210 },
			tags: ['eicar', 'text'],
		});
		expect(s.stats).toMatchObject({
			malicious: 62,
			suspicious: 1,
			harmless: 0,
			undetected: 8,
			timeout: 0,
		});
		expect(s.permalink).toBe(
			'https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
		);
	});

	it('converts epoch seconds to ISO strings', () => {
		expect(s.lastAnalysisDate).toBe(new Date(1790000000 * 1000).toISOString());
		expect(s.firstSubmissionDate).toBe('2008-01-10T21:20:00.000Z');
	});
});

describe('summarize: per type', () => {
	it('file extras', () => {
		const s = summarize('file', fixtures.fileMalicious, opts('x'));
		expect(s).toMatchObject({
			sha256: expect.any(String),
			sha1: 'cf8bd9dfddff007f75adf4c2be48005cea317c62',
			md5: '69630e4574ec6798239b091cda43dca0',
			meaningfulName: 'eicar.com',
			size: 68,
			typeDescription: 'Text',
			typeTag: 'text',
			timesSubmitted: 123456,
			popularThreatLabel: 'virus.eicar/test',
			sandboxVerdicts: [
				{
					sandbox: 'Zenbox',
					category: 'malicious',
					malwareClassification: ['MALWARE'],
					malwareNames: ['EICAR'],
				},
			],
		});
		expect(s.names).toHaveLength(10);
	});

	it('url extras and clean verdict', () => {
		const s = summarize('url', fixtures.urlClean, opts('https://example.com/'));
		expect(s).toMatchObject({
			verdict: 'clean',
			url: 'https://example.com/',
			finalUrl: 'https://www.example.com/',
			title: 'Example Domain',
			categories: ['information technology'],
			lastHttpResponseCode: 200,
		});
	});

	it('domain extras with certificate expiry', () => {
		const s = summarize('domain', fixtures.domain, opts('example.com'));
		expect(s).toMatchObject({
			registrar: 'RESERVED-Internet Assigned Numbers Authority',
			creationDate: '1992-01-01T00:00:00.000Z',
			categories: ['information technology', 'Business/Economy'],
			lastDnsRecords: [
				{ type: 'A', value: '93.184.216.34' },
				{ type: 'MX', value: 'mail.example.com' },
			],
			lastHttpsCertificate: {
				issuer: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
				subject: 'www.example.org',
				notAfter: '2026-03-01T23:59:59.000Z',
				daysUntilExpiry: 30,
			},
		});
		expect(s.lastDnsRecords).toEqual([
			{ type: 'A', value: '93.184.216.34' },
			{ type: 'MX', value: 'mail.example.com' },
		]);
		expect(s.permalink).toBe('https://www.virustotal.com/gui/domain/example.com');
	});

	it('IPv6 extras and suspicious verdict', () => {
		const s = summarize('ip_address', fixtures.ipV6, opts('2606:4700:4700::1111'));
		expect(s).toMatchObject({
			verdict: 'suspicious',
			asn: 13335,
			asOwner: 'CLOUDFLARENET',
			country: 'US',
			network: '2606:4700:4700::/48',
			regionalInternetRegistry: 'ARIN',
		});
		expect(s.permalink).toBe('https://www.virustotal.com/gui/ip-address/2606:4700:4700::1111');
	});
});

describe('summarize: engines and thresholds', () => {
	it('includes only non-clean engines when asked', () => {
		const s = summarize('file', fixtures.fileMalicious, opts('x', { includeEngines: true }));
		expect(s.engines).toEqual([
			{ engine: 'Kaspersky', category: 'malicious', result: 'EICAR-Test-File' },
			{ engine: 'Sophos', category: 'suspicious', result: 'Generic PUA' },
		]);
	});

	it('omits engines by default', () => {
		expect(summarize('file', fixtures.fileMalicious, opts('x'))).not.toHaveProperty('engines');
	});

	it('applies custom thresholds', () => {
		const s = summarize(
			'file',
			fixtures.fileMalicious,
			opts('x', { thresholds: { malicious: 100, suspicious: 100 } }),
		);
		expect(s.verdict).toBe('clean');
	});
});

describe('summarize: missing data', () => {
	it('returns the unknown item for null (404)', () => {
		expect(summarize('file', null, opts('abc'))).toEqual({
			found: false,
			type: 'file',
			indicator: 'abc',
			verdict: 'unknown',
		});
		expect(unknownItem('url', 'u').verdict).toBe('unknown');
	});

	it('tolerates an object with no attributes and emits no undefined keys', () => {
		const s = summarize('domain', { data: { id: 'a.com', type: 'domain' } }, opts('a.com'));
		expect(s).toMatchObject({ found: true, verdict: 'unknown', detectionRatio: '0/0', tags: [] });
		expect(Object.values(s)).not.toContain(undefined);
		expect(s).not.toHaveProperty('reputation');
		expect(s).not.toHaveProperty('registrar');
		expect(s).not.toHaveProperty('lastHttpsCertificate');
	});

	it('tolerates wrongly typed attributes', () => {
		const s = summarize(
			'file',
			{
				data: {
					id: 'x',
					attributes: {
						names: 'nope',
						last_analysis_date: 'soon',
						total_votes: 5,
						sandbox_verdicts: [],
					},
				},
			},
			opts('x'),
		);
		expect(s).toMatchObject({ found: true });
		expect(s).not.toHaveProperty('lastAnalysisDate');
		expect(s).not.toHaveProperty('votes');
	});
});

describe('isoFromEpoch', () => {
	it('handles missing and invalid values', () => {
		expect(isoFromEpoch(undefined)).toBeUndefined();
		expect(isoFromEpoch('1')).toBeUndefined();
		expect(isoFromEpoch(0)).toBe('1970-01-01T00:00:00.000Z');
	});
});
