import { describe, expect, it } from 'vitest';
import { urlId } from '../shared/urlId';

describe('urlId', () => {
	it("matches VirusTotal's documented example", () => {
		expect(urlId('http://www.example.com/')).toBe('aHR0cDovL3d3dy5leGFtcGxlLmNvbS8');
	});

	it('has no padding', () => {
		expect(urlId('http://a.co/')).not.toContain('=');
	});

	it('uses the url-safe alphabet', () => {
		const id = urlId('http://example.com/?q=>>>???');
		expect(id).not.toMatch(/[+/=]/);
	});

	it('round-trips', () => {
		const url = 'https://example.com/päth?x=1&y=ü';
		expect(Buffer.from(urlId(url), 'base64url').toString('utf8')).toBe(url);
	});
});
