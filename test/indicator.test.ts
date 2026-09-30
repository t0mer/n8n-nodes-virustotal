import { describe, expect, it } from 'vitest';
import { detectIndicator, refang } from '../shared/indicator';

const MD5 = 'd41d8cd98f00b204e9800998ecf8427e';
const SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
const SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function ok(input: string, force?: Parameters<typeof detectIndicator>[1]) {
	const r = detectIndicator(input, force);
	if (!r.ok) throw new Error(`expected ok, got: ${r.reason}`);
	return r;
}

describe('refang', () => {
	it.each([
		['hxxp://example[.]com', 'http://example.com'],
		['hxxps://example[.]com/a', 'https://example.com/a'],
		['HXXPS://Example(.)com', 'https://Example.com'],
		['hxxp[:]//evil[.]com', 'http://evil.com'],
		['hxxp[://]evil[.]com', 'http://evil.com'],
		['1.2.3[.]4', '1.2.3.4'],
		['example[dot]com', 'example.com'],
		['fxp://a[.]b', 'ftp://a.b'],
		['  spaced.com  ', 'spaced.com'],
	])('%s -> %s', (input, expected) => expect(refang(input)).toBe(expected));
});

describe('detectIndicator: hashes', () => {
	it.each([
		['MD5', MD5],
		['SHA-1', SHA1],
		['SHA-256', SHA256],
	])('detects %s as file', (_n, hash) => {
		expect(ok(hash)).toMatchObject({ type: 'file', indicator: hash });
	});

	it('lowercases hashes', () => {
		expect(ok(SHA256.toUpperCase()).indicator).toBe(SHA256);
	});

	it('does not treat a wrong-length hex string as a hash', () => {
		expect(detectIndicator('abcdef12').ok).toBe(false);
	});
});

describe('detectIndicator: urls', () => {
	it('detects http and https URLs', () => {
		expect(ok('https://example.com/a?b=1')).toMatchObject({
			type: 'url',
			indicator: 'https://example.com/a?b=1',
		});
	});

	it('refangs defanged URLs and reports it', () => {
		expect(ok('hxxp://evil[.]com/x')).toMatchObject({
			type: 'url',
			indicator: 'http://evil.com/x',
			refanged: true,
		});
	});

	it('treats a host with a path as a URL and adds http://', () => {
		expect(ok('example.com/login')).toMatchObject({
			type: 'url',
			indicator: 'http://example.com/login',
		});
	});

	it('keeps case in the path', () => {
		expect(ok('http://Example.com/AbC').indicator).toBe('http://Example.com/AbC');
	});
});

describe('detectIndicator: ips', () => {
	it.each(['1.2.3.4', '255.255.255.255', '0.0.0.0'])('IPv4 %s', (ip) => {
		expect(ok(ip)).toMatchObject({ type: 'ip_address', indicator: ip });
	});

	it('refangs IPs', () => {
		expect(ok('1.2.3[.]4')).toMatchObject({
			type: 'ip_address',
			indicator: '1.2.3.4',
			refanged: true,
		});
	});

	it.each([
		'2001:db8::1',
		'::1',
		'::',
		'fe80::1',
		'2001:0db8:0000:0000:0000:ff00:0042:8329',
		'::ffff:192.168.1.1',
		'2001:db8:85a3::8a2e:370:7334',
	])('IPv6 %s', (ip) => {
		expect(ok(ip)).toMatchObject({ type: 'ip_address', indicator: ip });
	});

	it('strips IPv6 brackets', () => {
		expect(ok('[2001:db8::1]').indicator).toBe('2001:db8::1');
	});

	it.each(['256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4'])('rejects bad IPv4 %s as an IP', (v) => {
		const r = detectIndicator(v);
		expect(r.ok && r.type === 'ip_address').toBe(false);
	});

	it.each(['1::2::3', '12345::1', '1:2:3:4:5:6:7:8:9', 'g::1'])('rejects bad IPv6 %s', (v) => {
		expect(detectIndicator(v).ok).toBe(false);
	});
});

describe('detectIndicator: domains', () => {
	it('detects and lowercases domains', () => {
		expect(ok('Example.COM')).toMatchObject({ type: 'domain', indicator: 'example.com' });
	});

	it('refangs domains', () => {
		expect(ok('example[.]com')).toMatchObject({
			type: 'domain',
			indicator: 'example.com',
			refanged: true,
		});
	});

	it('strips a trailing dot', () => {
		expect(ok('example.com.').indicator).toBe('example.com');
	});

	it('converts IDN domains to punycode', () => {
		expect(ok('bücher.de')).toMatchObject({ type: 'domain', indicator: 'xn--bcher-kva.de' });
	});

	it('accepts punycode TLDs', () => {
		expect(ok('example.xn--p1ai').type).toBe('domain');
	});

	it.each(['localhost', 'not a domain', 'foo.123', '-bad.com', 'a..b.com'])('rejects %s', (v) => {
		expect(detectIndicator(v).ok).toBe(false);
	});

	it('rejects empty input', () => {
		expect(detectIndicator('   ').ok).toBe(false);
	});
});

describe('detectIndicator: force type', () => {
	it('forces a hash', () => {
		expect(ok(MD5, 'file').type).toBe('file');
		expect(detectIndicator('example.com', 'file').ok).toBe(false);
	});

	it('forces a domain from a URL', () => {
		expect(ok('https://Sub.Example.com/path', 'domain')).toMatchObject({
			type: 'domain',
			indicator: 'sub.example.com',
		});
	});

	it('forces a URL on a bare host', () => {
		expect(ok('example.com', 'url')).toMatchObject({
			type: 'url',
			indicator: 'http://example.com',
		});
	});

	it('forces an IP and rejects non-IPs', () => {
		expect(ok('1.2.3.4', 'ip_address').type).toBe('ip_address');
		expect(detectIndicator('example.com', 'ip_address').ok).toBe(false);
	});

	it('resolves a string that is both hex and could be a name', () => {
		// 32 hex chars: auto says file, force domain refuses because it has no dot.
		expect(ok(MD5).type).toBe('file');
		expect(detectIndicator(MD5, 'domain').ok).toBe(false);
	});
});
