import { describe, expect, it } from 'vitest';
import { objectId, objectPath } from '../shared/objects';

describe('objectPath', () => {
	it('uses the collection for each type', () => {
		expect(objectPath('file', 'abc')).toBe('/files/abc');
		expect(objectPath('domain', 'example.com')).toBe('/domains/example.com');
		expect(objectPath('ip_address', '1.2.3.4')).toBe('/ip_addresses/1.2.3.4');
	});

	it('encodes URLs as base64url ids, never the raw URL', () => {
		expect(objectPath('url', 'http://www.example.com/')).toBe(
			'/urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8',
		);
		expect(objectId('url', 'http://a/')).not.toContain('/');
	});

	it('keeps IPv6 colons path-safe', () => {
		expect(objectPath('ip_address', '2001:db8::1')).toBe('/ip_addresses/2001%3Adb8%3A%3A1');
	});
});
