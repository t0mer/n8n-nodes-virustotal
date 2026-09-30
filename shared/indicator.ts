export type IndicatorType = 'file' | 'url' | 'domain' | 'ip_address';
export type ForceType = 'auto' | IndicatorType;

export interface Indicator {
	ok: true;
	type: IndicatorType;
	/** Refanged and normalized value; this is what is sent to VirusTotal. */
	indicator: string;
	/** True when the input had to be refanged. */
	refanged: boolean;
}

export interface IndicatorError {
	ok: false;
	reason: string;
}

export type IndicatorResult = Indicator | IndicatorError;

const HASH_LENGTHS = [32, 40, 64];

/** Turns defanged input such as `hxxp://example[.]com` back into a real indicator. */
export function refang(input: string): string {
	return input
		.trim()
		.replace(/^h(?:xx|tt)p(s?)(?=\[?:|:)/i, (_m, s: string) => `http${s.toLowerCase()}`)
		.replace(/^fxp(?=:)/i, 'ftp')
		.replace(/\[:\/\/\]|\(:\/\/\)/g, '://')
		.replace(/\[:\]|\(:\)/g, ':')
		.replace(/\[\/\]|\(\/\)/g, '/')
		.replace(/\[@\]|\(@\)/g, '@')
		.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}/gi, '.');
}

export function isHash(value: string): boolean {
	return HASH_LENGTHS.includes(value.length) && /^[a-f0-9]+$/i.test(value);
}

export function isIPv4(value: string): boolean {
	const parts = value.split('.');
	return (
		parts.length === 4 &&
		parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === '0' || !p.startsWith('0')))
	);
}

export function isIPv6(raw: string): boolean {
	const value = raw.replace(/^\[|\]$/g, '');
	if (!value.includes(':') || /[^0-9a-f:.]/i.test(value)) return false;
	if ((value.match(/::/g) ?? []).length > 1 || /:::/.test(value)) return false;

	let groups = value.split(':');
	let needed = 8;
	const last = groups[groups.length - 1];
	if (last.includes('.')) {
		if (!isIPv4(last)) return false;
		groups = groups.slice(0, -1);
		needed = 6;
		if (value.endsWith('::' + last)) groups.push('');
	}

	const compressed = value.includes('::');
	const filled = groups.filter((g) => g !== '');
	if (!filled.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
	if (!compressed) return groups.length === needed && groups.every((g) => g !== '');
	return filled.length < needed;
}

export function isIp(value: string): boolean {
	return isIPv4(value) || isIPv6(value);
}

/** Lowercases and converts internationalized names to punycode. Returns null if invalid. */
function normalizeHostname(value: string): string | null {
	const host = value.trim().replace(/\.$/, '');
	if (!host || /[\s/?#@:]/.test(host)) return null;
	let ascii: string;
	try {
		ascii = new URL(`http://${host}`).hostname;
	} catch {
		return null;
	}
	ascii = ascii.toLowerCase();
	const labels = ascii.split('.');
	const validLabels = labels.every((l) => /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l));
	const tld = labels[labels.length - 1];
	const validTld = /^[a-z]{2,}$/.test(tld) || /^xn--[a-z0-9-]+$/.test(tld);
	return labels.length >= 2 && validLabels && validTld && ascii.length <= 253 ? ascii : null;
}

function hostnameFromUrl(value: string): string | null {
	try {
		return new URL(value).hostname || null;
	} catch {
		return null;
	}
}

function hasScheme(value: string): boolean {
	return /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
}

function fail(reason: string): IndicatorError {
	return { ok: false, reason };
}

function done(type: IndicatorType, indicator: string, refanged: boolean): Indicator {
	return { ok: true, type, indicator, refanged };
}

/**
 * Detects what kind of indicator `input` is, after refanging it.
 * Detection order: hash, URL, IP, domain. `force` overrides detection for ambiguous input.
 */
export function detectIndicator(input: string, force: ForceType = 'auto'): IndicatorResult {
	const trimmed = (input ?? '').trim();
	if (!trimmed) return fail('The indicator is empty');

	const value = refang(trimmed);
	const refanged = value !== trimmed;

	if (force === 'file') {
		return isHash(value)
			? done('file', value.toLowerCase(), refanged)
			: fail('Not a valid MD5, SHA-1 or SHA-256 hash');
	}
	if (force === 'ip_address') {
		const ip = value.replace(/^\[|\]$/g, '');
		return isIp(ip)
			? done('ip_address', ip.toLowerCase(), refanged)
			: fail('Not a valid IP address');
	}
	if (force === 'domain') {
		const host = hasScheme(value) ? hostnameFromUrl(value) : value;
		const normalized = host ? normalizeHostname(host) : null;
		return normalized ? done('domain', normalized, refanged) : fail('Not a valid domain name');
	}
	if (force === 'url') {
		const url = hasScheme(value) ? value : `http://${value}`;
		return hostnameFromUrl(url) ? done('url', url, refanged) : fail('Not a valid URL');
	}

	if (isHash(value)) return done('file', value.toLowerCase(), refanged);
	if (hasScheme(value)) {
		return hostnameFromUrl(value) ? done('url', value, refanged) : fail('Not a valid URL');
	}
	const bareIp = value.replace(/^\[|\]$/g, '');
	if (isIp(bareIp)) return done('ip_address', bareIp.toLowerCase(), refanged);

	const domain = normalizeHostname(value);
	if (domain) return done('domain', domain, refanged);

	// A host with a path or query but no scheme, such as `example.com/login`.
	if (/^[^/?#\s]+[/?#]/.test(value)) {
		const url = `http://${value}`;
		const host = hostnameFromUrl(url);
		if (host && (isIp(host.replace(/^\[|\]$/g, '')) || normalizeHostname(host))) {
			return done('url', url, refanged);
		}
	}
	return fail(`"${trimmed}" is not a hash, URL, IP address or domain`);
}
