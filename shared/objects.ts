import type { IndicatorType } from './indicator';
import { urlId } from './urlId';

export const COLLECTION: Record<IndicatorType, string> = {
	file: 'files',
	url: 'urls',
	domain: 'domains',
	ip_address: 'ip_addresses',
};

/** The id VirusTotal uses in paths: URLs are base64url-encoded, everything else is as-is. */
export function objectId(type: IndicatorType, indicator: string): string {
	return type === 'url' ? urlId(indicator) : indicator;
}

/** Path of an object below the v3 base URL, e.g. `/domains/example.com`. */
export function objectPath(type: IndicatorType, indicator: string): string {
	return `/${COLLECTION[type]}/${encodeURIComponent(objectId(type, indicator))}`;
}
