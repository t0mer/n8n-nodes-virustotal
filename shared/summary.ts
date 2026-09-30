import type { IDataObject } from 'n8n-workflow';
import type { IndicatorType } from './indicator';
import type { Thresholds, Verdict } from './verdict';
import { DEFAULT_THRESHOLDS, computeVerdict, detectionRatio, normalizeStats } from './verdict';

export interface SummaryOptions {
	indicator: string;
	thresholds?: Thresholds;
	includeEngines?: boolean;
	/** Clock override for tests. */
	now?: () => number;
}

type Attributes = Record<string, unknown>;

const GUI_TYPE: Record<IndicatorType, string> = {
	file: 'file',
	url: 'url',
	domain: 'domain',
	ip_address: 'ip-address',
};

/** Epoch seconds to an ISO-8601 string; undefined when absent. */
export function isoFromEpoch(value: unknown): string | undefined {
	if (typeof value !== 'number' || !Number.isFinite(value)) return undefined;
	return new Date(value * 1000).toISOString();
}

function str(value: unknown): string | undefined {
	return typeof value === 'string' && value !== '' ? value : undefined;
}

function num(value: unknown): number | undefined {
	return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function obj(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === 'object' && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function compact(input: Record<string, unknown>): IDataObject {
	const out: IDataObject = {};
	for (const [key, value] of Object.entries(input)) {
		if (value !== undefined) out[key] = value as IDataObject[string];
	}
	return out;
}

/** Unique category names from VT's `{ vendor: category }` map. */
function categoryList(value: unknown): string[] | undefined {
	const map = obj(value);
	if (!map) return undefined;
	return [...new Set(Object.values(map).filter((v): v is string => typeof v === 'string'))];
}

/** A certificate name object (`{ CN, O, ... }`) reduced to one readable string. */
function certName(value: unknown): string | undefined {
	const name = obj(value);
	if (!name) return undefined;
	return str(name.CN) ?? str(name.O) ?? undefined;
}

function sandboxVerdicts(value: unknown): IDataObject[] | undefined {
	const map = obj(value);
	if (!map) return undefined;
	return Object.entries(map).map(([key, entry]) => {
		const e = obj(entry) ?? {};
		return compact({
			sandbox: str(e.sandbox_name) ?? key,
			category: str(e.category),
			malwareClassification: Array.isArray(e.malware_classification)
				? e.malware_classification
				: undefined,
			malwareNames: Array.isArray(e.malware_names) ? e.malware_names : undefined,
		});
	});
}

function flaggedEngines(value: unknown): IDataObject[] {
	const map = obj(value);
	if (!map) return [];
	return Object.entries(map)
		.map(([key, entry]) => ({ key, e: obj(entry) ?? {} }))
		.filter(({ e }) => e.category === 'malicious' || e.category === 'suspicious')
		.map(({ key, e }) => ({
			engine: str(e.engine_name) ?? key,
			category: e.category as string,
			result: typeof e.result === 'string' ? e.result : null,
		}));
}

function certificate(value: unknown, now: number): IDataObject | undefined {
	const cert = obj(value);
	if (!cert) return undefined;
	const notAfterRaw = str(obj(cert.validity)?.not_after);
	let notAfter: string | undefined;
	let daysUntilExpiry: number | undefined;
	if (notAfterRaw) {
		const parsed = Date.parse(
			notAfterRaw.includes('T') ? notAfterRaw : `${notAfterRaw.replace(' ', 'T')}Z`,
		);
		if (!Number.isNaN(parsed)) {
			notAfter = new Date(parsed).toISOString();
			daysUntilExpiry = Math.floor((parsed - now) / 86_400_000);
		}
	}
	return compact({
		issuer: certName(cert.issuer),
		subject: certName(cert.subject),
		notAfter,
		daysUntilExpiry,
	});
}

function typeFields(type: IndicatorType, a: Attributes, now: number): IDataObject {
	switch (type) {
		case 'file':
			return compact({
				sha256: str(a.sha256),
				sha1: str(a.sha1),
				md5: str(a.md5),
				meaningfulName: str(a.meaningful_name),
				names: Array.isArray(a.names) ? a.names.slice(0, 10) : undefined,
				size: num(a.size),
				typeDescription: str(a.type_description),
				typeTag: str(a.type_tag),
				firstSubmissionDate: isoFromEpoch(a.first_submission_date),
				timesSubmitted: num(a.times_submitted),
				popularThreatLabel: str(obj(a.popular_threat_classification)?.suggested_threat_label),
				sandboxVerdicts: sandboxVerdicts(a.sandbox_verdicts),
			});
		case 'url':
			return compact({
				url: str(a.url),
				finalUrl: str(a.last_final_url),
				title: str(a.title),
				categories: categoryList(a.categories),
				lastHttpResponseCode: num(a.last_http_response_code),
			});
		case 'domain':
			return compact({
				categories: categoryList(a.categories),
				registrar: str(a.registrar),
				creationDate: isoFromEpoch(a.creation_date),
				lastDnsRecords: Array.isArray(a.last_dns_records)
					? a.last_dns_records.map((r) =>
							compact({ type: str(obj(r)?.type), value: str(obj(r)?.value) }),
						)
					: undefined,
				lastHttpsCertificate: certificate(a.last_https_certificate, now),
				whoisDate: isoFromEpoch(a.whois_date),
			});
		case 'ip_address':
			return compact({
				asn: num(a.asn),
				asOwner: str(a.as_owner),
				country: str(a.country),
				network: str(a.network),
				regionalInternetRegistry: str(a.regional_internet_registry),
			});
	}
}

/** The item returned for an indicator VirusTotal has never seen. */
export function unknownItem(type: IndicatorType, indicator: string): IDataObject {
	return { found: false, type, indicator, verdict: 'unknown' satisfies Verdict };
}

/**
 * Maps a VirusTotal v3 response (`{ data: {...} }`) to the normalized Summary.
 * Pass null for an object VirusTotal does not know.
 */
export function summarize(
	type: IndicatorType,
	body: IDataObject | null,
	options: SummaryOptions,
): IDataObject {
	const data = obj(body?.data);
	if (!data) return unknownItem(type, options.indicator);

	const attributes = (obj(data.attributes) ?? {}) as Attributes;
	const id = str(data.id);
	const stats = normalizeStats(attributes.last_analysis_stats);
	const thresholds = options.thresholds ?? DEFAULT_THRESHOLDS;
	const votes = obj(attributes.total_votes);

	const summary = compact({
		found: true,
		type,
		indicator: options.indicator,
		id,
		verdict: computeVerdict(attributes.last_analysis_stats ? stats : undefined, thresholds),
		stats: stats as unknown as IDataObject,
		detectionRatio: detectionRatio(stats),
		reputation: num(attributes.reputation),
		votes: votes
			? { harmless: num(votes.harmless) ?? 0, malicious: num(votes.malicious) ?? 0 }
			: undefined,
		tags: Array.isArray(attributes.tags) ? attributes.tags : [],
		lastAnalysisDate: isoFromEpoch(attributes.last_analysis_date),
		permalink: id ? `https://www.virustotal.com/gui/${GUI_TYPE[type]}/${id}` : undefined,
	});

	const extra = typeFields(type, attributes, (options.now ?? Date.now)());
	const result: IDataObject = { ...summary, ...extra };
	if (options.includeEngines) result.engines = flaggedEngines(attributes.last_analysis_results);
	return result;
}
