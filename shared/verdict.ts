export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface Stats {
	malicious: number;
	suspicious: number;
	harmless: number;
	undetected: number;
	timeout: number;
	[category: string]: number;
}

export interface Thresholds {
	malicious: number;
	suspicious: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = { malicious: 3, suspicious: 1 };

const STAT_KEYS = ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout'] as const;

/** Normalizes VirusTotal's `last_analysis_stats`; missing counters become 0. */
export function normalizeStats(raw: unknown): Stats {
	const source = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
	const stats: Stats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 };
	for (const key of STAT_KEYS) {
		const value = Number(source[key]);
		stats[key] = Number.isFinite(value) ? value : 0;
	}
	return stats;
}

/**
 * Heuristic verdict from engine counts. Not a security guarantee.
 * - malicious >= threshold -> malicious
 * - malicious + suspicious >= suspicious threshold -> suspicious
 * - engines have looked at it -> clean
 * - no analysis results at all -> unknown
 */
export function computeVerdict(
	stats: Stats | undefined,
	thresholds: Thresholds = DEFAULT_THRESHOLDS,
): Verdict {
	if (!stats) return 'unknown';
	const analyzed = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
	if (analyzed === 0) return 'unknown';
	if (stats.malicious >= thresholds.malicious) return 'malicious';
	if (stats.malicious + stats.suspicious >= thresholds.suspicious) return 'suspicious';
	return 'clean';
}

/** `malicious/total`, where total excludes type-unsupported, failure and timeout results. */
export function detectionRatio(stats: Stats): string {
	const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
	return `${stats.malicious}/${total}`;
}
