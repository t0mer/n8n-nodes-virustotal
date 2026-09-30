import { describe, expect, it } from 'vitest';
import { computeVerdict, detectionRatio, normalizeStats } from '../shared/verdict';

const stats = (o: Record<string, number>) => normalizeStats(o);
const T = { malicious: 3, suspicious: 1 };

describe('computeVerdict', () => {
	it('is malicious at the malicious threshold', () => {
		expect(computeVerdict(stats({ malicious: 3, harmless: 60 }), T)).toBe('malicious');
		expect(computeVerdict(stats({ malicious: 10 }), T)).toBe('malicious');
	});

	it('is suspicious below the malicious threshold when malicious + suspicious reach the suspicious one', () => {
		expect(computeVerdict(stats({ malicious: 2, harmless: 60 }), T)).toBe('suspicious');
		expect(computeVerdict(stats({ suspicious: 1, harmless: 60 }), T)).toBe('suspicious');
	});

	it('is clean when engines ran and flagged nothing', () => {
		expect(computeVerdict(stats({ harmless: 60, undetected: 10 }), T)).toBe('clean');
	});

	it('is unknown without stats or without any analysis result', () => {
		expect(computeVerdict(undefined, T)).toBe('unknown');
		expect(computeVerdict(stats({}), T)).toBe('unknown');
		expect(computeVerdict(stats({ timeout: 5 }), T)).toBe('unknown');
	});

	it('honours custom thresholds', () => {
		expect(
			computeVerdict(stats({ malicious: 1, harmless: 9 }), { malicious: 1, suspicious: 1 }),
		).toBe('malicious');
		expect(
			computeVerdict(stats({ malicious: 1, harmless: 9 }), { malicious: 5, suspicious: 2 }),
		).toBe('clean');
	});
});

describe('detectionRatio', () => {
	it('excludes type-unsupported, failure and timeout from the denominator', () => {
		const s = normalizeStats({
			malicious: 5,
			suspicious: 2,
			harmless: 50,
			undetected: 15,
			timeout: 4,
			'type-unsupported': 9,
			failure: 3,
		});
		expect(detectionRatio(s)).toBe('5/72');
	});
});

describe('normalizeStats', () => {
	it('fills missing counters with 0 and ignores junk', () => {
		expect(normalizeStats({ malicious: 'x', harmless: 2 })).toMatchObject({
			malicious: 0,
			harmless: 2,
			timeout: 0,
		});
		expect(normalizeStats(null).undetected).toBe(0);
	});
});
