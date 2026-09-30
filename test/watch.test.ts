import { describe, expect, it } from 'vitest';
import type { Indicator } from '../shared/indicator';
import type { LookupResult } from '../shared/watch';
import { freshState, normalizeState, watchIndicators } from '../shared/watch';
import { fixtures } from './fixtures';

const T = { malicious: 3, suspicious: 1 };
const dom = (name: string): Indicator => ({
	ok: true,
	type: 'domain',
	indicator: name,
	refanged: false,
});

const report = (malicious: number, harmless = 60) => ({
	data: {
		id: 'x',
		type: 'domain',
		attributes: {
			last_analysis_stats: { malicious, suspicious: 0, harmless, undetected: 0, timeout: 0 },
		},
	},
});

/** A lookup that serves scripted bodies per indicator and records the order of calls. */
function scripted(
	script: Record<string, Array<LookupResult['rateLimited'] extends never ? never : LookupResult>>,
) {
	const order: string[] = [];
	const lookup = async (i: Indicator): Promise<LookupResult> => {
		order.push(i.indicator);
		const next = script[i.indicator]?.shift();
		if (!next) throw new Error(`no scripted result for ${i.indicator}`);
		return next;
	};
	return { lookup, order };
}

const body = (b: unknown): LookupResult => ({ body: b as never });

describe('watchIndicators', () => {
	it('the first sighting only records a baseline and emits nothing', async () => {
		const state = freshState();
		const { lookup } = scripted({ 'a.com': [body(report(10))] });
		const out = await watchIndicators({
			state,
			indicators: [dom('a.com')],
			fireWhen: 'verdictChanges',
			maxLookups: 3,
			thresholds: T,
			lookup,
		});
		expect(out).toEqual([]);
		expect(state.entries['a.com']).toMatchObject({ verdict: 'malicious', malicious: 10 });
	});

	it('Verdict Changes fires with previous verdict and stats', async () => {
		const state = freshState();
		const a = dom('a.com');
		const { lookup } = scripted({ 'a.com': [body(report(0)), body(report(5)), body(report(5))] });
		const opts = {
			state,
			indicators: [a],
			fireWhen: 'verdictChanges' as const,
			maxLookups: 1,
			thresholds: T,
			lookup,
		};
		await watchIndicators(opts);
		const out = await watchIndicators(opts);
		expect(out).toHaveLength(1);
		expect(out[0]).toMatchObject({
			event: 'verdictChanged',
			verdict: 'malicious',
			previousVerdict: 'clean',
			previousStats: { malicious: 0, harmless: 60 },
			indicator: 'a.com',
		});
		// No further change: nothing fires.
		expect(await watchIndicators(opts)).toEqual([]);
	});

	it('an unseen indicator that becomes known counts as a change', async () => {
		const state = freshState();
		const { lookup } = scripted({ 'a.com': [{ body: null }, body(report(0))] });
		const opts = {
			state,
			indicators: [dom('a.com')],
			fireWhen: 'verdictChanges' as const,
			maxLookups: 1,
			thresholds: T,
			lookup,
		};
		await watchIndicators(opts);
		expect(state.entries['a.com'].verdict).toBe('unknown');
		const out = await watchIndicators(opts);
		expect(out[0]).toMatchObject({
			previousVerdict: 'unknown',
			previousStats: null,
			verdict: 'clean',
		});
	});

	it('Becomes Malicious ignores other changes and fires only on the transition', async () => {
		const state = freshState();
		// clean -> suspicious (no fire) -> malicious (fire) -> malicious (no fire)
		const { lookup } = scripted({
			'a.com': [body(report(0)), body(report(2)), body(report(4)), body(report(9))],
		});
		const opts = {
			state,
			indicators: [dom('a.com')],
			fireWhen: 'becomesMalicious' as const,
			maxLookups: 1,
			thresholds: T,
			lookup,
		};
		await watchIndicators(opts);
		expect(await watchIndicators(opts)).toEqual([]);
		const fired = await watchIndicators(opts);
		expect(fired).toHaveLength(1);
		expect(fired[0].event).toBe('becameMalicious');
		expect(await watchIndicators(opts)).toEqual([]);
	});

	it('Malicious Count Increases fires on every increase, not on decreases', async () => {
		const state = freshState();
		const { lookup } = scripted({
			'a.com': [body(report(5)), body(report(7)), body(report(6)), body(report(8))],
		});
		const opts = {
			state,
			indicators: [dom('a.com')],
			fireWhen: 'maliciousIncreases' as const,
			maxLookups: 1,
			thresholds: T,
			lookup,
		};
		await watchIndicators(opts);
		expect(await watchIndicators(opts)).toHaveLength(1);
		expect(await watchIndicators(opts)).toEqual([]);
		const last = await watchIndicators(opts);
		expect(last[0]).toMatchObject({
			event: 'maliciousCountIncreased',
			previousStats: { malicious: 6 },
		});
	});

	it('works through a long list round-robin and never exceeds maxLookups', async () => {
		const state = freshState();
		const list = ['a', 'b', 'c', 'd', 'e'].map((n) => dom(`${n}.com`));
		const script = Object.fromEntries(
			list.map((i) => [i.indicator, [body(report(0)), body(report(0))]]),
		);
		const { lookup, order } = scripted(script);
		const opts = {
			state,
			indicators: list,
			fireWhen: 'verdictChanges' as const,
			maxLookups: 2,
			thresholds: T,
			lookup,
		};
		await watchIndicators(opts);
		await watchIndicators(opts);
		await watchIndicators(opts);
		expect(order).toEqual(['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'a.com']);
		expect(state.cursor).toBe(1);
	});

	it('on a rate limit it stops, keeps the cursor on the first unread indicator and does not throw', async () => {
		const state = freshState();
		const list = ['a', 'b', 'c'].map((n) => dom(`${n}.com`));
		const { lookup, order } = scripted({
			'a.com': [body(report(0))],
			'b.com': [{ rateLimited: true }],
		});
		const out = await watchIndicators({
			state,
			indicators: list,
			fireWhen: 'verdictChanges',
			maxLookups: 3,
			thresholds: T,
			lookup,
		});
		expect(out).toEqual([]);
		expect(order).toEqual(['a.com', 'b.com']);
		expect(state.cursor).toBe(1);
		expect(Object.keys(state.entries)).toEqual(['a.com']);
	});

	it('forgets indicators removed from the list and handles an empty list', async () => {
		const state = freshState();
		state.entries = {
			'gone.com': { verdict: 'clean', malicious: 0 },
			'a.com': { verdict: 'clean', malicious: 0 },
		};
		const { lookup } = scripted({ 'a.com': [body(report(0))] });
		await watchIndicators({
			state,
			indicators: [dom('a.com')],
			fireWhen: 'verdictChanges',
			maxLookups: 1,
			thresholds: T,
			lookup,
		});
		expect(Object.keys(state.entries)).toEqual(['a.com']);
		await watchIndicators({
			state,
			indicators: [],
			fireWhen: 'verdictChanges',
			maxLookups: 1,
			thresholds: T,
			lookup,
		});
		expect(state.entries).toEqual({});
	});

	it('uses the thresholds for the verdict', async () => {
		const state = freshState();
		const { lookup } = scripted({ 'a.com': [body(report(2)), body(report(2))] });
		const opts = {
			state,
			indicators: [dom('a.com')],
			fireWhen: 'verdictChanges' as const,
			maxLookups: 1,
			thresholds: { malicious: 2, suspicious: 1 },
			lookup,
		};
		await watchIndicators(opts);
		expect(state.entries['a.com'].verdict).toBe('malicious');
	});
});

describe('normalizeState', () => {
	it('keeps valid version 1 state', () => {
		const raw = {
			stateVersion: 1,
			cursor: 2,
			entries: { 'a.com': { verdict: 'clean' as const, malicious: 0 } },
		};
		expect(normalizeState(raw)).toEqual(raw);
	});

	it('starts a new baseline for missing or foreign versions', () => {
		expect(normalizeState(undefined)).toEqual(freshState());
		expect(normalizeState({ stateVersion: 99, cursor: 5, entries: {} })).toEqual(freshState());
		expect(normalizeState({})).toEqual(freshState());
	});
});

describe('fixtures sanity', () => {
	it('the domain fixture is clean', () => {
		expect(fixtures.domain.data.attributes.last_analysis_stats.malicious).toBe(0);
	});
});

describe('watchIndicators: a rejected indicator', () => {
	it('is skipped without blocking the ones after it, and the cursor moves on', async () => {
		const state = freshState();
		const list = ['a', 'b', 'c'].map((n) => dom(`${n}.com`));
		const { lookup, order } = scripted({
			'a.com': [body(report(0))],
			'b.com': [{ skipped: true }],
			'c.com': [body(report(0))],
		});
		await watchIndicators({
			state,
			indicators: list,
			fireWhen: 'verdictChanges',
			maxLookups: 3,
			thresholds: T,
			lookup,
		});
		expect(order).toEqual(['a.com', 'b.com', 'c.com']);
		expect(Object.keys(state.entries)).toEqual(['a.com', 'c.com']);
		expect(state.cursor).toBe(0);
	});
});
