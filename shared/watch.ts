import type { IDataObject } from 'n8n-workflow';
import type { Indicator } from './indicator';
import { summarize } from './summary';
import type { Stats, Thresholds, Verdict } from './verdict';

export const STATE_VERSION = 1;

export type FireWhen = 'becomesMalicious' | 'maliciousIncreases' | 'verdictChanges';

export interface WatchEntry {
	verdict: Verdict;
	malicious: number;
	stats?: Stats;
}

/** Persisted in the trigger's workflow static data. */
export interface WatchState {
	stateVersion: number;
	/** Round-robin position in the indicator list. */
	cursor: number;
	entries: Record<string, WatchEntry>;
}

export type LookupResult =
	| { rateLimited: true }
	| { rateLimited?: false; body: IDataObject | null };

export interface WatchOptions {
	state: WatchState;
	indicators: Indicator[];
	fireWhen: FireWhen;
	maxLookups: number;
	thresholds: Thresholds;
	lookup: (indicator: Indicator) => Promise<LookupResult>;
}

const EVENT_NAME: Record<FireWhen, string> = {
	becomesMalicious: 'becameMalicious',
	maliciousIncreases: 'maliciousCountIncreased',
	verdictChanges: 'verdictChanged',
};

export function freshState(): WatchState {
	return { stateVersion: STATE_VERSION, cursor: 0, entries: {} };
}

/** Reads persisted state; anything from another version starts a new baseline. */
export function normalizeState(raw: Partial<WatchState> | undefined): WatchState {
	if (
		!raw ||
		raw.stateVersion !== STATE_VERSION ||
		typeof raw.entries !== 'object' ||
		raw.entries === null
	) {
		return freshState();
	}
	return { stateVersion: STATE_VERSION, cursor: Number(raw.cursor) || 0, entries: raw.entries };
}

function changed(fireWhen: FireWhen, previous: WatchEntry, current: WatchEntry): boolean {
	switch (fireWhen) {
		case 'becomesMalicious':
			return previous.verdict !== 'malicious' && current.verdict === 'malicious';
		case 'maliciousIncreases':
			return current.malicious > previous.malicious;
		case 'verdictChanges':
			return previous.verdict !== current.verdict;
	}
}

/**
 * One poll: looks up the next `maxLookups` indicators round-robin, compares them with the stored
 * state and returns the items to emit. A first sighting only records a baseline.
 * Mutates `options.state`. Stops early, keeping the cursor at the first unread indicator, when rate limited.
 */
export async function watchIndicators(options: WatchOptions): Promise<IDataObject[]> {
	const { state, indicators, fireWhen, thresholds } = options;
	const emitted: IDataObject[] = [];
	const count = indicators.length;
	if (count === 0) {
		state.entries = {};
		state.cursor = 0;
		return emitted;
	}

	// Forget indicators that were removed from the list.
	const wanted = new Set(indicators.map((i) => i.indicator));
	for (const key of Object.keys(state.entries)) {
		if (!wanted.has(key)) delete state.entries[key];
	}

	const start = state.cursor % count;
	const lookups = Math.min(Math.max(1, options.maxLookups), count);
	let done = 0;

	for (let k = 0; k < lookups; k++) {
		const target = indicators[(start + k) % count];
		const result = await options.lookup(target);
		if (result.rateLimited) break;
		done++;

		const summary = summarize(target.type, result.body, {
			indicator: target.indicator,
			thresholds,
		});
		const current: WatchEntry = {
			verdict: summary.verdict as Verdict,
			malicious: Number((summary.stats as IDataObject | undefined)?.malicious ?? 0),
			stats: summary.stats as unknown as Stats | undefined,
		};
		const previous = state.entries[target.indicator];
		state.entries[target.indicator] = current;

		if (previous && changed(fireWhen, previous, current)) {
			emitted.push({
				...summary,
				event: EVENT_NAME[fireWhen],
				previousVerdict: previous.verdict,
				previousStats: (previous.stats ?? null) as unknown as IDataObject | null,
			});
		}
	}

	state.cursor = (start + done) % count;
	return emitted;
}
