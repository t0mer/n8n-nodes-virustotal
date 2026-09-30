import { describe, expect, it } from 'vitest';
import type { IDataObject } from 'n8n-workflow';
import type { PageResult } from '../shared/livehunt';
import { MAX_SEEN, normalizeHuntState, pollLivehunt, toNotification } from '../shared/livehunt';
import { VirusTotalTrigger } from '../nodes/VirusTotalTrigger/VirusTotalTrigger.node';
import { fakePoll } from './helpers';
import { fixtures } from './fixtures';

const T = { malicious: 3, suspicious: 1 };
const p1 = fixtures.livehuntPage1.data as unknown as IDataObject[];
const p2 = fixtures.livehuntPage2.data as unknown as IDataObject[];
const note = (id: string): IDataObject => ({
	id: `f-${id}`,
	type: 'file',
	attributes: {},
	context_attributes: { notification_id: id },
});

function pages(...results: PageResult[]) {
	const queue = [...results];
	const cursors: Array<string | undefined> = [];
	return {
		cursors,
		fetchPage: async (cursor?: string): Promise<PageResult> => {
			cursors.push(cursor);
			const next = queue.shift();
			if (!next) throw new Error('unexpected extra page request');
			return next;
		},
	};
}

describe('toNotification', () => {
	it('maps rule, ruleset, tags and a file Summary', () => {
		const n = toNotification(p1[0], T);
		expect(n?.id).toBe('n-3');
		expect(n?.item).toMatchObject({
			event: 'livehuntNotification',
			notificationId: 'n-3',
			notificationDate: new Date(1790000300 * 1000).toISOString(),
			ruleName: 'eicar_rule',
			rulesetName: 'my_ruleset',
			rulesetId: 'rs-1',
			notificationTags: ['my_ruleset', 'eicar'],
			found: true,
			type: 'file',
			verdict: 'malicious',
			meaningfulName: 'eicar.com',
		});
	});

	it('skips files without a notification id and leaves no undefined keys', () => {
		expect(toNotification(p1[2], T)).toBeNull();
		const n = toNotification(note('x'), T);
		expect(Object.values(n?.item ?? {})).not.toContain(undefined);
	});
});

describe('pollLivehunt', () => {
	it('the first poll baselines and emits nothing', async () => {
		const state = normalizeHuntState(undefined);
		const { fetchPage } = pages({ items: p1 });
		expect(await pollLivehunt({ state, thresholds: T, maxPages: 3, fetchPage })).toEqual([]);
		expect(state).toEqual({ seen: ['n-2', 'n-3'], baselined: true });
	});

	it('emits only unseen notifications, oldest first, and never twice', async () => {
		const state = { seen: ['n-1'], baselined: true };
		const a = pages({ items: [note('n-3'), note('n-2'), note('n-1')] });
		const out = await pollLivehunt({ state, thresholds: T, maxPages: 3, fetchPage: a.fetchPage });
		expect(out.map((i) => i.notificationId)).toEqual(['n-2', 'n-3']);

		const b = pages({ items: [note('n-3'), note('n-2'), note('n-1')] });
		expect(
			await pollLivehunt({ state, thresholds: T, maxPages: 3, fetchPage: b.fetchPage }),
		).toEqual([]);
	});

	it('follows the cursor while a whole page is new, and stops at the first seen notification', async () => {
		const state = { seen: ['n-0'], baselined: true };
		const { fetchPage, cursors } = pages(
			{ items: [note('n-4'), note('n-3')], next: 'C2' },
			{ items: [note('n-2'), note('n-0')], next: 'C3' },
		);
		const out = await pollLivehunt({ state, thresholds: T, maxPages: 5, fetchPage });
		expect(cursors).toEqual([undefined, 'C2']);
		expect(out.map((i) => i.notificationId)).toEqual(['n-2', 'n-3', 'n-4']);
	});

	it('reads at most maxPages pages', async () => {
		const state = { seen: [], baselined: true };
		const { fetchPage, cursors } = pages(
			{ items: [note('a')], next: 'C2' },
			{ items: [note('b')], next: 'C3' },
		);
		await pollLivehunt({ state, thresholds: T, maxPages: 2, fetchPage });
		expect(cursors).toHaveLength(2);
	});

	it('a rate-limited first poll does not establish the baseline', async () => {
		const state = normalizeHuntState(undefined);
		const { fetchPage } = pages({ rateLimited: true });
		expect(await pollLivehunt({ state, thresholds: T, maxPages: 3, fetchPage })).toEqual([]);
		expect(state.baselined).toBe(false);
	});

	it('an empty feed still establishes the baseline', async () => {
		const state = normalizeHuntState(undefined);
		await pollLivehunt({
			state,
			thresholds: T,
			maxPages: 3,
			fetchPage: pages({ items: [] }).fetchPage,
		});
		expect(state.baselined).toBe(true);
	});

	it('keeps at most the last 1000 ids', async () => {
		const state = { seen: Array.from({ length: MAX_SEEN }, (_, i) => `old-${i}`), baselined: true };
		await pollLivehunt({
			state,
			thresholds: T,
			maxPages: 1,
			fetchPage: pages({ items: [note('new-2'), note('new-1')] }).fetchPage,
		});
		expect(state.seen).toHaveLength(MAX_SEEN);
		expect(state.seen.slice(-2)).toEqual(['new-1', 'new-2']);
		expect(state.seen[0]).toBe('old-2');
	});
});

const ok = (body: unknown) => ({ statusCode: 200, body });
const hunt = (
	opts: Partial<Parameters<typeof fakePoll>[0]> & {
		responses: Parameters<typeof fakePoll>[0]['responses'];
	},
) => {
	const p = fakePoll({
		params: { event: 'livehuntNotification', rulesetFilter: '' },
		credentials: { tier: 'premium', requestsPerMinute: 10 },
		...opts,
	});
	return { ...p, result: () => new VirusTotalTrigger().poll.call(p.fn) };
};

describe('Livehunt trigger event', () => {
	it('requires the Premium tier and makes no request otherwise', async () => {
		const p = hunt({ credentials: { tier: 'public' }, responses: [] });
		await expect(p.result()).rejects.toThrow(
			'Livehunt notifications require a VirusTotal Premium API key',
		);
		expect(p.calls).toHaveLength(0);
	});

	it('baselines on the first poll and persists the version-independent hunt state', async () => {
		const p = hunt({ responses: [ok({ data: p1, meta: {} })] });
		expect(await p.result()).toBeNull();
		expect(p.calls[0].url).toBe(
			'https://www.virustotal.com/api/v3/intelligence/hunting_notification_files',
		);
		expect(p.calls[0].qs).toEqual({ limit: 40 });
		expect(p.staticData).toMatchObject({ baselined: true, seen: ['n-2', 'n-3'] });
	});

	it('emits new notifications on later polls', async () => {
		const p = hunt({
			responses: [ok(fixtures.livehuntPage1)],
			staticData: { baselined: true, seen: ['n-2'] },
		});
		const out = await p.result();
		expect(out?.[0].map((i) => i.json.notificationId)).toEqual(['n-3']);
	});

	it('sends a plain ruleset name as a tag filter and passes explicit filters through', async () => {
		const a = hunt({
			params: { event: 'livehuntNotification', rulesetFilter: 'my_ruleset' },
			responses: [ok({ data: [] })],
		});
		await a.result();
		expect(a.calls[0].qs).toEqual({ limit: 40, filter: 'tag:my_ruleset' });
		const b = hunt({
			params: { event: 'livehuntNotification', rulesetFilter: 'ruleset:abc' },
			responses: [ok({ data: [] })],
		});
		await b.result();
		expect(b.calls[0].qs).toMatchObject({ filter: 'ruleset:abc' });
	});

	it('ends the poll quietly on a 429 and keeps state', async () => {
		const p = hunt({
			responses: [
				{ statusCode: 429, body: { error: { code: 'QuotaExceededError', message: 'q' } } },
			],
			staticData: { baselined: true, seen: ['x'] },
		});
		expect(await p.result()).toBeNull();
		expect(p.staticData.seen).toEqual(['x']);
	});

	it('throws on a 401', async () => {
		const p = hunt({
			responses: [
				{ statusCode: 401, body: { error: { code: 'WrongCredentialsError', message: 'x' } } },
			],
		});
		await expect(p.result()).rejects.toThrow('Invalid or inactive VirusTotal API key');
	});

	it('manual mode returns the latest notifications and leaves state untouched', async () => {
		const p = hunt({ mode: 'manual', responses: [ok(fixtures.livehuntPage1)] });
		const out = await p.result();
		expect(p.calls[0].qs).toEqual({ limit: 3 });
		expect(out?.[0]).toHaveLength(2);
		expect(out?.[0][0].json.event).toBe('test');
		expect(p.staticData).toEqual({});
	});

	it('the watched event still works on the same node', async () => {
		const p = fakePoll({
			params: {
				event: 'watchedIndicatorChanged',
				indicators: { items: [{ value: 'a.com' }] },
				fireWhen: 'verdictChanges',
				maxLookups: 1,
			},
			responses: [
				ok({
					data: {
						id: 'a.com',
						attributes: {
							last_analysis_stats: {
								malicious: 0,
								suspicious: 0,
								harmless: 5,
								undetected: 0,
								timeout: 0,
							},
						},
					},
				}),
			],
		});
		expect(await new VirusTotalTrigger().poll.call(p.fn)).toBeNull();
		expect(p.calls[0].url).toBe('https://www.virustotal.com/api/v3/domains/a.com');
	});
});

describe('fixture sanity', () => {
	it('page 2 holds the oldest notification', () => {
		expect(p2[0].context_attributes).toMatchObject({ notification_id: 'n-1' });
	});
});
