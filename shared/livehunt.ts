import type { IDataObject } from 'n8n-workflow';
import { isoFromEpoch, summarize } from './summary';
import type { Thresholds } from './verdict';

/** Notification ids remembered for deduplication. */
export const MAX_SEEN = 1000;

/** Unread regions of the feed that still need reading, newest first. */
export const MAX_PENDING = 20;

export interface HuntState {
	seen: string[];
	baselined: boolean;
	/** Cursors to resume from: pages a poll could not read because of its page budget or a rate limit. */
	pending: string[];
}

export function normalizeHuntState(raw: Partial<HuntState> | undefined): HuntState {
	return {
		seen: Array.isArray(raw?.seen)
			? raw.seen.filter((id): id is string => typeof id === 'string')
			: [],
		baselined: raw?.baselined === true,
		pending: Array.isArray(raw?.pending)
			? raw.pending.filter((c): c is string => typeof c === 'string')
			: [],
	};
}

export interface Notification {
	id: string;
	item: IDataObject;
}

function str(value: unknown): string | undefined {
	return typeof value === 'string' && value !== '' ? value : undefined;
}

/** Reads one Livehunt notification file. Returns null when it carries no notification id. */
export function toNotification(raw: IDataObject, thresholds: Thresholds): Notification | null {
	const context = (raw.context_attributes ?? {}) as IDataObject;
	const id =
		str(context.notification_id) ??
		(typeof context.notification_id === 'number' ? String(context.notification_id) : undefined);
	if (!id) return null;

	const tags = Array.isArray(context.notification_tags) ? context.notification_tags : [];
	const item: IDataObject = {
		event: 'livehuntNotification',
		notificationId: id,
		notificationDate: isoFromEpoch(context.notification_date),
		ruleName: str(context.rule_name),
		rulesetName: str(context.ruleset_name),
		rulesetId: str(context.ruleset_id),
		notificationTags: tags as IDataObject[string],
		...summarize(
			'file',
			{ data: { id: raw.id, type: 'file', attributes: raw.attributes } } as IDataObject,
			{
				indicator: String(raw.id ?? ''),
				thresholds,
			},
		),
	};
	for (const key of Object.keys(item)) {
		if (item[key] === undefined) delete item[key];
	}
	return { id, item };
}

export type PageResult =
	| { rateLimited: true }
	| { rateLimited?: false; items: IDataObject[]; next?: string };

export interface HuntOptions {
	state: HuntState;
	thresholds: Thresholds;
	maxPages: number;
	fetchPage: (cursor?: string) => Promise<PageResult>;
}

/**
 * One poll of the Livehunt notifications feed (newest first). The first run only records a
 * baseline. Afterwards every unseen notification is emitted once, oldest first.
 *
 * A poll reads at most `maxPages` pages. When it cannot finish (page budget spent, or a rate
 * limit), the cursor of the first unread page is kept in `state.pending` and read on a later
 * poll, so a backlog is never skipped. Nothing it did not read is marked as seen.
 */
export async function pollLivehunt(options: HuntOptions): Promise<IDataObject[]> {
	const { state } = options;
	const seen = new Set(state.seen);
	const fresh: Notification[] = [];
	const freshIds = new Set<string>();
	let budget = Math.max(1, options.maxPages);
	let pagesRead = 0;
	let limited = false;

	/** Reads from `start` until a page holds an already-seen notification or the feed ends. */
	const walk = async (start?: string): Promise<{ done: boolean; resume?: string }> => {
		let cursor = start;
		while (budget > 0) {
			const result = await options.fetchPage(cursor);
			if (result.rateLimited) {
				limited = true;
				return { done: false, resume: cursor };
			}
			budget--;
			pagesRead++;

			let allNew = result.items.length > 0;
			for (const raw of result.items) {
				const notification = toNotification(raw, options.thresholds);
				if (!notification) continue;
				if (seen.has(notification.id)) {
					allNew = false;
					continue;
				}
				if (!freshIds.has(notification.id)) {
					freshIds.add(notification.id);
					fresh.push(notification);
				}
			}
			if (!allNew || !result.next) return { done: true };
			cursor = result.next;
		}
		return { done: false, resume: cursor };
	};

	const pending: string[] = [];
	const head = await walk(undefined);
	if (!head.done && head.resume) pending.push(head.resume);

	if (state.baselined) {
		const older = [...state.pending];
		for (let i = 0; i < older.length; i++) {
			if (limited || budget <= 0) {
				pending.push(...older.slice(i));
				break;
			}
			const region = await walk(older[i]);
			if (!region.done && region.resume) pending.push(region.resume);
		}
	}

	const oldestFirst = [...fresh].reverse();
	state.seen = [...state.seen, ...oldestFirst.map((n) => n.id)].slice(-MAX_SEEN);

	if (!state.baselined) {
		// Only a completed read may establish the baseline; a rate-limited first poll reads nothing.
		state.baselined = pagesRead > 0;
		state.pending = [];
		return [];
	}
	state.pending = pending.slice(0, MAX_PENDING);
	return oldestFirst.map((n) => n.item);
}
