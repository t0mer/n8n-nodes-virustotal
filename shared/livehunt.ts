import type { IDataObject } from 'n8n-workflow';
import { isoFromEpoch, summarize } from './summary';
import type { Thresholds } from './verdict';

/** Notification ids remembered for deduplication. */
export const MAX_SEEN = 1000;

export interface HuntState {
	seen: string[];
	baselined: boolean;
}

export function normalizeHuntState(raw: Partial<HuntState> | undefined): HuntState {
	return {
		seen: Array.isArray(raw?.seen)
			? raw.seen.filter((id): id is string => typeof id === 'string')
			: [],
		baselined: raw?.baselined === true,
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
 * Stops on a rate limit without marking anything it did not read as seen.
 */
export async function pollLivehunt(options: HuntOptions): Promise<IDataObject[]> {
	const { state } = options;
	const seen = new Set(state.seen);
	const fresh: Notification[] = [];
	const freshIds = new Set<string>();
	let cursor: string | undefined;
	let pagesRead = 0;

	for (let page = 0; page < Math.max(1, options.maxPages); page++) {
		const result = await options.fetchPage(cursor);
		if (result.rateLimited) break;
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
		if (!result.next || !allNew) break;
		cursor = result.next;
	}

	const oldestFirst = [...fresh].reverse();
	state.seen = [...state.seen, ...oldestFirst.map((n) => n.id)].slice(-MAX_SEEN);

	if (!state.baselined) {
		// Only a completed read may establish the baseline; a rate-limited first poll reads nothing.
		state.baselined = pagesRead > 0;
		return [];
	}
	return oldestFirst.map((n) => n.item);
}
