import type { IDataObject } from 'n8n-workflow';
import type { VtContext, Waiter } from './transport';
import { vtRequest } from './transport';

export const MAX_PAGE_SIZE = 40;

export interface PaginateOptions {
	path: string;
	qs?: IDataObject;
	returnAll: boolean;
	/** Maximum items when `returnAll` is false. */
	limit?: number;
	throttle?: Waiter;
}

interface Page {
	data?: IDataObject[];
	meta?: { cursor?: string };
	links?: { next?: string };
}

/**
 * Collects items from a cursor-paginated collection. Every page is a request,
 * so each one goes through the throttle.
 */
export async function paginate(ctx: VtContext, options: PaginateOptions): Promise<IDataObject[]> {
	const items: IDataObject[] = [];
	const wanted = options.returnAll ? Infinity : Math.max(1, options.limit ?? 10);
	let cursor: string | undefined;

	while (items.length < wanted) {
		const pageSize = Math.min(MAX_PAGE_SIZE, wanted - items.length);
		const page = await vtRequest<Page>(ctx, {
			path: options.path,
			qs: { ...options.qs, limit: pageSize, ...(cursor ? { cursor } : {}) },
			throttle: options.throttle,
		});

		const data = Array.isArray(page.data) ? page.data : [];
		items.push(...data);

		cursor = page.meta?.cursor;
		if (!cursor || !page.links?.next || data.length === 0) break;
	}

	return items.slice(0, wanted === Infinity ? undefined : wanted);
}
