import { sleep } from 'n8n-workflow';
import type { VtContext, Waiter } from './transport';
import { CREDENTIAL_NAME } from './transport';

export const DEFAULT_REQUESTS_PER_MINUTE = 4;

/**
 * Spaces request starts evenly so that at most `requestsPerMinute` are sent per minute.
 * The first request goes out immediately. Create one per execution and share it.
 */
export class Throttle implements Waiter {
	readonly intervalMs: number;

	private nextSlot = 0;

	constructor(
		readonly requestsPerMinute: number,
		private readonly signal?: AbortSignal,
		private readonly now: () => number = Date.now,
	) {
		const rpm =
			Number.isFinite(requestsPerMinute) && requestsPerMinute > 0
				? requestsPerMinute
				: DEFAULT_REQUESTS_PER_MINUTE;
		this.intervalMs = 60_000 / rpm;
	}

	async wait(): Promise<void> {
		// Reserve the slot before sleeping so concurrent callers queue up behind each other.
		const start = Math.max(this.now(), this.nextSlot);
		this.nextSlot = start + this.intervalMs;
		const delay = start - this.now();
		if (delay > 0) await sleep(delay, this.signal);
	}
}

/** Reads the requests-per-minute setting from the credential. */
export async function getRequestsPerMinute(ctx: VtContext): Promise<number> {
	const credentials = await ctx.getCredentials(CREDENTIAL_NAME);
	const value = Number(credentials.requestsPerMinute);
	return Number.isFinite(value) && value > 0 ? value : DEFAULT_REQUESTS_PER_MINUTE;
}

/** Builds the per-execution throttle from the credential, honouring execution cancellation. */
export async function createThrottle(ctx: VtContext): Promise<Throttle> {
	const signal = 'getExecutionCancelSignal' in ctx ? ctx.getExecutionCancelSignal() : undefined;
	return new Throttle(await getRequestsPerMinute(ctx), signal);
}
