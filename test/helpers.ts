import { vi } from 'vitest';
import type { VtContext } from '../shared/transport';

export interface FakeResponse {
	statusCode: number;
	body: unknown;
}

/** Builds a context whose HTTP helpers replay the given responses in order. */
export function fakeContext(responses: FakeResponse[]) {
	const queue = [...responses];
	const calls: Array<Record<string, unknown>> = [];
	const next = async (...args: unknown[]) => {
		const options = args[args.length - 1] as Record<string, unknown>;
		calls.push(options);
		const res = queue.shift();
		if (!res) throw new Error('no more fake responses');
		return res;
	};
	const ctx = {
		helpers: {
			httpRequestWithAuthentication: vi.fn(next),
			httpRequest: vi.fn(next),
		},
		getNode: () => ({
			name: 'VirusTotal',
			type: 'virusTotal',
			typeVersion: 1,
			position: [0, 0],
			parameters: {},
			id: '1',
		}),
	} as unknown as VtContext;
	return { ctx, calls };
}
