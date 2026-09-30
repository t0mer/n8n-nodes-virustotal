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

export interface FakeExecuteOptions {
	/** One parameter map per input item. */
	params: Array<Record<string, unknown>>;
	responses: FakeResponse[];
	credentials?: Record<string, unknown>;
	continueOnFail?: boolean;
	binary?: Record<string, Buffer>;
}

/**
 * A minimal IExecuteFunctions. Like n8n, getNodeParameter throws when a parameter
 * has no value and no fallback was given, which mimics a parameter hidden by displayOptions.
 */
export function fakeExecute(options: FakeExecuteOptions) {
	const { ctx, calls } = fakeContext(options.responses);
	const fn = ctx as unknown as Record<string, unknown>;
	fn.getInputData = () => options.params.map(() => ({ json: {} }));
	fn.getNodeParameter = (name: string, index: number, fallback?: unknown) => {
		const value = options.params[index]?.[name];
		if (value !== undefined) return value;
		if (fallback !== undefined) return fallback;
		throw new Error(`Could not get parameter "${name}"`);
	};
	fn.getCredentials = async () => ({
		apiKey: 'test-key',
		tier: 'public',
		requestsPerMinute: 100000,
		...options.credentials,
	});
	fn.continueOnFail = () => options.continueOnFail ?? false;
	fn.getExecutionCancelSignal = () => undefined;
	(fn.helpers as Record<string, unknown>).assertBinaryData = (_i: number, property: string) => {
		if (!options.binary?.[property]) throw new Error(`no binary data "${property}"`);
		return { fileName: `${property}.bin`, mimeType: 'application/octet-stream' };
	};
	(fn.helpers as Record<string, unknown>).getBinaryDataBuffer = async (
		_i: number,
		property: string,
	) => {
		const buffer = options.binary?.[property];
		if (!buffer) throw new Error(`no binary data "${property}"`);
		return buffer;
	};
	return { fn: fn as unknown as import('n8n-workflow').IExecuteFunctions, calls };
}

export interface FakePollOptions {
	params: Record<string, unknown>;
	responses: FakeResponse[];
	staticData?: Record<string, unknown>;
	mode?: 'manual' | 'trigger';
	credentials?: Record<string, unknown>;
}

/** A minimal IPollFunctions with persistent static data. */
export function fakePoll(options: FakePollOptions) {
	const { ctx, calls } = fakeContext(options.responses);
	const fn = ctx as unknown as Record<string, unknown>;
	const staticData = options.staticData ?? {};
	fn.getNodeParameter = (name: string, fallback?: unknown) => {
		const value = options.params[name];
		if (value !== undefined) return value;
		if (fallback !== undefined) return fallback;
		throw new Error(`Could not get parameter "${name}"`);
	};
	fn.getCredentials = async () => ({
		apiKey: 'test-key',
		tier: 'public',
		requestsPerMinute: 4,
		...options.credentials,
	});
	fn.getMode = () => options.mode ?? 'trigger';
	fn.getWorkflowStaticData = () => staticData;
	(fn.helpers as Record<string, unknown>).returnJsonArray = (items: unknown[]) =>
		items.map((json) => ({ json }));
	return { fn: fn as unknown as import('n8n-workflow').IPollFunctions, calls, staticData };
}
