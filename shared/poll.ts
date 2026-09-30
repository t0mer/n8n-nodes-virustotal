import type { IDataObject } from 'n8n-workflow';
import { NodeOperationError, sleep } from 'n8n-workflow';
import type { VtContext, Waiter } from './transport';
import { vtRequest } from './transport';

export const DEFAULT_TIMEOUT_MINUTES = 10;

/** Default poll cadence in seconds: max(20, 60 / requestsPerMinute * 1.5), leaving quota headroom. */
export function defaultPollIntervalSeconds(requestsPerMinute: number): number {
	const rpm = requestsPerMinute > 0 ? requestsPerMinute : 4;
	return Math.max(20, (60 / rpm) * 1.5);
}

export interface AnalysisBody extends IDataObject {
	data?: {
		id?: string;
		attributes?: { status?: string; stats?: IDataObject };
	};
	meta?: { file_info?: { sha256?: string }; url_info?: { id?: string } };
}

export interface WaitOptions {
	analysisId: string;
	throttle?: Waiter;
	intervalMs: number;
	timeoutMs: number;
	signal?: AbortSignal;
	itemIndex?: number;
	/** Test hooks. */
	now?: () => number;
	sleepFn?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

/**
 * Which kind of object an analysis belongs to. For URL analyses `meta` holds both `url_info` and
 * `file_info` (the fetched content), so the analysis id prefix (`u-`) decides when both are present.
 */
export function analysisObjectType(
	analysisId: string,
	analysis: AnalysisBody,
): 'file' | 'url' | undefined {
	const { file_info: file, url_info: url } = analysis.meta ?? {};
	if (url && (!file || analysisId.startsWith('u-'))) return 'url';
	return file ? 'file' : undefined;
}

/** The id of the analysed object (file SHA-256 or URL id), available once the analysis has data. */
export function analysedObjectId(
	analysis: AnalysisBody,
	type?: 'file' | 'url',
): string | undefined {
	const file = analysis.meta?.file_info?.sha256;
	const url = analysis.meta?.url_info?.id;
	return type === 'url' ? (url ?? file) : (file ?? url);
}

/**
 * Polls `/analyses/{id}` until it is completed. Every poll goes through the throttle.
 * Throws with the analysis id on timeout so the user can continue with Analysis > Get.
 */
export async function waitForAnalysis(ctx: VtContext, options: WaitOptions): Promise<AnalysisBody> {
	const now = options.now ?? Date.now;
	const nap = options.sleepFn ?? sleep;
	const startedAt = now();
	const node = ctx.getNode();
	const itemIndex = options.itemIndex;

	for (;;) {
		if (options.signal?.aborted) {
			throw new NodeOperationError(
				node,
				'The execution was cancelled while waiting for the analysis',
				{
					itemIndex,
					description: `Analysis ID: ${options.analysisId}`,
				},
			);
		}

		const body = await vtRequest<AnalysisBody>(ctx, {
			path: `/analyses/${encodeURIComponent(options.analysisId)}`,
			throttle: options.throttle,
		});
		if (body.data?.attributes?.status === 'completed') return body;

		if (now() - startedAt >= options.timeoutMs) {
			throw new NodeOperationError(
				node,
				`The analysis did not finish within ${Math.round(options.timeoutMs / 60000)} minute(s). Analysis ID: ${options.analysisId}`,
				{
					itemIndex,
					description:
						'Use Mode "Submit Only" and then Analysis > Get with this analysis ID to check on it later.',
				},
			);
		}

		let cancelled = false;
		try {
			await nap(options.intervalMs, options.signal);
		} catch {
			cancelled = true;
		}
		if (cancelled) {
			throw new NodeOperationError(
				node,
				'The execution was cancelled while waiting for the analysis',
				{
					itemIndex,
					description: `Analysis ID: ${options.analysisId}`,
				},
			);
		}
	}
}
