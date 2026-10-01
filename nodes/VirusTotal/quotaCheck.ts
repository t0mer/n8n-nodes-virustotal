import type { IDataObject, IExecuteFunctions, INodeProperties } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import type { Throttle } from '../../shared/throttle';
import { CREDENTIAL_NAME, vtRequest } from '../../shared/transport';
import { flattenQuotas } from './resources/account';

/** Batches estimated at this many requests or fewer never trigger a quota lookup. */
export const QUOTA_CHECK_MIN_REQUESTS = 10;

/** Name of the VirusTotal quota that holds the daily request budget. */
export const DAILY_QUOTA_NAME = 'api_requests_daily';

/** Requests for a scan or rescan that waits for the result: hash check, upload, a few polls, report. */
const SCAN_WAIT_REQUESTS = 5;
/** Requests for a scan or rescan that only submits: hash check or lookup, plus the submission. */
const SCAN_SUBMIT_REQUESTS = 2;
/** Pages assumed for an operation set to Return All. */
const RETURN_ALL_PAGES = 3;

export const batchOptionsProperty: INodeProperties = {
	displayName: 'Batch Options',
	name: 'batchOptions',
	type: 'collection',
	placeholder: 'Add Option',
	default: {},
	options: [
		{
			displayName: 'Check Quota Before Batch',
			name: 'checkQuotaBeforeBatch',
			type: 'boolean',
			default: false,
			description:
				'Whether to read your daily API quota once before a batch estimated at more than 10 requests, and fail early if the remaining budget is too small. The check costs one request.',
		},
	],
};

/**
 * Rough request count for one item. Lookups and listings cost 1. A scan or rescan costs 5 when it
 * waits for the result and 2 when it only submits. Return All is assumed to take 3 pages.
 * It is an estimate for failing early, not an exact count.
 */
export function estimateItemRequests(fn: IExecuteFunctions, index: number): number {
	const get = (name: string, fallback: unknown) => fn.getNodeParameter(name, index, fallback);
	const operation = String(get('operation', ''));
	if (operation === 'scan' || operation === 'rescan') {
		return get('mode', 'wait') === 'wait' ? SCAN_WAIT_REQUESTS : SCAN_SUBMIT_REQUESTS;
	}
	return get('returnAll', false) === true ? RETURN_ALL_PAGES : 1;
}

/** Fails early when the remaining daily quota cannot cover the estimated batch. Calls the API at most once. */
export async function checkQuotaBeforeBatch(
	fn: IExecuteFunctions,
	itemCount: number,
	throttle: Throttle,
): Promise<void> {
	const options = fn.getNodeParameter('batchOptions', 0, {}) as IDataObject;
	if (options.checkQuotaBeforeBatch !== true) return;

	let estimate = 0;
	for (let i = 0; i < itemCount; i++) estimate += estimateItemRequests(fn, i);
	if (estimate <= QUOTA_CHECK_MIN_REQUESTS) return;

	const credentials = await fn.getCredentials(CREDENTIAL_NAME);
	const apiKey = encodeURIComponent(String(credentials.apiKey));
	const body = await vtRequest<{ data?: IDataObject }>(fn, {
		path: `/users/${apiKey}/overall_quotas`,
		throttle,
	});
	const daily = flattenQuotas(body.data)
		.map((item) => item.quota as IDataObject)
		.find((quota) => quota.name === DAILY_QUOTA_NAME);
	const remaining = daily?.remaining;
	if (typeof remaining !== 'number' || remaining >= estimate) return;

	throw new NodeOperationError(
		fn.getNode(),
		`Not enough daily VirusTotal quota: this batch needs about ${estimate} requests but ${remaining} remain today`,
		{
			description:
				'Reduce the number of input items, split the batch across days, or use a key with a larger quota. Turn off "Check Quota Before Batch" to run anyway.',
		},
	);
}
