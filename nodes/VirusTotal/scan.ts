import type { IDataObject, INodeProperties } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import type { IndicatorType } from '../../shared/indicator';
import { COLLECTION } from '../../shared/objects';
import type { AnalysisBody } from '../../shared/poll';
import {
	DEFAULT_TIMEOUT_MINUTES,
	analysedObjectId,
	defaultPollIntervalSeconds,
	waitForAnalysis,
} from '../../shared/poll';
import { summarize, unknownItem } from '../../shared/summary';
import { vtLookup } from '../../shared/transport';
import { sha256Hex } from '../../shared/upload';
import { readLookupOptions, show } from './lookup';
import type { OperationContext } from './types';

export type ScanMode = 'wait' | 'submit';

/** Mode and wait settings shared by every Scan and Rescan operation. */
export function scanProperties(resource: string, operations: string[]): INodeProperties[] {
	return [
		{
			displayName: 'Mode',
			name: 'mode',
			type: 'options',
			options: [
				{
					name: 'Submit Only',
					value: 'submit',
					description:
						'Return the analysis ID immediately. Use Analysis > Get to check on it later.',
				},
				{
					name: 'Wait for Result',
					value: 'wait',
					description: 'Wait for the analysis to finish and return the report',
				},
			],
			default: 'wait',
			displayOptions: show(resource, ...operations),
		},
		{
			displayName: 'Scan Options',
			name: 'scanOptions',
			type: 'collection',
			placeholder: 'Add Option',
			default: {},
			displayOptions: { show: { resource: [resource], operation: operations, mode: ['wait'] } },
			options: [
				{
					displayName: 'Poll Interval (Seconds)',
					name: 'pollIntervalSeconds',
					type: 'number',
					typeOptions: { minValue: 0 },
					default: 0,
					description:
						'Seconds between status checks. 0 picks max(20, 60 / requests per minute x 1.5), which leaves quota headroom on the public tier.',
				},
				{
					displayName: 'Timeout (Minutes)',
					name: 'timeoutMinutes',
					type: 'number',
					typeOptions: { minValue: 1 },
					default: DEFAULT_TIMEOUT_MINUTES,
					description: 'How long to wait for the analysis before failing with the analysis ID',
				},
			],
		},
	];
}

export function readMode(ctx: OperationContext): ScanMode {
	return ctx.fn.getNodeParameter('mode', ctx.index, 'wait') as ScanMode;
}

function permalink(type: IndicatorType, id: string): string {
	return `https://www.virustotal.com/gui/${type}/${id}`;
}

/** Turns a scan submission into the operation's result: an analysis reference or the finished report. */
export async function finishScan(
	ctx: OperationContext,
	type: 'file' | 'url',
	indicator: string,
	analysisId: string,
	knownId?: string,
	extra: IDataObject = {},
): Promise<IDataObject> {
	const objectId = knownId ?? (type === 'url' ? sha256Hex(Buffer.from(indicator)) : indicator);

	if (readMode(ctx) === 'submit') {
		return {
			type,
			indicator,
			analysisId,
			status: 'submitted',
			permalink: permalink(type, objectId),
			...extra,
		};
	}

	const scanOptions = ctx.fn.getNodeParameter('scanOptions', ctx.index, {}) as {
		pollIntervalSeconds?: number;
		timeoutMinutes?: number;
	};
	const intervalSeconds =
		scanOptions.pollIntervalSeconds || defaultPollIntervalSeconds(ctx.throttle.requestsPerMinute);
	const analysis: AnalysisBody = await waitForAnalysis(ctx.fn, {
		analysisId,
		throttle: ctx.throttle,
		intervalMs: intervalSeconds * 1000,
		timeoutMs: (scanOptions.timeoutMinutes || DEFAULT_TIMEOUT_MINUTES) * 60_000,
		signal: ctx.fn.getExecutionCancelSignal(),
		itemIndex: ctx.index,
	});

	const finalId = analysedObjectId(analysis, type) ?? objectId;
	const report = await vtLookup<IDataObject>(ctx.fn, {
		// finalId is already a VirusTotal object id (file hash or URL SHA-256), so it is not re-encoded.
		path: `/${COLLECTION[type]}/${finalId}`,
		throttle: ctx.throttle,
	});
	return renderReport(ctx, type, indicator, report, { analysisId, ...extra });
}

/** Renders a fetched report (or null for unknown) as a Summary or raw object, plus extra fields. */
export function renderReport(
	ctx: OperationContext,
	type: 'file' | 'url',
	indicator: string,
	report: IDataObject | null,
	extra: IDataObject = {},
): IDataObject {
	const options = readLookupOptions(ctx);
	if (!report) return { ...unknownItem(type, indicator), ...extra };
	if (options.output === 'raw') return { ...((report.data as IDataObject) ?? report), ...extra };
	return {
		...summarize(type, report, {
			indicator,
			includeEngines: options.includeEngines,
			thresholds: {
				malicious: options.maliciousThreshold,
				suspicious: options.suspiciousThreshold,
			},
		}),
		...extra,
	};
}

/** The analysis id in a scan/submit/rescan response. */
export function analysisIdOf(ctx: OperationContext, body: IDataObject): string {
	const id = (body.data as IDataObject | undefined)?.id;
	if (typeof id !== 'string' || !id) {
		throw new NodeOperationError(ctx.fn.getNode(), 'VirusTotal did not return an analysis ID', {
			itemIndex: ctx.index,
		});
	}
	return id;
}
