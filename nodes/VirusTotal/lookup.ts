import type { IDataObject, INodeProperties } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import type { IndicatorType } from '../../shared/indicator';
import { detectIndicator } from '../../shared/indicator';
import { objectPath } from '../../shared/objects';
import { summarize } from '../../shared/summary';
import { vtLookup } from '../../shared/transport';
import type { OperationContext, OperationHandler } from './types';

export interface LookupOptions {
	includeEngines: boolean;
	maliciousThreshold: number;
	onNotFound: 'unknown' | 'error';
	output: 'summary' | 'raw';
	suspiciousThreshold: number;
}

/** The shared "Options" collection shown on every lookup operation. */
export const lookupOptionsProperty: INodeProperties = {
	displayName: 'Options',
	name: 'options',
	type: 'collection',
	placeholder: 'Add Option',
	default: {},
	options: [
		{
			displayName: 'Include Engine Results',
			name: 'includeEngines',
			type: 'boolean',
			default: false,
			description:
				'Whether to add the engines that flagged the indicator (malicious or suspicious only)',
		},
		{
			displayName: 'Malicious Threshold',
			name: 'maliciousThreshold',
			type: 'number',
			typeOptions: { minValue: 1 },
			default: 3,
			description: 'Number of engines that must flag the indicator for the verdict to be malicious',
		},
		{
			displayName: 'On Not Found',
			name: 'onNotFound',
			type: 'options',
			options: [
				{ name: 'Return Unknown Item', value: 'unknown' },
				{ name: 'Throw Error', value: 'error' },
			],
			default: 'unknown',
			description:
				'What to do when VirusTotal has never seen the indicator. Unseen hashes are normal, so the default does not fail the workflow.',
		},
		{
			displayName: 'Output',
			name: 'output',
			type: 'options',
			options: [
				{ name: 'Raw', value: 'raw', description: 'The VirusTotal object, unchanged' },
				{ name: 'Summary', value: 'summary', description: 'A normalized result with a verdict' },
			],
			default: 'summary',
		},
		{
			displayName: 'Suspicious Threshold',
			name: 'suspiciousThreshold',
			type: 'number',
			typeOptions: { minValue: 1 },
			default: 1,
			description:
				'Number of malicious plus suspicious engines needed for the verdict to be suspicious. The verdict is a heuristic, not a guarantee.',
		},
	],
};

export function readLookupOptions(ctx: OperationContext): LookupOptions {
	const raw = ctx.fn.getNodeParameter('options', ctx.index, {}) as Partial<LookupOptions>;
	return {
		includeEngines: raw.includeEngines ?? false,
		maliciousThreshold: raw.maliciousThreshold ?? 3,
		onNotFound: raw.onNotFound ?? 'unknown',
		output: raw.output ?? 'summary',
		suspiciousThreshold: raw.suspiciousThreshold ?? 1,
	};
}

/** Fetches one object and returns it as a Summary or as raw VirusTotal data. */
export async function lookupObject(
	ctx: OperationContext,
	type: IndicatorType,
	indicator: string,
	options: LookupOptions,
): Promise<IDataObject> {
	ctx.setIndicator(indicator);
	const body = await vtLookup<IDataObject>(ctx.fn, {
		path: objectPath(type, indicator),
		throttle: ctx.throttle,
	});

	if (body === null && options.onNotFound === 'error') {
		throw new NodeOperationError(ctx.fn.getNode(), `"${indicator}" was not found on VirusTotal`, {
			itemIndex: ctx.index,
			description: 'VirusTotal has no report for this indicator yet. Scan or submit it first.',
		});
	}

	if (options.output === 'raw' && body !== null) return (body.data as IDataObject) ?? body;

	return summarize(type, body, {
		indicator,
		includeEngines: options.includeEngines,
		thresholds: { malicious: options.maliciousThreshold, suspicious: options.suspiciousThreshold },
	});
}

/** Shorthand for a parameter's displayOptions. */
export function show(resource: string, ...operations: string[]) {
	return { show: { resource: [resource], operation: operations } };
}

/** Reads a string parameter and checks that it is an indicator of the expected type. */
export function readTyped(ctx: OperationContext, param: string, type: IndicatorType): string {
	const input = ctx.fn.getNodeParameter(param, ctx.index) as string;
	ctx.setIndicator(input);
	const detected = detectIndicator(input, type);
	if (!detected.ok) {
		throw new NodeOperationError(ctx.fn.getNode(), detected.reason, { itemIndex: ctx.index });
	}
	return detected.indicator;
}

/** Handler for a "Get Report" operation of one object type. */
export function reportHandler(type: IndicatorType, param: string): OperationHandler {
	return async (ctx) =>
		lookupObject(ctx, type, readTyped(ctx, param, type), readLookupOptions(ctx));
}
