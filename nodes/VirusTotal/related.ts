import type { IDataObject, INodeProperties, INodePropertyOptions } from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';
import type { IndicatorType } from '../../shared/indicator';
import { objectPath } from '../../shared/objects';
import { paginate } from '../../shared/paginate';
import { summarize } from '../../shared/summary';
import { readTyped, show } from './lookup';
import type { OperationHandler } from './types';

export interface Relationship {
	name: string;
	value: string;
	/** Shown in the dropdown description when the relationship may need a Premium key. */
	premium?: boolean;
}

function toOption(r: Relationship): INodePropertyOptions {
	return {
		name: r.name,
		value: r.value,
		description: r.premium ? 'May require a Premium API key' : undefined,
	};
}

/** Relationship, Return All, Limit and Output parameters for a "Get Related" operation. */
export function relatedProperties(
	resource: string,
	operation: string,
	relationships: Relationship[],
	defaultRelationship: string,
): INodeProperties[] {
	const displayOptions = show(resource, operation);
	return [
		{
			displayName: 'Relationship',
			name: 'relationship',
			type: 'options',
			options: [...relationships].sort((a, b) => a.name.localeCompare(b.name)).map(toOption),
			default: defaultRelationship,
			displayOptions,
			description: 'The kind of related objects to fetch',
		},
		{
			displayName: 'Return All',
			name: 'returnAll',
			type: 'boolean',
			default: false,
			displayOptions,
			description: 'Whether to return all results or only up to a given limit',
		},
		{
			displayName: 'Limit',
			name: 'limit',
			type: 'number',
			typeOptions: { minValue: 1 },
			default: 50,
			displayOptions: { show: { ...displayOptions.show, returnAll: [false] } },
			description: 'Max number of results to return',
		},
		{
			displayName: 'Output',
			name: 'output',
			type: 'options',
			options: [
				{ name: 'Raw', value: 'raw', description: 'The VirusTotal objects, unchanged' },
				{
					name: 'Summary',
					value: 'summary',
					description: 'Normalized results for files, URLs, domains and IPs',
				},
			],
			default: 'summary',
			displayOptions,
		},
	];
}

const SUMMARIZABLE: Record<string, IndicatorType> = {
	file: 'file',
	url: 'url',
	domain: 'domain',
	ip_address: 'ip_address',
};

/** Summarizes related files/URLs/domains/IPs; flattens everything else to `{ id, type, ...attributes }`. */
export function mapRelated(item: IDataObject): IDataObject {
	const type = SUMMARIZABLE[String(item.type)];
	const attributes = (item.attributes ?? {}) as IDataObject;
	if (!type) return { id: item.id, type: item.type, ...attributes };
	const indicator = type === 'url' ? String(attributes.url ?? item.id) : String(item.id);
	return summarize(type, { data: item }, { indicator });
}

function needsPremium(error: unknown): boolean {
	return error instanceof NodeApiError && error.httpCode === '403';
}

/** Handler that lists the objects related to one object. */
export function relatedHandler(
	type: IndicatorType,
	param: string,
	fixedRelationship?: string,
): OperationHandler {
	return async (ctx) => {
		const id = readTyped(ctx, param, type);
		const relationship =
			fixedRelationship ?? (ctx.fn.getNodeParameter('relationship', ctx.index) as string);
		const returnAll = ctx.fn.getNodeParameter('returnAll', ctx.index, false) as boolean;
		const limit = returnAll
			? undefined
			: (ctx.fn.getNodeParameter('limit', ctx.index, 50) as number);
		const output = ctx.fn.getNodeParameter('output', ctx.index, 'summary') as string;

		let items: IDataObject[] = [];
		let failure: unknown;
		try {
			items = await paginate(ctx.fn, {
				path: `${objectPath(type, id)}/${encodeURIComponent(relationship)}`,
				returnAll,
				limit,
				throttle: ctx.throttle,
			});
		} catch (error) {
			failure = error;
		}

		if (needsPremium(failure)) {
			throw new NodeOperationError(
				ctx.fn.getNode(),
				`The "${relationship}" relationship requires a Premium VirusTotal API key`,
				{ itemIndex: ctx.index },
			);
		}
		if (failure) throw failure;

		return output === 'raw' ? items : items.map(mapRelated);
	};
}
