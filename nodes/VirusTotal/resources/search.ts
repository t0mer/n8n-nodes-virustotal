import type { IDataObject, INodeProperties } from 'n8n-workflow';
import { paginate } from '../../../shared/paginate';
import { show } from '../lookup';
import { requirePremium } from '../premium';
import { mapRelated } from '../related';
import type { OperationContext, ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['search'] } },
		options: [
			{
				name: 'Intelligence Search',
				value: 'intelligenceSearch',
				action: 'Search with intelligence',
				description:
					'Premium only. Search the VirusTotal corpus with Intelligence query modifiers such as positives:5+ or type:pdf.',
			},
			{
				name: 'Search',
				value: 'search',
				action: 'Search for objects',
				description:
					'Basic search by file hash, URL, domain, IP address or comment. Use Indicator > Lookup to check a known indicator.',
			},
		],
		default: 'search',
	},
	{
		displayName: 'Query',
		name: 'query',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 44d88612fea8a8f36de82e1278abb02f',
		displayOptions: show('search', 'search', 'intelligenceSearch'),
		description:
			'A file hash, URL, domain, IP address or comment text. Intelligence Search accepts query modifiers.',
	},
	{
		displayName: 'Order',
		name: 'order',
		type: 'string',
		default: '',
		placeholder: 'e.g. last_submission_date-',
		displayOptions: show('search', 'intelligenceSearch'),
		description:
			'Sort key, with a trailing - for descending order. Leave empty for the default order.',
	},
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		displayOptions: show('search', 'search', 'intelligenceSearch'),
		description: 'Whether to return all results or only up to a given limit',
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: { minValue: 1 },
		default: 50,
		displayOptions: {
			show: {
				resource: ['search'],
				operation: ['intelligenceSearch', 'search'],
				returnAll: [false],
			},
		},
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
		displayOptions: show('search', 'search', 'intelligenceSearch'),
	},
];

async function runSearch(ctx: OperationContext, path: string, extraQs: IDataObject = {}) {
	const query = (ctx.fn.getNodeParameter('query', ctx.index) as string).trim();
	ctx.setIndicator(query);
	const returnAll = ctx.fn.getNodeParameter('returnAll', ctx.index, false) as boolean;
	const limit = returnAll ? undefined : (ctx.fn.getNodeParameter('limit', ctx.index, 50) as number);
	const output = ctx.fn.getNodeParameter('output', ctx.index, 'summary') as string;
	const items = await paginate(ctx.fn, {
		path,
		qs: { query, ...extraQs },
		returnAll,
		limit,
		throttle: ctx.throttle,
	});
	return output === 'raw' ? items : items.map(mapRelated);
}

export const searchResource: ResourceModule = {
	properties,
	handlers: {
		async intelligenceSearch(ctx) {
			requirePremium(ctx, 'Intelligence Search');
			const order = (ctx.fn.getNodeParameter('order', ctx.index, '') as string).trim();
			return runSearch(ctx, '/intelligence/search', order ? { order } : {});
		},
		search: (ctx) => runSearch(ctx, '/search'),
	},
};
