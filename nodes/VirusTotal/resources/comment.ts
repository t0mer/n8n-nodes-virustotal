import type { IDataObject, INodeProperties } from 'n8n-workflow';
import { paginate } from '../../../shared/paginate';
import { isoFromEpoch } from '../../../shared/summary';
import { vtRequest } from '../../../shared/transport';
import { show } from '../lookup';
import { objectRefProperties, readObjectRef } from '../objectRef';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['comment'] } },
		options: [
			{
				name: 'Create',
				value: 'create',
				action: 'Create a comment',
				description: 'Post a comment on an object. Comments are public.',
			},
			{
				name: 'Get Many',
				value: 'getAll',
				action: 'Get many comments',
				description: 'List the comments on an object',
			},
		],
		default: 'getAll',
	},
	...objectRefProperties('comment', ['create', 'getAll']),
	{
		displayName: 'Text',
		name: 'text',
		type: 'string',
		typeOptions: { rows: 4 },
		required: true,
		default: '',
		displayOptions: show('comment', 'create'),
		description: 'The comment. Comments are public and visible to all VirusTotal users.',
	},
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		displayOptions: show('comment', 'getAll'),
		description: 'Whether to return all results or only up to a given limit',
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: { minValue: 1 },
		default: 50,
		displayOptions: { show: { resource: ['comment'], operation: ['getAll'], returnAll: [false] } },
		description: 'Max number of results to return',
	},
];

function mapComment(item: IDataObject): IDataObject {
	const a = (item.attributes ?? {}) as IDataObject;
	const out: IDataObject = { id: item.id, text: a.text };
	const date = isoFromEpoch(a.date);
	if (date) out.date = date;
	if (a.votes) out.votes = a.votes as IDataObject;
	if (Array.isArray(a.tags)) out.tags = a.tags;
	return out;
}

export const commentResource: ResourceModule = {
	properties,
	handlers: {
		async create(ctx) {
			const ref = readObjectRef(ctx);
			const text = (ctx.fn.getNodeParameter('text', ctx.index) as string).trim();
			const body = await vtRequest<{ data?: IDataObject }>(ctx.fn, {
				method: 'POST',
				path: `${ref.path}/comments`,
				body: { data: { type: 'comment', attributes: { text } } },
				throttle: ctx.throttle,
			});
			return { ...mapComment(body.data ?? {}), objectType: ref.type, objectId: ref.id };
		},
		async getAll(ctx) {
			const ref = readObjectRef(ctx);
			const returnAll = ctx.fn.getNodeParameter('returnAll', ctx.index, false) as boolean;
			const limit = returnAll
				? undefined
				: (ctx.fn.getNodeParameter('limit', ctx.index, 50) as number);
			const items = await paginate(ctx.fn, {
				path: `${ref.path}/comments`,
				returnAll,
				limit,
				throttle: ctx.throttle,
			});
			return items.map(mapComment);
		},
	},
};
