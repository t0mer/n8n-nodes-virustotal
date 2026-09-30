import type { IDataObject, INodeProperties } from 'n8n-workflow';
import { paginate } from '../../../shared/paginate';
import { isoFromEpoch } from '../../../shared/summary';
import { vtRequestRaw } from '../../../shared/transport';
import { show } from '../lookup';
import { objectRefProperties, readObjectRef } from '../objectRef';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['vote'] } },
		options: [
			{
				name: 'Create',
				value: 'create',
				action: 'Create a vote',
				description: 'Vote an object harmless or malicious',
			},
			{
				name: 'Get Many',
				value: 'getAll',
				action: 'Get many votes',
				description: 'List the votes on an object',
			},
		],
		default: 'getAll',
	},
	...objectRefProperties('vote', ['create', 'getAll']),
	{
		displayName: 'Verdict',
		name: 'verdict',
		type: 'options',
		options: [
			{ name: 'Harmless', value: 'harmless' },
			{ name: 'Malicious', value: 'malicious' },
		],
		default: 'harmless',
		displayOptions: show('vote', 'create'),
	},
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		displayOptions: show('vote', 'getAll'),
		description: 'Whether to return all results or only up to a given limit',
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: { minValue: 1 },
		default: 50,
		displayOptions: { show: { resource: ['vote'], operation: ['getAll'], returnAll: [false] } },
		description: 'Max number of results to return',
	},
];

function mapVote(item: IDataObject): IDataObject {
	const a = (item.attributes ?? {}) as IDataObject;
	const out: IDataObject = { id: item.id, verdict: a.verdict };
	const date = isoFromEpoch(a.date);
	if (date) out.date = date;
	if (typeof a.value === 'number') out.value = a.value;
	return out;
}

export const voteResource: ResourceModule = {
	properties,
	handlers: {
		async create(ctx) {
			const ref = readObjectRef(ctx);
			const verdict = ctx.fn.getNodeParameter('verdict', ctx.index) as string;
			const res = await vtRequestRaw<{ data?: IDataObject }>(ctx.fn, {
				method: 'POST',
				path: `${ref.path}/votes`,
				body: { data: { type: 'vote', attributes: { verdict } } },
				acceptStatus: [409],
				throttle: ctx.throttle,
			});
			// A duplicate vote is not a failure: the object already carries the caller's vote.
			if (res.statusCode === 409) {
				return {
					created: false,
					alreadyVoted: true,
					verdict,
					objectType: ref.type,
					objectId: ref.id,
				};
			}
			return {
				created: true,
				...mapVote(res.body.data ?? {}),
				objectType: ref.type,
				objectId: ref.id,
			};
		},
		async getAll(ctx) {
			const ref = readObjectRef(ctx);
			const returnAll = ctx.fn.getNodeParameter('returnAll', ctx.index, false) as boolean;
			const limit = returnAll
				? undefined
				: (ctx.fn.getNodeParameter('limit', ctx.index, 50) as number);
			const items = await paginate(ctx.fn, {
				path: `${ref.path}/votes`,
				returnAll,
				limit,
				throttle: ctx.throttle,
			});
			return items.map(mapVote);
		},
	},
};
