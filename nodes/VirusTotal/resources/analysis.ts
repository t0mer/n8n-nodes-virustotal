import type { INodeProperties } from 'n8n-workflow';
import { isoFromEpoch } from '../../../shared/summary';
import type { AnalysisBody } from '../../../shared/poll';
import { analysedObjectId, analysisObjectType } from '../../../shared/poll';
import { vtRequest } from '../../../shared/transport';
import { show } from '../lookup';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['analysis'] } },
		options: [
			{
				name: 'Get',
				value: 'get',
				action: 'Get an analysis',
				description: 'Check the status and results of a scan or rescan',
			},
		],
		default: 'get',
	},
	{
		displayName: 'Analysis ID',
		name: 'analysisId',
		type: 'string',
		required: true,
		default: '',
		displayOptions: show('analysis', 'get'),
		description: 'The analysis ID returned by a Scan or Rescan operation in Submit Only mode',
	},
];

export const analysisResource: ResourceModule = {
	properties,
	handlers: {
		async get(ctx) {
			const analysisId = (ctx.fn.getNodeParameter('analysisId', ctx.index) as string).trim();
			ctx.setIndicator(analysisId);
			const body = await vtRequest<AnalysisBody>(ctx.fn, {
				path: `/analyses/${encodeURIComponent(analysisId)}`,
				throttle: ctx.throttle,
			});
			const attributes = body.data?.attributes ?? {};
			const itemType = analysisObjectType(analysisId, body);
			const itemId = analysedObjectId(body, itemType);
			return {
				analysisId,
				status: attributes.status ?? 'unknown',
				completed: attributes.status === 'completed',
				date: isoFromEpoch((attributes as { date?: unknown }).date),
				stats: attributes.stats ?? {},
				...(itemId ? { itemType, itemId } : {}),
			};
		},
	},
};
