import type { IDataObject, INodeProperties } from 'n8n-workflow';
import { CREDENTIAL_NAME, vtRequest } from '../../../shared/transport';
import { show } from '../lookup';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['account'] } },
		options: [
			{
				name: 'Get Popular Threat Categories',
				value: 'getPopularThreatCategories',
				action: 'Get popular threat categories',
				description: 'List the threat categories VirusTotal uses to classify files',
			},
			{
				name: 'Get Quotas',
				value: 'getQuotas',
				action: 'Get API quotas',
				description:
					'Get used and allowed API quotas, so a workflow can check its budget before a bulk job',
			},
		],
		default: 'getQuotas',
	},
	{
		displayName: 'Quota lookups cost one request each and count toward the same quota',
		name: 'quotaNotice',
		type: 'notice',
		default: '',
		displayOptions: show('account', 'getQuotas'),
	},
];

interface QuotaEntry {
	allowed?: unknown;
	used?: unknown;
}

/** One `{ quota: { name, used, allowed, remaining } }` item per quota, preferring the user-level counters. */
export function flattenQuotas(data: IDataObject | undefined): IDataObject[] {
	const items: IDataObject[] = [];
	for (const [name, value] of Object.entries(data ?? {})) {
		const scopes = (value ?? {}) as { user?: QuotaEntry; group?: QuotaEntry };
		const entry = scopes.user ?? scopes.group;
		const allowed = entry?.allowed;
		const used = entry?.used;
		if (typeof allowed !== 'number' && typeof used !== 'number') continue;
		const quota: IDataObject = {
			name,
			used: typeof used === 'number' ? used : 0,
			allowed: typeof allowed === 'number' ? allowed : null,
		};
		if (typeof allowed === 'number')
			quota.remaining = Math.max(0, allowed - (quota.used as number));
		items.push({ quota });
	}
	return items;
}

export const accountResource: ResourceModule = {
	properties,
	handlers: {
		async getPopularThreatCategories(ctx) {
			const body = await vtRequest<{ data?: unknown[] }>(ctx.fn, {
				path: '/popular_threat_categories',
				throttle: ctx.throttle,
			});
			return { categories: Array.isArray(body.data) ? body.data : [] } as IDataObject;
		},
		async getQuotas(ctx) {
			const credentials = await ctx.fn.getCredentials(CREDENTIAL_NAME);
			const apiKey = encodeURIComponent(String(credentials.apiKey));
			const body = await vtRequest<{ data?: IDataObject }>(ctx.fn, {
				path: `/users/${apiKey}/overall_quotas`,
				throttle: ctx.throttle,
			});
			return flattenQuotas(body.data);
		},
	},
};
