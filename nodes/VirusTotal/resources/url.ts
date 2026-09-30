import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, readTyped, reportHandler, show } from '../lookup';
import type { Relationship } from '../related';
import { relatedHandler, relatedProperties } from '../related';
import { analysisIdOf, finishScan, scanProperties } from '../scan';
import { objectPath } from '../../../shared/objects';
import { vtRequest } from '../../../shared/transport';
import type { ResourceModule } from '../types';

const RELATIONSHIPS: Relationship[] = [
	{ name: 'Comments', value: 'comments' },
	{ name: 'Contacted Domains', value: 'contacted_domains' },
	{ name: 'Contacted IPs', value: 'contacted_ips' },
	{ name: 'Downloaded Files', value: 'downloaded_files' },
	{ name: 'Last Serving IP Address', value: 'last_serving_ip_address' },
	{ name: 'Redirecting URLs', value: 'redirecting_urls' },
	{ name: 'Redirects To', value: 'redirects_to', premium: true },
	{ name: 'Referrer Files', value: 'referrer_files', premium: true },
];

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['url'] } },
		options: [
			{
				name: 'Get Related',
				value: 'getRelated',
				action: 'Get objects related to a URL',
				description: 'List related objects such as downloaded files or redirects',
			},
			{
				name: 'Get Report',
				value: 'getReport',
				action: 'Get a URL report',
				description: 'Get the report for a URL. The URL ID is computed for you.',
			},
			{
				name: 'Rescan',
				value: 'rescan',
				action: 'Rescan a URL',
				description: 'Ask VirusTotal to analyse an already known URL again',
			},
			{
				name: 'Scan',
				value: 'scan',
				action: 'Scan a URL',
				description:
					'Submit a URL for analysis. Submitted URLs become visible to VirusTotal users, so do not include tokens or credentials in query strings.',
			},
		],
		default: 'getReport',
	},
	{
		displayName: 'URL',
		name: 'url',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. https://example.com/login',
		displayOptions: show('url', 'getReport', 'getRelated', 'scan', 'rescan'),
		description: 'The URL to look up. It is encoded for you; never paste a VirusTotal ID here.',
	},
	...scanProperties('url', ['scan', 'rescan']),
	{ ...lookupOptionsProperty, displayOptions: show('url', 'getReport') },
	{
		...lookupOptionsProperty,
		displayOptions: { show: { resource: ['url'], operation: ['scan', 'rescan'], mode: ['wait'] } },
	},
	...relatedProperties('url', 'getRelated', RELATIONSHIPS, 'downloaded_files'),
];

export const urlResource: ResourceModule = {
	properties,
	handlers: {
		getRelated: relatedHandler('url', 'url'),
		getReport: reportHandler('url', 'url'),
		async rescan(ctx) {
			const url = readTyped(ctx, 'url', 'url');
			const body = await vtRequest(ctx.fn, {
				method: 'POST',
				path: `${objectPath('url', url)}/analyse`,
				throttle: ctx.throttle,
			});
			return finishScan(ctx, 'url', url, analysisIdOf(ctx, body));
		},
		async scan(ctx) {
			const url = readTyped(ctx, 'url', 'url');
			const body = await vtRequest(ctx.fn, {
				method: 'POST',
				path: '/urls',
				body: { url },
				form: true,
				throttle: ctx.throttle,
			});
			return finishScan(ctx, 'url', url, analysisIdOf(ctx, body));
		},
	},
};
