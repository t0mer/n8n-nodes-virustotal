import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { Relationship } from '../related';
import { relatedHandler, relatedProperties } from '../related';
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
		displayOptions: show('url', 'getReport', 'getRelated'),
		description: 'The URL to look up. It is encoded for you; never paste a VirusTotal ID here.',
	},
	{ ...lookupOptionsProperty, displayOptions: show('url', 'getReport') },
	...relatedProperties('url', 'getRelated', RELATIONSHIPS, 'downloaded_files'),
];

export const urlResource: ResourceModule = {
	properties,
	handlers: {
		getRelated: relatedHandler('url', 'url'),
		getReport: reportHandler('url', 'url'),
	},
};
