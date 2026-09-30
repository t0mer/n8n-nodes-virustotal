import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { Relationship } from '../related';
import { relatedHandler, relatedProperties } from '../related';
import type { ResourceModule } from '../types';

const RELATIONSHIPS: Relationship[] = [
	{ name: 'Comments', value: 'comments' },
	{ name: 'Communicating Files', value: 'communicating_files', premium: true },
	{ name: 'Downloaded Files', value: 'downloaded_files', premium: true },
	{ name: 'Historical SSL Certificates', value: 'historical_ssl_certificates' },
	{ name: 'Historical WHOIS', value: 'historical_whois' },
	{ name: 'Referrer Files', value: 'referrer_files', premium: true },
	{ name: 'Resolutions', value: 'resolutions' },
	{ name: 'URLs', value: 'urls', premium: true },
];

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['ip'] } },
		options: [
			{
				name: 'Get Related',
				value: 'getRelated',
				action: 'Get objects related to an IP address',
				description: 'List related objects such as resolutions or communicating files',
			},
			{
				name: 'Get Report',
				value: 'getReport',
				action: 'Get an IP address report',
				description: 'Get the report for an IPv4 or IPv6 address',
			},
		],
		default: 'getReport',
	},
	{
		displayName: 'IP Address',
		name: 'ip',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 8.8.8.8 or 2001:db8::1',
		displayOptions: show('ip', 'getReport', 'getRelated'),
		description: 'The IPv4 or IPv6 address to look up',
	},
	{ ...lookupOptionsProperty, displayOptions: show('ip', 'getReport') },
	...relatedProperties('ip', 'getRelated', RELATIONSHIPS, 'resolutions'),
];

export const ipResource: ResourceModule = {
	properties,
	handlers: {
		getRelated: relatedHandler('ip_address', 'ip'),
		getReport: reportHandler('ip_address', 'ip'),
	},
};
