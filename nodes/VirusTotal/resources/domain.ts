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
	{ name: 'Siblings', value: 'siblings' },
	{ name: 'Subdomains', value: 'subdomains' },
	{ name: 'URLs', value: 'urls', premium: true },
];

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['domain'] } },
		options: [
			{
				name: 'Get DNS Resolutions',
				value: 'getDnsResolutions',
				action: 'Get DNS resolutions of a domain',
				description: 'Shortcut for the Resolutions relationship',
			},
			{
				name: 'Get Related',
				value: 'getRelated',
				action: 'Get objects related to a domain',
				description: 'List related objects such as subdomains or communicating files',
			},
			{
				name: 'Get Report',
				value: 'getReport',
				action: 'Get a domain report',
				description: 'Get the report for a domain',
			},
		],
		default: 'getReport',
	},
	{
		displayName: 'Domain',
		name: 'domain',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. example.com',
		displayOptions: show('domain', 'getReport', 'getRelated', 'getDnsResolutions'),
		description: 'The domain name to look up',
	},
	{ ...lookupOptionsProperty, displayOptions: show('domain', 'getReport') },
	...relatedProperties('domain', 'getRelated', RELATIONSHIPS, 'subdomains'),
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		displayOptions: show('domain', 'getDnsResolutions'),
		description: 'Whether to return all results or only up to a given limit',
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: { minValue: 1 },
		default: 50,
		displayOptions: {
			show: { resource: ['domain'], operation: ['getDnsResolutions'], returnAll: [false] },
		},
		description: 'Max number of results to return',
	},
];

export const domainResource: ResourceModule = {
	properties,
	handlers: {
		getDnsResolutions: relatedHandler('domain', 'domain', 'resolutions'),
		getRelated: relatedHandler('domain', 'domain'),
		getReport: reportHandler('domain', 'domain'),
	},
};
