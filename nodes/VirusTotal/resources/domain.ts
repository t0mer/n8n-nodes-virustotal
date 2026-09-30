import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['domain'] } },
		options: [
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
		displayOptions: show('domain', 'getReport'),
		description: 'The domain name to look up',
	},
	{ ...lookupOptionsProperty, displayOptions: show('domain', 'getReport') },
];

export const domainResource: ResourceModule = {
	properties,
	handlers: { getReport: reportHandler('domain', 'domain') },
};
