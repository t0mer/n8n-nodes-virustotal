import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['ip'] } },
		options: [
			{
				name: 'Get Report',
				value: 'getReport',
				action: 'Get a IP address report',
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
		displayOptions: show('ip', 'getReport'),
		description: 'The IPv4 or IPv6 address to look up',
	},
	{ ...lookupOptionsProperty, displayOptions: show('ip', 'getReport') },
];

export const ipResource: ResourceModule = {
	properties,
	handlers: { getReport: reportHandler('ip_address', 'ip') },
};
