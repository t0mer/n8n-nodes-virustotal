import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['file'] } },
		options: [
			{
				name: 'Get Report',
				value: 'getReport',
				action: 'Get a file report',
				description: 'Get the report for a file hash',
			},
		],
		default: 'getReport',
	},
	{
		displayName: 'Hash',
		name: 'hash',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
		displayOptions: show('file', 'getReport'),
		description: 'An MD5, SHA-1 or SHA-256 hash',
	},
	{ ...lookupOptionsProperty, displayOptions: show('file', 'getReport') },
];

export const fileResource: ResourceModule = {
	properties,
	handlers: { getReport: reportHandler('file', 'hash') },
};
