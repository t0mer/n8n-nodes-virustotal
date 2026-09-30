import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { ResourceModule } from '../types';

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['url'] } },
		options: [
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
		displayOptions: show('url', 'getReport'),
		description: 'The URL to look up. It is encoded for you; never paste a VirusTotal ID here.',
	},
	{ ...lookupOptionsProperty, displayOptions: show('url', 'getReport') },
];

export const urlResource: ResourceModule = {
	properties,
	handlers: { getReport: reportHandler('url', 'url') },
};
