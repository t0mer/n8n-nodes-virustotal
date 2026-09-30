import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, reportHandler, show } from '../lookup';
import type { Relationship } from '../related';
import { relatedHandler, relatedProperties } from '../related';
import type { ResourceModule } from '../types';

const RELATIONSHIPS: Relationship[] = [
	{ name: 'Bundled Files', value: 'bundled_files', premium: true },
	{ name: 'Comments', value: 'comments' },
	{ name: 'Contacted Domains', value: 'contacted_domains' },
	{ name: 'Contacted IPs', value: 'contacted_ips' },
	{ name: 'Contacted URLs', value: 'contacted_urls' },
	{ name: 'Dropped Files', value: 'dropped_files' },
	{ name: 'Embedded Domains', value: 'embedded_domains', premium: true },
	{ name: 'Embedded IPs', value: 'embedded_ips', premium: true },
	{ name: 'Embedded URLs', value: 'embedded_urls', premium: true },
	{ name: 'Execution Parents', value: 'execution_parents' },
	{ name: 'ITW Domains', value: 'itw_domains', premium: true },
	{ name: 'ITW IPs', value: 'itw_ips', premium: true },
	{ name: 'ITW URLs', value: 'itw_urls', premium: true },
	{ name: 'Similar Files', value: 'similar_files', premium: true },
];

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['file'] } },
		options: [
			{
				name: 'Get Related',
				value: 'getRelated',
				action: 'Get objects related to a file',
				description: 'List related objects such as contacted domains or dropped files',
			},
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
		displayOptions: show('file', 'getReport', 'getRelated'),
		description: 'An MD5, SHA-1 or SHA-256 hash',
	},
	{ ...lookupOptionsProperty, displayOptions: show('file', 'getReport') },
	...relatedProperties('file', 'getRelated', RELATIONSHIPS, 'contacted_domains'),
];

export const fileResource: ResourceModule = {
	properties,
	handlers: {
		getRelated: relatedHandler('file', 'hash'),
		getReport: reportHandler('file', 'hash'),
	},
};
