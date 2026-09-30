import type { INodeProperties } from 'n8n-workflow';
import { lookupOptionsProperty, readTyped, reportHandler, show } from '../lookup';
import type { Relationship } from '../related';
import { relatedHandler, relatedProperties } from '../related';
import { analysisIdOf, finishScan, renderReport, scanProperties } from '../scan';
import { uploadFile } from '../../../shared/upload';
import { vtRequest } from '../../../shared/transport';
import { objectPath } from '../../../shared/objects';
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
			{
				name: 'Rescan',
				value: 'rescan',
				action: 'Rescan a file',
				description: 'Ask VirusTotal to analyse an already known file again',
			},
			{
				name: 'Scan',
				value: 'scan',
				action: 'Scan a file',
				description:
					'Upload a file for analysis. Uploaded files are shared with the VirusTotal community and security partners, so do not use this for confidential files.',
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
		displayOptions: show('file', 'getReport', 'getRelated', 'rescan'),
		description: 'An MD5, SHA-1 or SHA-256 hash',
	},
	{
		displayName: 'Input Binary Field',
		name: 'binaryPropertyName',
		type: 'string',
		default: 'data',
		required: true,
		displayOptions: show('file', 'scan'),
		description: 'Name of the binary property that holds the file to upload (up to 650 MB)',
	},
	{
		displayName: 'Password',
		name: 'password',
		type: 'string',
		typeOptions: { password: true },
		default: '',
		displayOptions: show('file', 'scan'),
		description: 'Password of a zipped sample. Leave empty for a plain file.',
	},
	{
		displayName: 'Check Hash First',
		name: 'checkHashFirst',
		type: 'boolean',
		default: true,
		displayOptions: show('file', 'scan'),
		description:
			'Whether to look up the file hash first and skip the upload when VirusTotal already has a report. Saves quota and avoids uploading known files.',
	},
	...scanProperties('file', ['scan', 'rescan']),
	{ ...lookupOptionsProperty, displayOptions: show('file', 'getReport') },
	{
		...lookupOptionsProperty,
		displayOptions: { show: { resource: ['file'], operation: ['scan', 'rescan'], mode: ['wait'] } },
	},
	...relatedProperties('file', 'getRelated', RELATIONSHIPS, 'contacted_domains'),
];

export const fileResource: ResourceModule = {
	properties,
	handlers: {
		getRelated: relatedHandler('file', 'hash'),
		getReport: reportHandler('file', 'hash'),
		async rescan(ctx) {
			const hash = readTyped(ctx, 'hash', 'file');
			const body = await vtRequest(ctx.fn, {
				method: 'POST',
				path: `${objectPath('file', hash)}/analyse`,
				throttle: ctx.throttle,
			});
			return finishScan(ctx, 'file', hash, analysisIdOf(ctx, body), hash);
		},
		async scan(ctx) {
			const property = ctx.fn.getNodeParameter('binaryPropertyName', ctx.index, 'data') as string;
			const binary = ctx.fn.helpers.assertBinaryData(ctx.index, property);
			const data = await ctx.fn.helpers.getBinaryDataBuffer(ctx.index, property);
			const result = await uploadFile(ctx.fn, {
				data,
				fileName: binary.fileName ?? 'file',
				password: (ctx.fn.getNodeParameter('password', ctx.index, '') as string) || undefined,
				checkHashFirst: ctx.fn.getNodeParameter('checkHashFirst', ctx.index, true) as boolean,
				throttle: ctx.throttle,
				itemIndex: ctx.index,
			});
			ctx.setIndicator(result.sha256);
			if (result.kind === 'existing') {
				return renderReport(ctx, 'file', result.sha256, result.report, { uploaded: false });
			}
			return finishScan(ctx, 'file', result.sha256, result.analysisId, result.sha256, {
				uploaded: true,
			});
		},
	},
};
