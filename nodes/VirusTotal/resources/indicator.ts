import type { INodeProperties } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import type { ForceType } from '../../../shared/indicator';
import { detectIndicator } from '../../../shared/indicator';
import { lookupObject, lookupOptionsProperty, readLookupOptions } from '../lookup';
import type { ResourceModule } from '../types';

const show = { resource: ['indicator'] };

const properties: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show },
		options: [
			{
				name: 'Lookup',
				value: 'lookup',
				action: 'Look up an indicator',
				description:
					'Check any indicator of compromise (file hash, URL, domain or IP address) and get a verdict. The default way to check an IOC: the type is detected automatically.',
			},
		],
		default: 'lookup',
	},
	{
		displayName: 'Indicator',
		name: 'indicator',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. 44d88612fea8a8f36de82e1278abb02f or example.com',
		displayOptions: { show: { ...show, operation: ['lookup'] } },
		description:
			'An MD5, SHA-1 or SHA-256 hash, a URL, a domain or an IP address. Defanged input such as hxxp://example[.]com is accepted.',
	},
	{
		displayName: 'Force Type',
		name: 'forceType',
		type: 'options',
		options: [
			{ name: 'Auto-Detect', value: 'auto' },
			{ name: 'Domain', value: 'domain' },
			{ name: 'File Hash', value: 'file' },
			{ name: 'IP Address', value: 'ip_address' },
			{ name: 'URL', value: 'url' },
		],
		default: 'auto',
		displayOptions: { show: { ...show, operation: ['lookup'] } },
		description: 'Only needed for ambiguous input',
	},
	{ ...lookupOptionsProperty, displayOptions: { show: { ...show, operation: ['lookup'] } } },
];

export const indicatorResource: ResourceModule = {
	properties,
	handlers: {
		async lookup(ctx) {
			const input = ctx.fn.getNodeParameter('indicator', ctx.index) as string;
			const force = ctx.fn.getNodeParameter('forceType', ctx.index, 'auto') as ForceType;
			ctx.setIndicator(input);

			const detected = detectIndicator(input, force);
			if (!detected.ok) {
				throw new NodeOperationError(ctx.fn.getNode(), detected.reason, {
					itemIndex: ctx.index,
					description: 'Use "Force Type" if the input is ambiguous.',
				});
			}
			return lookupObject(ctx, detected.type, detected.indicator, readLookupOptions(ctx));
		},
	},
};
