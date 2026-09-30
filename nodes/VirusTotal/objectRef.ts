import type { INodeProperties } from 'n8n-workflow';
import type { IndicatorType } from '../../shared/indicator';
import { objectPath } from '../../shared/objects';
import { readTyped, show } from './lookup';
import type { OperationContext } from './types';

/** Object Type and Object ID parameters for operations that work on any VirusTotal object. */
export function objectRefProperties(resource: string, operations: string[]): INodeProperties[] {
	const displayOptions = show(resource, ...operations);
	return [
		{
			displayName: 'Object Type',
			name: 'objectType',
			type: 'options',
			options: [
				{ name: 'Domain', value: 'domain' },
				{ name: 'File', value: 'file' },
				{ name: 'IP Address', value: 'ip_address' },
				{ name: 'URL', value: 'url' },
			],
			default: 'file',
			displayOptions,
		},
		{
			displayName: 'Object ID',
			name: 'objectId',
			type: 'string',
			required: true,
			default: '',
			placeholder: 'e.g. a file hash, domain, IP address or URL',
			displayOptions,
			description:
				'The file hash, domain, IP address or URL. URLs are encoded for you; do not paste a VirusTotal ID.',
		},
	];
}

export interface ObjectRef {
	type: IndicatorType;
	id: string;
	/** Path of the object, e.g. `/domains/example.com`. */
	path: string;
}

export function readObjectRef(ctx: OperationContext): ObjectRef {
	const type = ctx.fn.getNodeParameter('objectType', ctx.index) as IndicatorType;
	const id = readTyped(ctx, 'objectId', type);
	return { type, id, path: objectPath(type, id) };
}
