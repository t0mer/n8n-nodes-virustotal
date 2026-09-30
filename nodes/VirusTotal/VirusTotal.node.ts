import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import { createThrottle } from '../../shared/throttle';
import { CREDENTIAL_NAME } from '../../shared/transport';
import { analysisResource } from './resources/analysis';
import { commentResource } from './resources/comment';
import { domainResource } from './resources/domain';
import { fileResource } from './resources/file';
import { indicatorResource } from './resources/indicator';
import { ipResource } from './resources/ip';
import { urlResource } from './resources/url';
import { voteResource } from './resources/vote';
import type { ResourceModule, Tier } from './types';

const RESOURCES: Record<string, ResourceModule> = {
	analysis: analysisResource,
	comment: commentResource,
	domain: domainResource,
	file: fileResource,
	indicator: indicatorResource,
	ip: ipResource,
	url: urlResource,
	vote: voteResource,
};

const resourceProperty: INodeProperties = {
	displayName: 'Resource',
	name: 'resource',
	type: 'options',
	noDataExpression: true,
	options: [
		{ name: 'Analysis', value: 'analysis' },
		{ name: 'Comment', value: 'comment' },
		{ name: 'Domain', value: 'domain' },
		{ name: 'File', value: 'file' },
		{ name: 'Indicator', value: 'indicator' },
		{ name: 'IP Address', value: 'ip' },
		{ name: 'URL', value: 'url' },
		{ name: 'Vote', value: 'vote' },
	],
	default: 'indicator',
};

export class VirusTotal implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'VirusTotal',
		name: 'virusTotal',
		icon: { light: 'file:virustotal.svg', dark: 'file:virustotal.dark.svg' },
		group: ['input'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description:
			'Look up and scan files, URLs, domains and IP addresses with VirusTotal, and get a normalized verdict',
		defaults: { name: 'VirusTotal' },
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [{ name: CREDENTIAL_NAME, required: true }],
		properties: [resourceProperty, ...Object.values(RESOURCES).flatMap((r) => r.properties)],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const throttle = await createThrottle(this);
		const credentials = await this.getCredentials(CREDENTIAL_NAME);
		const tier: Tier = credentials.tier === 'premium' ? 'premium' : 'public';

		for (let i = 0; i < items.length; i++) {
			let indicator = '';
			let failure: Error | undefined;

			try {
				const resource = this.getNodeParameter('resource', i) as string;
				const operation = this.getNodeParameter('operation', i) as string;
				const handler = RESOURCES[resource]?.handlers[operation];
				if (!handler) {
					throw new NodeOperationError(
						this.getNode(),
						`Unsupported operation "${operation}" for resource "${resource}"`,
						{ itemIndex: i },
					);
				}

				const result = await handler({
					fn: this,
					index: i,
					throttle,
					tier,
					setIndicator: (value) => {
						indicator = value;
					},
				});
				for (const json of Array.isArray(result) ? result : [result]) {
					returnData.push({ json, pairedItem: { item: i } });
				}
			} catch (error) {
				if (this.continueOnFail()) {
					const json: IDataObject = { error: (error as Error).message, indicator };
					if (error instanceof NodeApiError && error.httpCode)
						json.statusCode = Number(error.httpCode);
					returnData.push({ json, pairedItem: { item: i } });
					continue;
				}
				failure = error as Error;
			}

			if (failure) {
				if (failure instanceof NodeApiError || failure instanceof NodeOperationError) {
					failure.context.itemIndex ??= i;
					throw failure;
				}
				throw new NodeOperationError(this.getNode(), failure, { itemIndex: i });
			}
		}

		return [returnData];
	}
}
