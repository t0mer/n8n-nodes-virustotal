import type {
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IPollFunctions,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import type { ForceType, Indicator } from '../../shared/indicator';
import { detectIndicator } from '../../shared/indicator';
import { objectPath } from '../../shared/objects';
import { getRequestsPerMinute } from '../../shared/throttle';
import { CREDENTIAL_NAME, vtRequestRaw } from '../../shared/transport';
import { summarize } from '../../shared/summary';
import type { FireWhen, LookupResult, WatchState } from '../../shared/watch';
import { normalizeState, watchIndicators } from '../../shared/watch';

/** Indicators returned in manual ("Fetch Test Event") mode. */
const TEST_EVENT_LOOKUPS = 3;

export class VirusTotalTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'VirusTotal Trigger',
		name: 'virusTotalTrigger',
		icon: { light: 'file:virustotal.svg', dark: 'file:virustotal.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: '={{$parameter["event"]}}',
		description: 'Starts a workflow when the VirusTotal verdict of a watched indicator changes',
		defaults: { name: 'VirusTotal Trigger' },
		polling: true,
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [{ name: CREDENTIAL_NAME, required: true }],
		properties: [
			{
				displayName: 'Event',
				name: 'event',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Watched Indicator Changed',
						value: 'watchedIndicatorChanged',
						description:
							'Fires when a watched hash, URL, domain or IP changes verdict. Reads existing reports only; it never uploads, submits or rescans.',
					},
				],
				default: 'watchedIndicatorChanged',
			},
			{
				displayName: 'Indicators',
				name: 'indicators',
				type: 'fixedCollection',
				typeOptions: { multipleValues: true },
				placeholder: 'Add Indicator',
				default: {},
				displayOptions: { show: { event: ['watchedIndicatorChanged'] } },
				description:
					'Hashes, URLs, domains or IP addresses to watch. The type is detected automatically.',
				options: [
					{
						displayName: 'Indicator',
						name: 'items',
						values: [
							{
								displayName: 'Indicator',
								name: 'value',
								type: 'string',
								default: '',
								placeholder: 'e.g. example.com or 44d88612fea8a8f36de82e1278abb02f',
							},
						],
					},
				],
			},
			{
				displayName: 'Fire When',
				name: 'fireWhen',
				type: 'options',
				options: [
					{ name: 'Becomes Malicious', value: 'becomesMalicious' },
					{ name: 'Malicious Count Increases', value: 'maliciousIncreases' },
					{ name: 'Verdict Changes', value: 'verdictChanges' },
				],
				default: 'verdictChanges',
				displayOptions: { show: { event: ['watchedIndicatorChanged'] } },
			},
			{
				displayName: 'Max Lookups per Poll',
				name: 'maxLookups',
				type: 'number',
				typeOptions: { minValue: 1 },
				default: 3,
				displayOptions: { show: { event: ['watchedIndicatorChanged'] } },
				description:
					'Each lookup costs one API request. Capped at the credential\'s "Requests per Minute". A long list is covered round-robin across several polls.',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				displayOptions: { show: { event: ['watchedIndicatorChanged'] } },
				options: [
					{
						displayName: 'Malicious Threshold',
						name: 'maliciousThreshold',
						type: 'number',
						typeOptions: { minValue: 1 },
						default: 3,
						description:
							'Number of engines that must flag an indicator for the verdict to be malicious',
					},
					{
						displayName: 'Suspicious Threshold',
						name: 'suspiciousThreshold',
						type: 'number',
						typeOptions: { minValue: 1 },
						default: 1,
						description:
							'Number of malicious plus suspicious engines needed for the verdict to be suspicious',
					},
				],
			},
		],
	};

	async poll(this: IPollFunctions): Promise<INodeExecutionData[][] | null> {
		const rpm = await getRequestsPerMinute(this);
		const requested = this.getNodeParameter('maxLookups', 3) as number;
		const maxLookups = Math.max(1, Math.min(requested, rpm));
		const fireWhen = this.getNodeParameter('fireWhen', 'verdictChanges') as FireWhen;
		const options = this.getNodeParameter('options', {}) as {
			maliciousThreshold?: number;
			suspiciousThreshold?: number;
		};
		const thresholds = {
			malicious: options.maliciousThreshold ?? 3,
			suspicious: options.suspiciousThreshold ?? 1,
		};

		const configured =
			(this.getNodeParameter('indicators', {}) as { items?: Array<{ value?: string }> }).items ??
			[];
		const seen = new Set<string>();
		const indicators: Indicator[] = [];
		for (const entry of configured) {
			if (!entry.value?.trim()) continue;
			const detected = detectIndicator(entry.value, 'auto' satisfies ForceType);
			if (!detected.ok) {
				throw new NodeOperationError(
					this.getNode(),
					`Invalid watched indicator "${entry.value}": ${detected.reason}`,
				);
			}
			if (seen.has(detected.indicator)) continue;
			seen.add(detected.indicator);
			indicators.push(detected);
		}

		// Reads existing reports only. The per-poll cap keeps a poll within the per-minute budget,
		// so no spacing or waiting is needed; a 429 ends the poll instead of being retried.
		const lookup = async (target: Indicator): Promise<LookupResult> => {
			const res = await vtRequestRaw<IDataObject>(this, {
				path: objectPath(target.type, target.indicator),
				acceptStatus: [404, 429],
			});
			if (res.statusCode === 429) return { rateLimited: true };
			return { body: res.statusCode === 404 ? null : res.body };
		};

		if (this.getMode() === 'manual') {
			const items: IDataObject[] = [];
			for (const target of indicators.slice(0, Math.min(TEST_EVENT_LOOKUPS, maxLookups))) {
				const result = await lookup(target);
				if (result.rateLimited) break;
				items.push({
					...summarize(target.type, result.body, { indicator: target.indicator, thresholds }),
					event: 'test',
				});
			}
			return items.length ? [this.helpers.returnJsonArray(items)] : null;
		}

		const staticData = this.getWorkflowStaticData('node');
		const state: WatchState = normalizeState(staticData as Partial<WatchState>);
		const emitted = await watchIndicators({
			state,
			indicators,
			fireWhen,
			maxLookups,
			thresholds,
			lookup,
		});
		Object.assign(staticData, state);

		return emitted.length ? [this.helpers.returnJsonArray(emitted)] : null;
	}
}
