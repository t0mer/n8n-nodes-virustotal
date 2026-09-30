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
import type { HuntState, PageResult } from '../../shared/livehunt';
import { normalizeHuntState, pollLivehunt, toNotification } from '../../shared/livehunt';

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
						name: 'Livehunt Notification',
						value: 'livehuntNotification',
						description:
							'Premium only. Fires for each new Livehunt notification file. Needs a Premium key and the credential Tier set to Premium.',
					},
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
				displayName: 'Ruleset Filter',
				name: 'rulesetFilter',
				type: 'string',
				default: '',
				placeholder: 'e.g. my_ruleset or tag:my_ruleset',
				displayOptions: { show: { event: ['livehuntNotification'] } },
				description:
					'Optional. A tag or ruleset name; a plain name is sent as a tag: filter. A value that already contains ":" is sent unchanged as the filter. Leave empty for all notifications.',
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
		const event = this.getNodeParameter('event', 'watchedIndicatorChanged') as string;
		return event === 'livehuntNotification' ? pollHunt(this) : pollWatched(this);
	}
}

async function pollWatched(ctx: IPollFunctions): Promise<INodeExecutionData[][] | null> {
	const rpm = await getRequestsPerMinute(ctx);
	const requested = ctx.getNodeParameter('maxLookups', 3) as number;
	const maxLookups = Math.max(1, Math.min(requested, rpm));
	const fireWhen = ctx.getNodeParameter('fireWhen', 'verdictChanges') as FireWhen;
	const options = ctx.getNodeParameter('options', {}) as {
		maliciousThreshold?: number;
		suspiciousThreshold?: number;
	};
	const thresholds = {
		malicious: options.maliciousThreshold ?? 3,
		suspicious: options.suspiciousThreshold ?? 1,
	};

	const configured =
		(ctx.getNodeParameter('indicators', {}) as { items?: Array<{ value?: string }> }).items ?? [];
	const seen = new Set<string>();
	const indicators: Indicator[] = [];
	for (const entry of configured) {
		if (!entry.value?.trim()) continue;
		const detected = detectIndicator(entry.value, 'auto' satisfies ForceType);
		if (!detected.ok) {
			throw new NodeOperationError(
				ctx.getNode(),
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
		const res = await vtRequestRaw<IDataObject>(ctx, {
			path: objectPath(target.type, target.indicator),
			acceptStatus: [400, 404, 429],
		});
		if (res.statusCode === 429) return { rateLimited: true };
		if (res.statusCode === 400) return { skipped: true };
		return { body: res.statusCode === 404 ? null : res.body };
	};

	if (ctx.getMode() === 'manual') {
		const items: IDataObject[] = [];
		for (const target of indicators.slice(0, Math.min(TEST_EVENT_LOOKUPS, maxLookups))) {
			const result = await lookup(target);
			if (result.rateLimited) break;
			if (result.skipped) continue;
			items.push({
				...summarize(target.type, result.body, { indicator: target.indicator, thresholds }),
				event: 'test',
			});
		}
		return items.length ? [ctx.helpers.returnJsonArray(items)] : null;
	}

	const staticData = ctx.getWorkflowStaticData('node');
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

	return emitted.length ? [ctx.helpers.returnJsonArray(emitted)] : null;
}

const HUNT_PAGE_SIZE = 40;
const HUNT_MAX_PAGES = 3;

async function pollHunt(ctx: IPollFunctions): Promise<INodeExecutionData[][] | null> {
	const credentials = await ctx.getCredentials(CREDENTIAL_NAME);
	if (credentials.tier !== 'premium') {
		throw new NodeOperationError(
			ctx.getNode(),
			'Livehunt notifications require a VirusTotal Premium API key',
			{
				description:
					'Set "Tier" to Premium in the VirusTotal API credential if your key is a Premium key.',
			},
		);
	}

	const rpm = await getRequestsPerMinute(ctx);
	const manual = ctx.getMode() === 'manual';
	const rawFilter = (ctx.getNodeParameter('rulesetFilter', '') as string).trim();
	const filter = rawFilter && !rawFilter.includes(':') ? `tag:${rawFilter}` : rawFilter;
	const thresholds = { malicious: 3, suspicious: 1 };

	const fetchPage = async (cursor?: string): Promise<PageResult> => {
		const res = await vtRequestRaw<{ data?: IDataObject[]; meta?: { cursor?: string } }>(ctx, {
			path: '/intelligence/hunting_notification_files',
			qs: {
				limit: manual ? TEST_EVENT_LOOKUPS : HUNT_PAGE_SIZE,
				...(filter ? { filter } : {}),
				...(cursor ? { cursor } : {}),
			},
			acceptStatus: [429],
		});
		if (res.statusCode === 429) return { rateLimited: true };
		return {
			items: Array.isArray(res.body.data) ? res.body.data : [],
			next: res.body.meta?.cursor,
		};
	};

	if (manual) {
		const page = await fetchPage();
		if (page.rateLimited) return null;
		const items = page.items
			.map((raw) => toNotification(raw, thresholds)?.item)
			.filter((item): item is IDataObject => item !== undefined)
			.map((item) => ({ ...item, event: 'test' }));
		return items.length ? [ctx.helpers.returnJsonArray(items)] : null;
	}

	const staticData = ctx.getWorkflowStaticData('node');
	const state: HuntState = normalizeHuntState(staticData as Partial<HuntState>);
	const emitted = await pollLivehunt({
		state,
		thresholds,
		maxPages: Math.max(1, Math.min(HUNT_MAX_PAGES, rpm)),
		fetchPage,
	});
	Object.assign(staticData, state);
	return emitted.length ? [ctx.helpers.returnJsonArray(emitted)] : null;
}
