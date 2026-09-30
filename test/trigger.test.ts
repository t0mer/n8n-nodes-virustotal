import { describe, expect, it } from 'vitest';
import { VirusTotalTrigger } from '../nodes/VirusTotalTrigger/VirusTotalTrigger.node';
import { fakePoll } from './helpers';

const report = (malicious: number) => ({
	statusCode: 200,
	body: {
		data: {
			id: 'x',
			type: 'domain',
			attributes: {
				last_analysis_stats: { malicious, suspicious: 0, harmless: 60, undetected: 0, timeout: 0 },
			},
		},
	},
});
const list = (...values: string[]) => ({ items: values.map((value) => ({ value })) });
const poll = (opts: Parameters<typeof fakePoll>[0]) => {
	const p = fakePoll(opts);
	return { ...p, result: () => new VirusTotalTrigger().poll.call(p.fn) };
};

describe('VirusTotal Trigger', () => {
	it('is a polling trigger without inputs, and not usable as a tool', () => {
		const d = new VirusTotalTrigger().description;
		expect(d.polling).toBe(true);
		expect(d.inputs).toEqual([]);
		expect(d.usableAsTool).toBeUndefined();
		expect(d.name.endsWith('Trigger')).toBe(true);
	});

	it('first poll baselines silently and stores versioned state', async () => {
		const p = poll({
			params: { indicators: list('example.com'), fireWhen: 'verdictChanges', maxLookups: 3 },
			responses: [report(0)],
		});
		expect(await p.result()).toBeNull();
		expect(p.staticData).toMatchObject({
			stateVersion: 1,
			cursor: 0,
			entries: { 'example.com': { verdict: 'clean' } },
		});
		expect(p.calls[0].url).toBe('https://www.virustotal.com/api/v3/domains/example.com');
	});

	it('emits an item with event, previous verdict and stats when the verdict changes', async () => {
		const staticData = {
			stateVersion: 1,
			cursor: 0,
			entries: {
				'example.com': { verdict: 'clean', malicious: 0, stats: { malicious: 0, harmless: 60 } },
			},
		};
		const p = poll({
			params: { indicators: list('Example[.]com'), fireWhen: 'verdictChanges', maxLookups: 3 },
			responses: [report(9)],
			staticData,
		});
		const out = await p.result();
		expect(out?.[0]).toHaveLength(1);
		expect(out?.[0][0].json).toMatchObject({
			event: 'verdictChanged',
			verdict: 'malicious',
			previousVerdict: 'clean',
			previousStats: { malicious: 0 },
			indicator: 'example.com',
		});
	});

	it('never exceeds Max Lookups, and caps it at the credential rate', async () => {
		const values = ['a', 'b', 'c', 'd', 'e', 'f'].map((n) => `${n}.com`);
		const p = poll({
			params: { indicators: list(...values), fireWhen: 'verdictChanges', maxLookups: 50 },
			responses: Array(6).fill(report(0)),
			credentials: { requestsPerMinute: 4 },
		});
		await p.result();
		expect(p.calls).toHaveLength(4);
		expect(p.staticData.cursor).toBe(4);
	});

	it('ends the poll quietly on a 429, keeping state, without throwing or sleeping through it', async () => {
		const p = poll({
			params: { indicators: list('a.com', 'b.com'), fireWhen: 'verdictChanges', maxLookups: 2 },
			responses: [
				report(0),
				{ statusCode: 429, body: { error: { code: 'QuotaExceededError', message: 'q' } } },
			],
		});
		expect(await p.result()).toBeNull();
		expect(p.calls).toHaveLength(2);
		expect(p.staticData.cursor).toBe(1);
	});

	it('skips an indicator VirusTotal rejects with 400 and still checks the next one', async () => {
		const p = poll({
			params: { indicators: list('a.com', 'b.com'), fireWhen: 'verdictChanges', maxLookups: 2 },
			responses: [
				{ statusCode: 400, body: { error: { code: 'InvalidArgumentError', message: 'bad' } } },
				report(0),
			],
		});
		expect(await p.result()).toBeNull();
		expect(p.calls).toHaveLength(2);
		expect(Object.keys(p.staticData.entries as object)).toEqual(['b.com']);
	});

	it('throws on a 401', async () => {
		const p = poll({
			params: { indicators: list('a.com'), fireWhen: 'verdictChanges', maxLookups: 1 },
			responses: [
				{ statusCode: 401, body: { error: { code: 'WrongCredentialsError', message: 'x' } } },
			],
		});
		await expect(p.result()).rejects.toThrow('Invalid or inactive VirusTotal API key');
	});

	it('records an unknown indicator (404) as unknown', async () => {
		const p = poll({
			params: {
				indicators: list('d41d8cd98f00b204e9800998ecf8427e'),
				fireWhen: 'verdictChanges',
				maxLookups: 1,
			},
			responses: [{ statusCode: 404, body: { error: { code: 'NotFoundError', message: 'n' } } }],
		});
		expect(await p.result()).toBeNull();
		expect(
			(p.staticData.entries as Record<string, { verdict: string }>)[
				'd41d8cd98f00b204e9800998ecf8427e'
			].verdict,
		).toBe('unknown');
	});

	it('rejects an invalid watched indicator with a clear message', async () => {
		const p = poll({
			params: { indicators: list('not an ioc'), fireWhen: 'verdictChanges', maxLookups: 1 },
			responses: [],
		});
		await expect(p.result()).rejects.toThrow('Invalid watched indicator "not an ioc"');
	});

	it('ignores blank and duplicate indicators', async () => {
		const p = poll({
			params: {
				indicators: list('a.com', ' ', 'A[.]com'),
				fireWhen: 'verdictChanges',
				maxLookups: 5,
			},
			responses: [report(0)],
		});
		await p.result();
		expect(p.calls).toHaveLength(1);
	});

	it('manual mode returns current summaries for up to 3 indicators and leaves state untouched', async () => {
		const p = poll({
			mode: 'manual',
			params: {
				indicators: list('a.com', 'b.com', 'c.com', 'd.com'),
				fireWhen: 'verdictChanges',
				maxLookups: 10,
			},
			responses: [report(0), report(1), report(9)],
			credentials: { requestsPerMinute: 10 },
		});
		const out = await p.result();
		expect(p.calls).toHaveLength(3);
		expect(out?.[0].map((i) => i.json.event)).toEqual(['test', 'test', 'test']);
		expect(out?.[0][2].json).toMatchObject({ verdict: 'malicious' });
		expect(p.staticData).toEqual({});
	});

	it('restarts the baseline when stored state has another version', async () => {
		const p = poll({
			params: { indicators: list('a.com'), fireWhen: 'verdictChanges', maxLookups: 1 },
			responses: [report(9)],
			staticData: { stateVersion: 0, entries: { 'a.com': { verdict: 'clean', malicious: 0 } } },
		});
		expect(await p.result()).toBeNull();
		expect(p.staticData.stateVersion).toBe(1);
	});
});
