import { describe, expect, it } from 'vitest';
import { VirusTotal } from '../nodes/VirusTotal/VirusTotal.node';
import { fakeExecute } from './helpers';
import { fixtures } from './fixtures';

const SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

async function run(operation: string, status: number, body: unknown) {
	const { fn, calls } = fakeExecute({
		params: [{ resource: 'file', operation, hash: SHA256 }],
		responses: [{ statusCode: status, body }],
	});
	const [[item]] = await new VirusTotal().execute.call(fn);
	return { json: item.json, calls };
}

describe('File > behaviour', () => {
	it('Get Behaviour Summary merges the summary under the hash', async () => {
		const { json, calls } = await run('getBehaviourSummary', 200, fixtures.behaviourSummary);
		expect(calls[0].url).toBe(
			`https://www.virustotal.com/api/v3/files/${SHA256}/behaviour_summary`,
		);
		expect(json).toMatchObject({
			found: true,
			hash: SHA256,
			processes_created: ['x.exe'],
			verdicts: ['MALWARE'],
		});
	});

	it('Get MITRE ATT&CK returns the trees per sandbox', async () => {
		const { json, calls } = await run('getMitre', 200, fixtures.behaviourMitre);
		expect(calls[0].url).toBe(
			`https://www.virustotal.com/api/v3/files/${SHA256}/behaviour_mitre_trees`,
		);
		expect(json).toMatchObject({ found: true, hash: SHA256 });
		expect(json.sandboxes).toHaveProperty('Zenbox.tactics');
	});

	it('returns found:false when there are no sandbox reports (404)', async () => {
		const { json } = await run('getMitre', 404, fixtures.errorNotFound);
		expect(json).toEqual({ found: false, hash: SHA256 });
	});
});
