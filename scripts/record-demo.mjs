// Records assets/demo/demo.mp4 + poster.png against a throwaway n8n started with:
//   npx n8n-node dev --custom-user-folder <dir outside the repo>
// Usage: node scripts/record-demo.mjs   (needs API_KEY in .env, n8n on :5678, ffmpeg)
import { chromium } from '../node_modules/playwright/index.mjs';
import { readFileSync, mkdirSync, rmSync, readdirSync, renameSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'assets', 'demo');
const tmpDir = process.env.DEMO_TMP ?? join(root, '..', '.demo-tmp-virustotal');
const BASE = 'http://localhost:5678';
const EMAIL = 'demo@example.com';
const PASSWORD = 'Demo-Pass1234';
const BROWSER_ID = 'demo-browser-id-0001';

const apiKey = readFileSync(join(root, '.env'), 'utf8')
	.split('\n')
	.map((l) => l.match(/^API_KEY=(.*)$/))
	.find(Boolean)?.[1]
	?.trim()
	.replace(/^["']|["']$/g, '');
if (!apiKey) throw new Error('API_KEY missing in .env');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(outDir, { recursive: true });
rmSync(tmpDir, { recursive: true, force: true });
mkdirSync(tmpDir, { recursive: true });

const browser = await chromium.launch();

// ---------- unrecorded setup ----------
const setupCtx = await browser.newContext({ baseURL: BASE });
const sp = await setupCtx.newPage();
await sp.goto(BASE + '/');
await sp.evaluate((id) => localStorage.setItem('n8n-browserId', id), BROWSER_ID);
const apiRaw = (method, path, body) =>
	sp.evaluate(
		async ([m, p, b, id]) => {
			const r = await fetch(p, {
				method: m,
				headers: { 'content-type': 'application/json', 'browser-id': id },
				body: b ? JSON.stringify(b) : undefined,
			});
			return { status: r.status, json: await r.json().catch(() => null) };
		},
		[method, path, body, BROWSER_ID],
	);

const own = await apiRaw('POST', '/rest/owner/setup', {
	email: EMAIL, firstName: 'Demo', lastName: 'User', password: PASSWORD,
});
console.log('owner setup', own.status);
const login = await apiRaw('POST', '/rest/login', { emailOrLdapLoginId: EMAIL, password: PASSWORD });
console.log('login', login.status);
const sv = await apiRaw('POST', '/rest/me/survey', {
	version: 'v4',
	personalization_survey_submitted_at: new Date().toISOString(),
	personalization_survey_n8n_version: '1.0.0',
});
console.log('survey', sv.status);

// credential (key only travels node -> n8n API, never rendered)
const cred = await apiRaw('POST', '/rest/credentials', {
	name: 'VirusTotal account',
	type: 'virusTotalApi',
	data: { apiKey, tier: 'public', requestsPerMinute: 4 },
});
console.log('credential', cred.status);
const credId = cred.json?.data?.id;
if (!credId) throw new Error('credential not created: ' + cred.status);

const mk = (name, params, x = 0) => ({
	nodes: [
		{ id: 'n1', name: 'Manual Trigger', type: 'n8n-nodes-base.manualTrigger', typeVersion: 1, position: [0, 0], parameters: {} },
		{
			id: 'n2', name, type: 'CUSTOM.virusTotal', typeVersion: 1, position: [260, 0], parameters: params,
			credentials: { virusTotalApi: { id: credId, name: 'VirusTotal account' } },
		},
	],
	connections: { 'Manual Trigger': { main: [[{ node: name, type: 'main', index: 0 }]] } },
});
const flows = [
	{
		title: 'Indicator Lookup: EICAR file hash',
		node: 'Lookup EICAR hash',
		params: { resource: 'indicator', operation: 'lookup', indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' },
		caption: 'Indicator > Lookup: EICAR test file hash, normalized verdict',
	},
	{
		title: 'Indicator Lookup: defanged URL',
		node: 'Lookup defanged URL',
		params: { resource: 'indicator', operation: 'lookup', indicator: 'hxxp://malware.testing.google.test/testing/malware/' },
		caption: 'Defanged URL (hxxp://) is refanged and detected automatically',
	},
	{
		title: 'Indicator Lookup: unknown hash',
		node: 'Lookup unknown hash',
		params: { resource: 'indicator', operation: 'lookup', indicator: 'd41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef' },
		caption: 'Unseen hash returns verdict "unknown" and does not fail the workflow',
	},
	{
		title: 'Account: Get Quotas',
		node: 'Get quotas',
		params: { resource: 'account', operation: 'getQuotas' },
		caption: 'Account > Get Quotas: check your API budget before bulk jobs',
	},
];
for (const f of flows) {
	const w = mk(f.node, f.params);
	const r = await apiRaw('POST', '/rest/workflows', { name: f.title, ...w, settings: {}, active: false });
	console.log('workflow', f.title, r.status);
	f.id = r.json?.data?.id;
	if (!f.id) throw new Error('workflow create failed');
}
await sp.context().storageState({ path: join(tmpDir, 'state.json') });
await setupCtx.close();

// ---------- recorded session ----------
const ctx = await browser.newContext({
	baseURL: BASE,
	viewport: { width: 1280, height: 720 },
	storageState: join(tmpDir, 'state.json'),
	recordVideo: { dir: tmpDir, size: { width: 1280, height: 720 } },
});
await ctx.addInitScript(() => {
	const install = () => {
		if (document.getElementById('demo-cursor')) return;
		const c = document.createElement('div');
		c.id = 'demo-cursor';
		c.style.cssText = 'position:fixed;z-index:2147483647;width:18px;height:18px;border-radius:50%;background:rgba(255,80,60,.85);border:2px solid #fff;pointer-events:none;left:-30px;top:-30px;transform:translate(-50%,-50%)';
		const cap = document.createElement('div');
		cap.id = 'demo-caption';
		cap.style.cssText = 'position:fixed;z-index:2147483647;left:50%;bottom:18px;transform:translateX(-50%);max-width:90%;padding:10px 20px;border-radius:8px;background:rgba(15,23,42,.92);color:#fff;font:600 20px system-ui,sans-serif;pointer-events:none;text-align:center';
		document.documentElement.append(c, cap);
		document.addEventListener('mousemove', (e) => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
	};
	document.addEventListener('DOMContentLoaded', install);
	window.__caption = (t) => { install(); document.getElementById('demo-caption').textContent = t; };
});
const page = await ctx.newPage();
const caption = (t) => page.evaluate((x) => window.__caption(x), t).catch(() => {});
const move = async (loc) => {
	const b = await loc.boundingBox();
	if (b) await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 25 });
};
const shot = process.env.DEMO_SHOTS ? (n) => page.screenshot({ path: join(tmpDir, `shot-${n}.png`) }) : async () => {};

let lastCall = 0;
let posterDone = false;
for (const [i, f] of flows.entries()) {
	await page.goto(`/workflow/${f.id}`);
	await page.waitForSelector('[data-test-id="canvas-node"]', { timeout: 60000 });
	await sleep(1500);
	await caption(f.caption);
	await sleep(2500);
	// throttle: at most one API call every ~18s (public tier is 4 req/min)
	const wait = lastCall + 18000 - Date.now();
	if (wait > 0) await sleep(wait);
	const exec = page.locator('[data-test-id="execute-workflow-button"]').first();
	await move(exec);
	await exec.click();
	lastCall = Date.now();
	await page.waitForSelector('[data-test-id="canvas-node-status-success"], [data-test-id="canvas-node-status-error"]', { timeout: 60000 }).catch(() => {});
	await sleep(1500);
	const node = page.locator('[data-test-id="canvas-node"]', { hasText: f.node }).first();
	await move(node);
	await node.dblclick();
	await page.waitForSelector('[data-test-id="ndv-output-panel"], [data-test-id="output-panel"]', { timeout: 20000 }).catch(() => {});
	await sleep(1000);
	// JSON view makes the normalized fields readable
	const jsonBtn = page.locator('[data-test-id="ndv-run-data-display-mode"] >> text=JSON').last();
	if (await jsonBtn.count()) { await move(jsonBtn); await jsonBtn.click().catch(() => {}); }
	await caption(f.caption);
	await sleep(5500);
	await shot(i);
	if (i === 0 && !posterDone) {
		await page.screenshot({ path: join(outDir, 'poster.png') });
		posterDone = true;
	}
	await page.keyboard.press('Escape');
	await sleep(500);
}
await caption('github.com/t0mer/n8n-nodes-virustotal');
await sleep(2000);
await ctx.close();
await browser.close();

const webm = readdirSync(tmpDir).find((n) => n.endsWith('.webm'));
renameSync(join(tmpDir, webm), join(tmpDir, 'demo.webm'));
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', join(tmpDir, 'demo.webm'), '-c:v', 'libx264', '-crf', '20', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', join(outDir, 'demo.mp4')]);
console.log('done');
