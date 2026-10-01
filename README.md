# n8n-nodes-virustotal

An [n8n](https://n8n.io/) community node for the [VirusTotal API v3](https://docs.virustotal.com/reference/overview).
It looks up and scans files, URLs, domains and IP addresses, returns a **normalized verdict** your workflow
can branch on, and includes a **polling trigger** that fires when a watched indicator changes verdict.

> **Unofficial.** This project is not affiliated with, endorsed by, or sponsored by VirusTotal or Google.
> VirusTotal is a trademark of its owner. The node icon is an original drawing.

[Installation](#installation) ·
[Credentials](#credentials) ·
[Nodes and operations](#nodes-and-operations) ·
[Verdict](#the-verdict-heuristic) ·
[Trigger](#virustotal-trigger) ·
[Privacy](#privacy) ·
[Terms of use](#terms-of-use-of-the-public-api) ·
[Compatibility](#compatibility) ·
[Development](#development)

## Demo

[![Demo video](https://raw.githubusercontent.com/t0mer/n8n-nodes-virustotal/main/assets/demo/poster.png)](https://github.com/t0mer/n8n-nodes-virustotal/blob/main/assets/demo/demo.mp4)

Click the image to watch the demo: indicator lookup with a normalized verdict, a defanged URL, an unknown hash and the
quota check. Importable example workflows are in [`examples/`](examples/README.md).

## Why this node

n8n core ships only a credential for VirusTotal, to be used with the HTTP Request node. It has no operations.
This package adds real nodes, and differs in these ways:

- **English UI** and descriptions written so AI agents can choose the right operation (`usableAsTool`).
- **Normalized verdict** (`malicious`, `suspicious`, `clean`, `unknown`) with configurable thresholds.
- **Built-in rate limiting** for the public tier: requests are spaced to your per-minute quota, so a batch does not fail with 429.
- **Safe handling of unknown indicators**: an unseen hash returns an `unknown` item instead of failing the workflow.
- **A watch-list trigger** that detects verdict changes.

## Installation

In n8n, go to **Settings → Community Nodes → Install** and enter:

```
@t0mer/n8n-nodes-virustotal
```

See the [community nodes installation guide](https://docs.n8n.io/integrations/community-nodes/installation/).
Or install it with npm in your n8n installation folder:

```bash
npm install @t0mer/n8n-nodes-virustotal
```

## Credentials

Create a **VirusTotal API** credential.

1. Sign up at [virustotal.com](https://www.virustotal.com/), then open your profile menu and choose **API key**.
2. Paste the key into the credential.

| Field | Default | Description |
|---|---|---|
| **API Key** | | Sent as the `x-apikey` header on every request. |
| **Tier** | `Public` | Set to `Premium` if your key is a Premium key. Premium-only operations refuse to run on `Public`. |
| **Requests per Minute** | `4` | Client-side throttle applied to every request. Keep `4` on the public tier. Raise it to match your Premium contract. |

The credential test calls `GET /users/{apiKey}`. It costs one request.

### Tiers and quotas

| Tier | Quota |
|---|---|
| Public | 4 requests/minute, 500/day, 15.5K/month |
| Premium | Depends on your contract |

Every lookup, poll, comment and search counts toward the quota. The node never hard-codes Premium limits.

## Nodes and operations

The package provides two nodes:

- **VirusTotal**: the action node (also usable as an AI tool).
- **VirusTotal Trigger**: a polling trigger.

### Shared behaviour

Lookup operations have an **Options** collection:

| Option | Default | Description |
|---|---|---|
| Output | `Summary` | `Summary` is the normalized shape below. `Raw` returns the VirusTotal object unchanged. |
| On Not Found | `Return Unknown Item` | `{ found: false, type, indicator, verdict: "unknown" }`, or throw an error. |
| Malicious Threshold | `3` | Engines needed for a `malicious` verdict. |
| Suspicious Threshold | `1` | Malicious plus suspicious engines needed for a `suspicious` verdict. |
| Include Engine Results | off | Adds `engines`: `{ engine, category, result }` for engines that flagged the indicator. |

A Summary item looks like this:

```json
{
  "found": true,
  "type": "file",
  "indicator": "275a021b…fd0f",
  "id": "275a021b…fd0f",
  "verdict": "malicious",
  "stats": { "malicious": 62, "suspicious": 1, "harmless": 0, "undetected": 8, "timeout": 0 },
  "detectionRatio": "62/71",
  "reputation": -42,
  "votes": { "harmless": 3, "malicious": 210 },
  "tags": ["eicar"],
  "lastAnalysisDate": "2026-09-22T07:33:20.000Z",
  "permalink": "https://www.virustotal.com/gui/file/275a021b…fd0f"
}
```

Timestamps are converted from epoch seconds to ISO-8601. Keys that VirusTotal does not return are omitted, never `undefined`.
Per type, the Summary adds:

- **file**: `sha256`, `sha1`, `md5`, `meaningfulName`, `names` (first 10), `size`, `typeDescription`, `typeTag`, `firstSubmissionDate`, `timesSubmitted`, `popularThreatLabel`, `sandboxVerdicts`
- **url**: `url`, `finalUrl`, `title`, `categories`, `lastHttpResponseCode`
- **domain**: `categories`, `registrar`, `creationDate`, `lastDnsRecords`, `lastHttpsCertificate` (`issuer`, `subject`, `notAfter`, `daysUntilExpiry`), `whoisDate`
- **ip_address**: `asn`, `asOwner`, `country`, `network`, `regionalInternetRegistry`

Items are processed **one at a time**, through the throttle. `Continue On Fail` is supported: a failed item becomes
`{ error, indicator }` (plus `statusCode` for API errors). `pairedItem` is kept on every output item. The optional quota
check below runs before any item and, if it fails, stops the whole run regardless of `Continue On Fail`.

The node also has a **Batch Options** collection with **Check Quota Before Batch** (default off). When on, and the batch is
estimated at more than 10 requests, the node reads your quota once (one request, through the throttle) and fails before
processing any item if the remaining `api_requests_daily` budget is smaller than the estimate. The estimate is
deliberately rough: 1 request per item, 5 per scan or rescan that waits for the result, 2 per scan that only submits,
and 3 for an operation set to Return All.

### Indicator

**Lookup**: the default way to check any indicator of compromise. Give it a hash, URL, domain or IP and it detects the
type. Detection order is hash (MD5, SHA-1, SHA-256), URL, IP, domain. "Defanged" input such as `hxxp://example[.]com`,
`1.2.3[.]4` or `example[dot]com` is refanged first, and the output shows the normalized value. Use **Force Type** for
ambiguous input. A host with a path but no scheme, such as `example.com/login`, is treated as a URL.

### File

| Operation | Notes |
|---|---|
| Get Report | By MD5, SHA-1 or SHA-256. |
| Scan | Uploads a file from a binary property. See below. |
| Rescan | Asks VirusTotal to analyse a known hash again. |
| Get Behaviour Summary | Merged sandbox behaviour. |
| Get MITRE ATT&CK | ATT&CK tactics and techniques per sandbox. |
| Get Related | Relationship dropdown, with Return All / Limit. |
| Get Download URL | **Premium only.** Returns a temporary URL. The node never downloads the sample. |

**Scan** options:

- **Mode**: `Wait for Result` (default) uploads, polls the analysis, then returns the file report. `Submit Only` returns the analysis id at once; use **Analysis → Get** later.
- **Check Hash First** (default **on**): the SHA-256 is computed locally and looked up first. If VirusTotal already has a report, nothing is uploaded and the item carries `uploaded: false` and `analysisId: null` (in both modes, so downstream nodes can read `analysisId` either way). This saves quota and avoids sharing files VirusTotal already knows.
- **Password**: for password-protected zip samples.
- Files up to 32 MB are uploaded directly; files up to 650 MB use VirusTotal's one-time upload URL. Larger files fail before uploading.
- Polling defaults to `max(20, 60 / requestsPerMinute × 1.5)` seconds, with a 10 minute timeout. On timeout the error contains the analysis id.

### URL

**Get Report**, **Scan**, **Rescan**, **Get Related**. The node computes VirusTotal's URL id (unpadded base64url) itself, so you
pass the URL as is. **Scan** and **Rescan** have the same Mode options as file scans.

### Domain

**Get Report**, **Get Related** (subdomains, siblings, communicating files, historical WHOIS and SSL, …) and
**Get DNS Resolutions**, a shortcut to the `resolutions` relationship.

### IP Address

**Get Report** and **Get Related**. IPv4 and IPv6 are supported.

### Analysis

**Get**: status, stats and, once completed, the analysed object id (`itemType`, `itemId`).

### Comment and Vote

- **Comment → Get Many / Create** on any file, URL, domain or IP. Comments are public.
- **Vote → Get Many / Create** (`harmless` or `malicious`). A duplicate vote (409) is treated as success and returns `alreadyVoted: true`.

### Search

- **Search**: basic search by hash, URL, domain, IP or comment.
- **Intelligence Search**: **Premium only**, with `Order`.

### Account

- **Get Quotas**: one item per quota, `{ quota: { name, used, allowed, remaining } }`, so a workflow can check its budget before a bulk job.
- **Get Popular Threat Categories**.

### Premium-only operations

n8n cannot hide parameters based on credential fields, so Premium-only operations are labelled **"Premium only"** in their description
and enforced at run time: on a `Public` credential they fail immediately with a clear message, without spending a request.
A `403 ForbiddenError` from VirusTotal on a relationship is reported as "requires a Premium key". Which relationships need Premium depends
on your VirusTotal plan; the dropdown marks the ones that commonly do.

### Examples

**Branch on a verdict.** Indicator → Lookup with `{{ $json.url }}`, then an IF node on `{{ $json.verdict }} equals malicious`.

**Scan an email attachment.** Email trigger → File → Scan (Mode: Wait for Result, binary property `data`) → IF on `verdict`.
With Check Hash First on, repeated attachments cost one request each.

**Budget check before a bulk job.** Account → Get Quotas, then stop if `quota.remaining` for `api_requests_daily` is lower than your item count.

## The verdict heuristic

```
malicious >= Malicious Threshold                         -> malicious
malicious + suspicious >= Suspicious Threshold           -> suspicious
engines analysed the object and flagged nothing          -> clean
no report, or no engine results at all                   -> unknown
```

`detectionRatio` is `malicious / total`, where total counts `malicious`, `suspicious`, `harmless` and `undetected` engines and
excludes `type-unsupported`, `failure` and `timeout`. **The verdict is a heuristic, not a guarantee.** Tune the thresholds to your
risk tolerance, and treat `clean` as "no engine objected", not as "safe".

## VirusTotal Trigger

A polling trigger with two events. It never blocks and never waits for an analysis.

### Watched Indicator Changed

Watches a list of hashes, URLs, domains and IPs (types are detected automatically). **Fire When**:
`Verdict Changes` (default), `Becomes Malicious`, or `Malicious Count Increases`.
Output items are the Summary plus `event`, `previousVerdict` and `previousStats`.

- It **reads existing reports only**. It never uploads, submits or rescans.
- The first poll records a baseline and emits nothing. An indicator added later is baselined the same way. An indicator VirusTotal has not seen is stored as `unknown`; the move from `unknown` to a known verdict counts as a change.
- **Max Lookups per Poll** (default 3) is capped at the credential's Requests per Minute. The trigger walks the list round-robin and remembers where it stopped, so a long list is covered across several polls.
- On a `429` the trigger ends that poll quietly and keeps its position. A `401` raises an error.
- **Fetch Test Event** returns the current Summary for up to 3 indicators.

**Quota math.** Each lookup is one request. With N indicators, L lookups per poll and a poll every P minutes:

- a full refresh of the list takes `ceil(N / L) × P` minutes;
- daily usage is `L × 1440 / P` requests.

| Poll interval | Lookups per poll | Requests per day | Refresh time for 30 indicators |
|---|---|---|---|
| 1 minute | 3 | 4,320 | 10 min |
| 5 minutes | 3 | 864 | 50 min |
| 15 minutes | 3 | 288 | 150 min |
| 30 minutes | 3 | 144 | 300 min |

The public tier allows **500 requests per day**, and every other node in your workflows shares that budget. On the public tier, use
a poll interval of 15 minutes or more, or keep the list short. The one-minute row is only realistic on a Premium key.

### Livehunt Notification (Premium only)

Emits one item per new Livehunt notification file: notification id and date, rule name, ruleset, tags and a file Summary.
**Ruleset Filter** is optional; a plain name is sent as `tag:<name>`, and a value containing `:` is sent unchanged as the
VirusTotal `filter`. Notifications are de-duplicated by id (the last 1,000 ids are kept). The first poll records a baseline.
It requires the credential **Tier** to be `Premium`.

Trigger state is stored in the workflow static data with `stateVersion: 1`.

## Error handling

| HTTP / VirusTotal code | What the node does |
|---|---|
| 400 `BadRequestError`, `InvalidArgumentError` | No retry. Shows VirusTotal's message. |
| 400 `NotAvailableYet` | Retries with backoff (2 s, 4 s, 8 s). |
| 401 | No retry. "Invalid or inactive VirusTotal API key". |
| 403 | No retry. Says a Premium key may be required. |
| 404 | Not an error for lookups; see **On Not Found**. |
| 409 | A duplicate vote is treated as success. |
| 429 | Waits one minute and retries at most twice, then reports the exhausted quota. |
| 503, 504 | Retries with backoff (2 s, 4 s, 8 s). |

The API key is never logged or included in error output.

## Privacy

Read this before using the scan operations.

- **File → Scan uploads the file to VirusTotal.** Uploaded files are shared with the VirusTotal community and security partners. Do not scan confidential files. Keep **Check Hash First** on so known files are not uploaded at all.
- **URL → Scan submits the URL**, and submitted URLs become visible to VirusTotal users. Do not submit URLs that contain tokens or credentials in the query string.
- **Comments are public.** Anything posted with Comment → Create can be read by all VirusTotal users.
- Lookups (reports, searches, relationships) send only the indicator to VirusTotal.

## Terms of use of the public API

The VirusTotal **public API is for non-commercial use only**, and may not be used in commercial products or services.
Use a Premium key for commercial use. You are responsible for complying with the
[VirusTotal terms of service](https://docs.virustotal.com/docs/terms-of-service).

## Compatibility

- Built and tested with Node.js **24**.
- Requires a version of n8n that supports community nodes (`n8nNodesApiVersion` 1) and `this.helpers.httpRequestWithAuthentication`.
- No runtime dependencies. The only peer dependency is `n8n-workflow`.

## Development

```bash
npm ci
npm run lint      # n8n-node lint (strict)
npm run build
npm test          # vitest; CI never calls the real API
npm run dev       # runs n8n with the node loaded
```

`npm run dev` loads node definitions once at startup: restart it (and hard-refresh the browser) after adding operations.

Layout:

```
credentials/VirusTotalApi.credentials.ts
nodes/VirusTotal/           action node; resources/ holds one file per resource
nodes/VirusTotalTrigger/    polling trigger
shared/                     transport, throttle, indicator, verdict, summary, poll, upload, paginate, watch, livehunt
test/                       unit tests and fixtures
```

Releases use date-based versions (`YYYY.M.PATCH`). Pushing a tag publishes to npm with provenance.

## Resources

- [VirusTotal API v3 reference](https://docs.virustotal.com/reference/overview)
- [n8n community nodes](https://docs.n8n.io/integrations/community-nodes/)

## License

[MIT](LICENSE)
