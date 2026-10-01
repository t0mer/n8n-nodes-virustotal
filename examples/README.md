# Example workflows

Importable n8n workflows that use the VirusTotal nodes. Each file has a sticky note that explains it.

| File | What it does |
|---|---|
| `01-check-indicator-webhook.json` | A webhook receives an indicator, **Indicator > Lookup** returns a verdict, an IF node blocks or allows, and the webhook responds. |
| `02-scan-file-hash-first.json` | A webhook receives a file. **File > Scan** with **Check Hash First** skips the upload for known files, and **Wait for Result** returns the finished report. |
| `03-bulk-ioc-check.json` | Looks up a list of IOCs one by one with **Indicator > Lookup**, with **Batch Options > Check Quota Before Batch** on so the node stops early if the daily budget is too small, then splits flagged from clean. |
| `04-watch-list-trigger-notify.json` | **VirusTotal Trigger** watches indicators and sends a Slack message when a verdict changes. Replace Slack with Email or any other notification node. |
| `05-scan-url-before-posting.json` | **URL > Scan** submits a link, waits for the result, and approves or rejects the link. |
| `06-ai-agent-indicator-lookup.json` | An AI agent uses the VirusTotal node as a tool (**Indicator > Lookup**). The chat model node is a placeholder. |

## Import

1. Install the community node `@t0mer/n8n-nodes-virustotal` (Settings > Community Nodes).
2. In n8n, create a new workflow, open the menu (`...`) and choose **Import from File**, then pick a JSON file. You can also paste the file contents onto the canvas.
3. Open each VirusTotal node and select your **VirusTotal API** credential. The files contain no credential IDs or secrets.
4. Replace placeholders: the Slack channel and credential in workflow 4, the chat model credential in workflow 6, and the sample indicators.

## Notes

- The public API allows 4 requests per minute and 500 per day, for non-commercial use only. See the main README for details.
- Files and URLs you scan are shared with VirusTotal and its partners. Do not scan confidential data.
- Workflow 3 reads the quota through Batch Options > Check Quota Before Batch. It uses the `api_requests_daily` quota and lets the batch through if your account has no such entry.
