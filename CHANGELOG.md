# Changelog

## 2026.10.3 - 2026-10-10

### Fixed
- `package.json` at the tagged commit now carries the released version. Tags 2026.10.0 to
  2026.10.2 pointed at commits that still read 2026.9.0, so the published package could not
  be matched to its source.

### Added
- Codex files for both nodes.

## 2026.10.0 - 2026-10-01

First release.

### Added
- **VirusTotal** action node for the VirusTotal API v3, usable as an AI tool.
  - Indicator > Lookup: detects hashes, URLs, domains and IPs, accepts defanged input.
  - File: Get Report, Scan (hash-first check, direct and large uploads), Rescan, Get Behaviour Summary, Get MITRE ATT&CK, Get Related, Get Download URL (Premium).
  - URL, Domain and IP Address: Get Report, Get Related, and URL Scan and Rescan.
  - Analysis, Comment, Vote, Search (plus Intelligence Search on Premium) and Account resources.
  - Normalized verdict with configurable thresholds, and `unknown` items for unseen indicators.
  - Built-in request throttle, retries with backoff, and quota handling.
  - Optional Check Quota Before Batch (Batch Options): fails early when the daily budget is too small for a large batch.
- **VirusTotal Trigger** polling trigger.
  - Watched Indicator Changed: verdict-change detection over a watch list, round-robin within the per-poll request budget.
  - Livehunt Notification (Premium).
- **VirusTotal API** credential with tier and requests-per-minute settings.
- Six importable example workflows in `examples/`, and a demo video.
