# Changelog

Versions follow `MAJOR.MINOR.PATCH`. **v1.x** is Elastic Cloud Hosted / self-managed only (branch `release/1.x`). **v2.x** adds Elastic Cloud Serverless and AlertZero (branch `main`). v2 is a superset of v1: everything in 1.0.0 still works on Cloud Hosted / self-managed.

## [Unreleased]

### Added
- **Hunt report picker** (AlertZero tab): load the threat reports from `.kibana-threat-reports`, filter to reports with discriminating / uncertain IOCs, pick a report and an IOC, seed a matching event (IP, domain, URL or file hash) and run Continuous Threat Hunt on that report through a `reportIds` bypass sweep. Reports are shown with severity, source and hunt status, which refreshes after the run.
- **Clean proposals** (AlertZero tab): preview and dismiss pending proposals through the Workflows API (`POST /api/workflows/executions/{id}/resume` with `approved: false`). Scope: demo only or everything pending. Dismiss-only by construction; it never approves, so no proposed action can run.
- `seedHuntIoc` accepts URLs and generic file hashes (MD5 / SHA-1 / SHA-256).

## [2.0.0] — 2026-11-23 (`main`)

### Added
- **Serverless support.** A *Deployment Type* selector in the connection dialog (Cloud Hosted / Self-managed, or Serverless Security).
  - Serverless is API-key only; Basic Auth is hidden and ignored.
  - The connection test uses `GET /` on Serverless (no `/_cluster/health`) and confirms the project is serverless.
  - Kibana calls send `elastic-api-version: 2023-10-31` on Serverless.
- **AlertZero tab** (Serverless Security projects), see [docs/ALERTZERO.md](docs/ALERTZERO.md):
  - Seed five tagged detection rules (one deliberately noisy), a Defend-shaped attack chain with benign noise, and closed false-positive alerts for Rule Tuning.
  - Run the Workers on demand through the Workflows API (list, start, follow), one by one or as a sequence, with billing confirmation.
  - **Endpoint modes:** *Simulated* (per-host generated `agent.id`/`host.id`, so Endpoint Analysis proposes isolate / kill / suspend without executing) or *Real enrolled host* (picked from `/api/endpoint/metadata`).
  - Configurable victim host, so each run gets a fresh investigation.
  - Hunt IOC seeding and a tag-based reset (dry run first).
- `src/elastic.js`: connection config, auth headers and ES/Kibana fetch helpers extracted from `App.jsx`.
- README rewritten for v2; this changelog; `docs/ALERTZERO.md`.

### Changed
- README corrected: 13 vendors (was 7), ML anomaly detection and email notifications documented, Ransomware listed as an APT-style scenario, API keys documented as stored in `localStorage` (not React state), dev-server proxy requirement stated.
- API key example now includes `metrics-*`.

### Known limitations
- AlertZero is a Preview feature; managed Worker workflow IDs may change.
- Real-host mode and Rule Coverage have not been exercised end to end through the forge.
- Hunt: a manual run with no new candidate reports does nothing. Running Hunt on a chosen report (`reportIds`) was verified against the Workflows API (it re-hunted an already-clean report and recorded a hit), but the forge has no report picker yet; the Hunt IOC box only seeds the event.

## [1.0.0] — 2026-11-23 — ECH only (`v1.0.0`, `release/1.x`)

Log generators for 13 vendors, APT / raw attack scenarios with background noise, ML anomaly detection demo jobs, the Elasticsearch and Kibana dev-server proxies, self-managed cluster support, alert email notifications, custom noise and logs-per-day controls.
