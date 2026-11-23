# AlertZero demo walkthrough

How to use the **AlertZero** tab in Elastic Demo Forge (v2) to seed data, run the Workers and show proposed response actions. AlertZero is a **Preview** feature of Elastic Security on **Serverless Security projects**; behaviour can change. Official docs: [AlertZero](https://www.elastic.co/docs/solutions/security/alertzero).

> Everything below marked **verified** was run end to end against a real Serverless Security project (Serverless 9.7.0) while building this. Things marked **not verified** were not.

---

## 1. What you get

AlertZero's Workers are AI agents that triage alerts, hunt, tune rules and investigate attacks, then bring **proposed actions** to a person to approve. They are grouped into four Watches:

| Watch | Workers | What the forge seeds for it |
|---|---|---|
| **Triage** | Alert Triage, Attack Discovery | A noisy rule's benign alerts (to close as false positives) and a multi-stage attack chain |
| **Hunt** | Continuous Threat Hunt | A manual IOC event you seed after the Worker has built threat reports |
| **Detection** | Rule Tuning, Rule Coverage | Closed false-positive alerts on a noisy rule; disabled prebuilt rules left for coverage gaps |
| **Forensics** | Endpoint Analysis | Defend-shaped process and network events carrying an `agent.id`, so it can propose isolate / kill / suspend |

The Workers are **managed Elastic Workflows**. The forge lists and starts them through the Workflows API; approving proposed actions stays a human step in Kibana.

---

## 2. Prerequisites

- A **Serverless Security project** with AlertZero turned on for the space (the `securitySolution:enableAlertZero` setting; AlertZero is off by default and enabled per space). Workers start at **Manual** autonomy, which is what this demo wants: every action waits for your approval.
- An AI model for the Workers (an Elastic Managed LLM or your own connector).
- **Connect ES** in the forge set to **Serverless (Security)** with both the **Elasticsearch endpoint** and **Kibana URL**, and an API key from Kibana → Stack Management → API keys. The tested key had broad privileges (it creates and deletes detection rules, writes to the alerts index and data streams, and lists/runs workflows); narrower scoping has not been verified. See the [AlertZero privileges](https://www.elastic.co/docs/solutions/security/alertzero/alertzero-privileges) page for the roles people need to view and decide proposed actions.
- For **Real enrolled host** mode only: Elastic Defend installed with an enrolled endpoint. The project used for testing had *Endpoint Protection Complete*.
- `npm run dev` running (the proxy routes only exist in the dev server).

Cost: each Worker run counts as a workflow execution, each AI analysis as an Agent Builder execution, plus model tokens. The tab asks you to confirm before any run.

---

## 3. Demo flow at a glance

| Step | Where | Action |
|---|---|---|
| 1 | Forge → AlertZero | **Seed everything** (pick endpoint mode, new victim host) |
| 2 | wait ~3 min | Rules run every minute; alerts appear in 2–3 minutes |
| 3 | Forge → AlertZero | **Run sequence** (or run Workers one by one) |
| 4 | Kibana → Security → AlertZero → Proposed actions | Review **Investigate** and **Configure** items; approve the forensic handoff |
| 5 | wait ~5 min | Endpoint Analysis runs |
| 6 | Proposed actions → **Respond** | Show the recommended isolate / kill / suspend and the reasoning |
| 7 | Forge → AlertZero | **Reset** when done |

---

## 4. Step by step

### 4.1 Seed

**Seed everything** does three things (each also has its own button):

1. **Rules** — creates five custom detection rules tagged `alertzero-demo`:
   `AZ Demo - Office app spawning PowerShell`, `Registry Run key persistence`, `LSASS dump via comsvcs.dll`, `Remote service execution (PsExec-style)`, and the deliberately noisy `PowerShell ExecutionPolicy Bypass`. Existing rules are reused (409 is treated as "exists").
2. **Attack chain + noise** — indexes Defend-shaped events into `logs-endpoint.events.process-demo` and `logs-endpoint.events.network-demo`:
   Word → hidden encoded PowerShell → Run-key persistence → `rundll32` MiniDump → PsExec-style service, with C2 connections to `203.0.113.45:443` (a documentation address) and a benign IT-inventory script on many hosts that fires the noisy rule. *Noise hosts* controls how many.
3. **False-positive alerts** — writes closed alerts (`workflow_status: closed`, `workflow_reason: false_positive`) for the noisy rule directly into `.alerts-security.alerts-default`, carrying the rule's real UUID.

Why the false-positive default is 90: the noisy rule also raises about one *open* alert per noise host. Rule Tuning screens rules by false-positive **rate** against a 50% threshold, so closed alerts must clearly outnumber the open ones. With 30 closed and 30 open the rate sits exactly on the threshold. **Verified.**

> The alert documents must include `kibana.alert.rule.revision: 0`. Rule Tuning's screening query groups by rule UUID *and* revision, and alerts without a revision were silently dropped. The forge sets it. **Verified.**

### 4.2 Choose the endpoint (important for Respond)

Endpoint Analysis takes endpoint IDs only from the evidence (Elastic Defend `agent.id`) and **drops every response action it cannot fill**. Events with no agent produce a verdict but no isolate/kill/suspend.

| Mode | What it does | Use when |
|---|---|---|
| **Simulated** | Adds `agent.id`, `agent.type: endpoint` and `host.id` to the chain. IDs are derived from the host name, so each host is distinct and stable across runs. Proposals appear; **approving one does not execute anything** (the host is not enrolled). | You want to show that AlertZero *recommends* an action from the activity. **Verified.** |
| **Real enrolled host** | "Load enrolled endpoints" reads `/api/endpoint/metadata` and lists your Defend hosts; the synthetic chain is attributed to the host you pick (its name and `agent.id`). | You want an action that can really run, on a machine you own. **Listing verified; seeding and approval not verified** (the lab VM was offline). |

> **Real mode warning:** the attack is synthetic but attributed to a real host. Approving a proposed isolate / kill / suspend would run for real on it. Use only a machine you own, and release it afterwards (Endpoints → Release).

#### Use a new victim host for every run

Attack Discovery **attaches a new attack to an existing open investigation** for the same host. If the previous investigation for `ws-finance-07` is still open (for example its *Close Investigation* proposal is pending), the new attack is merged into it and **no new Investigate item or forensic handoff appears**. Click **New host** (or type a name) before each demo run. Resolve or ignore the old items; they don't block a fresh host. **Verified.**

### 4.3 Run the Workers

Use **Run sequence** (Alert Triage → Attack Discovery → Continuous Threat Hunt → Rule Tuning → Rule Coverage) or the per-Worker **Run** buttons. **Refresh status** shows each Worker's latest execution.

What to know about each run (all **verified** unless noted):

| Worker | What "completed" means | What to expect |
|---|---|---|
| **Alert Triage** | It dispatched its sweep | Workers also run on **schedules** (Triage every 15 min). If the scheduled run already processed the alerts, a manual run reports `nothing_pending`. Results appear as Investigate proposals (e.g. "Close 30 alerts on 28 hosts as false positive"). |
| **Attack Discovery** | It waited for its child workflows (~1 min) | Output reports attacks generated, alerts analyzed and reviews requested. The AI review that creates the proposal continues for several minutes. |
| **Rule Tuning** | It only screened rules (~2 s) | When a rule qualifies it requests a review; the AI review runs as a child workflow for several minutes, then a *Review rule for tuning* proposal appears under **Configure**. |
| **Continuous Threat Hunt** | It dispatched | Hunts threat reports. A manual run with no new candidate reports selects **0 reports** and does nothing (see 4.5). |
| **Rule Coverage** | It dispatched | *Not run through the forge.* It also runs hourly on its own and produces *Review detection gap* proposals. |
| **Endpoint Analysis** | — | Not in the sequence. It starts when you approve the forensic handoff (4.4). |

> **"Completed" is not "done".** For most Workers the top-level run only dispatches work; the AI analysis continues as child workflows and the proposals arrive minutes later. Watch **Proposed actions** in Kibana, not the forge log.

### 4.4 Approve in Kibana and show Respond

1. Open **Security → AlertZero → Proposed actions**.
2. Under **Investigate**, find the attack on your victim host (an Attack Discovery title such as *Office Script to Persistence and Dumping*) and approve the **forensic handoff** ("Run a deep forensics investigation"). **This approval cannot be undone** and starts Endpoint Analysis.
3. Endpoint Analysis takes about 5 minutes. It resolves the host from the attack's alerts, checks endpoint telemetry, runs a forensic agent that reconstructs the timeline and extracts IOCs, then proposes containment.
4. Under **Respond** you should see actions such as **Isolate host `<victim>`** with a comment citing the activity (hidden PowerShell, Run-key persistence, MiniDump, C2 beaconing), plus a **Close Investigation** item. In the Investigation view: forensic timeline, IOCs, impacted entities and the verdict. **Verified (simulated mode, 2 actions proposed, 0 failed).**

In simulated mode the isolate cannot execute. If you do not want to leave proposals pending in a shared project, decline them.

### 4.5 Hunt

Continuous Threat Hunt matches your data against **threat reports it builds itself from public feeds** (the ingest runs every 4 hours). You cannot invent a report. The forge supports the follow-up step:

1. Let Hunt build its reports (scheduled, or run it once).
2. In Kibana, open a Hunt threat report and pick an IOC (domain, IP or SHA256) that no rule covers.
3. In the forge, enter it under **Hunt IOC** and click **Seed IOC event** (writes `logs-demo.hunt-default`).
4. Run **Continuous Threat Hunt** again. It should record a finding and a detection gap, which Rule Coverage can then turn into a proposal.

**Observed:** when reports already exist and the feed ingest only finds items it has seen before, a manual run selects 0 candidate reports and does nothing. The Worker's manual trigger accepts up to 10 `reportIds`, which forces a "bypass sweep" of specific reports. **Verified:** seeding an event for an IP from a report's `discriminating` IOCs and running Hunt with that report's ID re-hunted a report already marked `clean` and recorded a hit (a critical Cloud Accounts T1078.004 finding), a proposal behind an approval gate, and 3 coverage items for the Detection Watch. The forge has no report picker yet, so the `reportIds` run was started through the Workflows API directly. Threat reports live in `.kibana-threat-reports` (readable with the demo key); prefer IOCs with `tier: discriminating` — `reference` IOCs are mostly benign links.

### 4.6 Reset

**Dry run** counts what would go; **Reset…** removes, after a confirmation, only objects tagged `alertzero-demo`:

- the tagged detection rules,
- the data streams `logs-endpoint.events.process-demo`, `logs-endpoint.events.network-demo`, `logs-demo.hunt-default`,
- tagged alerts (`_delete_by_query` on the alerts index; **verified to work on Serverless**; if a project ever refuses it the tab says so).

It does not remove proposals, investigations or Worker settings, and never touches real Defend data. The full reset was verified against a mock; only the alert cleanup was verified live.

---

## 5. What the forge calls

| Purpose | API |
|---|---|
| List Workers | `GET /api/workflows?managed=managed&size=100` |
| Start a Worker | `POST /api/workflows/workflow/{id}/run` (body `{inputs:{}}`; returns an execution id) |
| Follow a run | `GET /api/workflows/workflow/{id}/executions?size=5&omitStepRuns=true` |
| Create / find / delete rules | `POST /api/detection_engine/rules`, `_find`, `_bulk_action` |
| List enrolled endpoints | `GET /api/endpoint/metadata` |
| Seed data | `_bulk` to the demo data streams and `.alerts-security.alerts-default` |

Managed Worker workflow IDs:

| Worker | ID |
|---|---|
| Alert Triage | `system-security-floor-alert-triage-default` |
| Attack Discovery | `system-security-floor-attack-discovery-default` |
| Continuous Threat Hunt | `system-security-hunt-continuous-threat-hunt-default` |
| Rule Tuning | `system-security-detection-rule-tuning-default` |
| Rule Coverage | `system-security-detection-rule-coverage-default` |
| Endpoint Analysis | `system-security-forensics-endpoint-analysis-default` |

These are managed, Preview workflows and the IDs may change between versions. AlertZero itself has no documented REST API: enabling Workers and approving proposed actions are UI steps.

---

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| **Respond has no isolate/kill/suspend**, only "Close Investigation" | The evidence had no `agent.id` ("required agent data was unavailable"). Reseed in **Simulated** or **Real** mode. |
| **Nothing new under Investigate** after Attack Discovery | The attack was attached to an existing open investigation for the same host. Use **New host** and reseed. |
| **Rule Tuning requests 0 reviews** | The noisy rule's false-positive rate is under 50%, or the closed alerts lack `kibana.alert.rule.revision`. Seed more false positives (default 90) with the current forge. |
| **Triage says `nothing_pending`** | The scheduled run already handled the alerts. Check Proposed actions. |
| **Hunt selects 0 reports** | No new candidate threat reports. Seed an IOC from a report and rerun (4.5). |
| **Worker shows "not found"** | The managed workflow ID is missing: AlertZero may be off for the space, or the Workers aren't enabled. |
| **Run fails with HTTP 403** | The API key lacks workflow privileges (`workflowsManagement:execute`, read executions). |
| **`ws-…` alerts don't appear** | Wait 2–3 minutes; the rules run every minute with a 3-hour lookback. |
| **Connect test fails on Serverless** | Use the **Serverless** deployment type; `/_cluster/health` doesn't exist there. |
| Endpoint events fail to index | Defend integration/templates missing for `logs-endpoint.events.*`; install Elastic Defend. |

Note: the cluster adds `event.agent_id_status: auth_metadata_missing` to simulated events because they were not sent by a real agent. It did not prevent analysis.

---

## 7. Known limitations

- AlertZero is Preview; Worker workflow IDs and behaviour may change.
- **Real enrolled host mode** has not been exercised end to end (host picker, seeding to a real host, approval).
- **Rule Coverage** has not been run through the forge end to end, and the Hunt report picker does not exist yet (Hunt on chosen reports was verified via the API).
- Simulated endpoints cannot execute response actions by design.
- Seeded alerts are written directly to the alerts index; they are not produced by rule executions, so they have no rule-execution history.
- Event `tags` are mapped as analyzed text in the endpoint indices, so exact-match tag filters on events don't work (reset uses data stream deletion, not tags, for events).

## 8. Related

A separate AlertZero demo kit (`alertzero-demo`, Python seed scripts, a lab guide and a PowerShell attack simulation for a real Windows VM with Elastic Defend) shows the Forensics Watch with a **real** endpoint. The forge's simulated mode covers the *recommendation*; the lab VM covers an action that actually executes.
