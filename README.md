<img width="1056" height="576" alt="Gemini_Generated_Image_nfhd2bnfhd2bnfhd (1)" src="https://github.com/user-attachments/assets/14b01232-ddf3-4d41-bd99-a4e497084b51" />
# Elastic Demo Forge

A browser-based data generator for **Elastic Security** demos. Produce realistic vendor log data, attack scenarios, ML anomalies and AlertZero demo data, and push it straight to Elasticsearch and Kibana — no Logstash, no Beats, no agents.

![Elastic Demo Forge](https://img.shields.io/badge/Elastic-8.x%20%7C%209.x%20%7C%20Serverless-005571?logo=elastic&logoColor=white) ![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black) ![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white) ![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-06B6D4?logo=tailwindcss&logoColor=white)

---

## Versions

| Version | Where | Targets |
|---|---|---|
| **v2** (in development, `2.0.0-dev.0`) | `main` | Elastic Cloud Hosted, self-managed **and Elastic Cloud Serverless** (Security projects), plus the **AlertZero** tab |
| **v1** (`v1.0.0`) | tag `v1.0.0`, branch `release/1.x` | Elastic Cloud Hosted and self-managed only |

Fixes that apply to both land on `release/1.x` first and are merged into `main`. See [CHANGELOG.md](CHANGELOG.md).

To run v1: `git checkout v1.0.0` (or `release/1.x` for later ECH-only fixes).

---

## What it does

- **Generate log data** from 13 vendor sources (see [Supported vendors](#supported-vendors-and-their-default-indices))
- **Push directly to Elasticsearch** via the `_bulk` API using an API key (or basic auth on hosted/self-managed)
- **Simulate attack scenarios** that produce correlated Kibana security alerts ready for [Attack Discovery](https://www.elastic.co/docs/solutions/security/ai/attack-discovery)
- **Generate background noise** alongside scenarios so the detection story is realistic
- **Set up ML anomaly detection** demo jobs and matching scenarios (impossible travel, unusual login time)
- **Run the AlertZero demo (v2, Serverless Security)**: seed data for all four Watches, run the Workers on demand, and show proposed response actions. See the [AlertZero walkthrough](docs/ALERTZERO.md)

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Node.js** | v18 or higher |
| **npm** | v9 or higher (bundled with Node.js) |
| **Elastic deployment** | One of: Elastic Cloud Hosted (8.x / 9.x), self-managed, or **Elastic Cloud Serverless — Security project** (v2 only) |
| **Kibana URL** | Needed for detection rules, ML rules, alert links and everything in the AlertZero tab |
| **Elastic Security** | Enabled (free or paid tier) |

> **Tip:** A free [Elastic Cloud trial](https://cloud.elastic.co/) gives you a managed cluster with Kibana and Elastic Security pre-configured.

---

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/Raricoza/elastic_sourceforge.git elastic-demo-forge
cd elastic-demo-forge
npm install
```

### 2. Start the dev server

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). If that port is taken, Vite prints the port it picked instead.

> **Run it with the dev server.** All Elasticsearch and Kibana requests go through the dev server's `/es-proxy` and `/kibana-proxy` routes (this avoids CORS and allows self-signed certificates). `npm run build` / `npm run preview` do **not** include these routes, so a static build cannot reach your cluster on its own.

### 3. Connect

Click **Connect ES** (top right) and choose a **Deployment Type**:

| | Cloud Hosted / Self-managed | Serverless (Security) — v2 |
|---|---|---|
| **Elasticsearch URL** | `https://<deployment>.es.<region>.<provider>.found.io` or `http://host:9200` | `https://<project>.es.<region>.<provider>.elastic.cloud` |
| **Kibana URL** | `https://<deployment>.kb...` (optional but recommended) | `https://<project>.kb...` (required for AlertZero) |
| **Auth** | API key or basic auth | **API key only** (serverless has no username/password access) |
| **Connection test** | `GET /_cluster/health` | `GET /` (serverless has no `/_cluster/health`; the dialog confirms the project is serverless) |
| **Kibana API calls** | standard | send `elastic-api-version: 2023-10-31` |

The connection (including the API key) is saved in your browser's `localStorage` under `elastic_config_forge`. Optional fields in the same dialog: an alert **email address** and **email connector ID** for per-alert notifications.

#### Creating an API key

**Serverless:** create the key in Kibana → **Stack Management → API keys**. (The `/_security/api_key` call below needs basic auth, which serverless does not offer.)

**Hosted / self-managed:** in Kibana go to **Stack Management → API Keys**, or run:

```bash
curl -X POST "https://<ES_URL>/_security/api_key" \
  -H "Authorization: Basic <base64(user:pass)>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "demo-forge",
    "role_descriptors": {
      "demo_writer": {
        "cluster": ["monitor"],
        "indices": [{
          "names": ["logs-*", "metrics-*", ".alerts-security.alerts-default"],
          "privileges": ["create_doc", "auto_configure"]
        }]
      }
    }
  }'
```

> `.alerts-security.alerts-default` write access is needed for APT scenario alerts. A key that only writes indices cannot create detection rules, ML jobs or run Workers: those need Kibana and `manage_ml` / Workflows privileges. The AlertZero demo has been tested end to end with a broad-privilege key; narrower scoping has not been verified.

---

## Features

### Log generators

Each vendor card lets you configure:

| Setting | Description |
|---|---|
| **Log volume** | Low / Medium / High |
| **Randomness** | Controls the pool of unique hostnames, users, and IPs |
| **Time range** | Last 15 minutes, 1 hour, 6 hours, 24 hours or 7 days (with an optional "logs per day" mode for 7 days) |
| **Hostname prefix** | e.g. `CORP-WIN` → generates `CORP-WIN-001`, `CORP-WIN-002`, … |
| **Max unique hosts** | Cap the hostname pool to force cross-event correlation |
| **Include admin users** | Mix in privileged account names (Administrator, svc_backup, etc.) |
| **Index override** | Send to a custom index instead of the default integration index |

Pushes are sent in batches so the cluster isn't flooded.

#### Supported vendors and their default indices

| Vendor | Default indices |
|---|---|
| Fortinet FortiGate | `logs-fortinet.fortigate.traffic-default`, `logs-fortinet.fortigate.utm-default` |
| Palo Alto Networks | `logs-panw.panos-5.5.0` |
| Cisco Switches | `logs-cisco.ios-default` |
| E-Mail Systems (O365 / Exchange) | `logs-o365.audit-default`, `logs-microsoft_exchange_server.log-default` |
| Endpoint Telemetry | `logs-endpoint.events.process-default`, `logs-endpoint.alerts-default` |
| Windows Events | `logs-windows.security-default`, `.application-`, `.system-`, `.powershell_operational-`, `.applocker-default` |
| Linux / Syslog | `logs-system.auth-default`, `logs-auditd.log-default` |
| Oracle Database | `logs-oracle.audit-default`, `metrics-oracle.performance-default` |
| Microsoft SQL Server | `logs-microsoft_sqlserver.{audit,log,agent}-default`, `metrics-microsoft_sqlserver.{transaction_log,performance}-default` |
| AWS CloudTrail | `logs-aws.cloudtrail-default` |
| Okta | `logs-okta.system-default` |
| CrowdStrike Falcon | `logs-crowdstrike.{falcon,fdr,alert,vulnerability,host}-default` |
| Windows DNS & AD | `logs-windows.sysmon_operational-default`, `logs-windows.security-default` |

For the best result install the matching [Elastic integrations](https://www.elastic.co/integrations) first (**Fleet → Integrations**) so index templates and mappings exist.

Windows Security, Application and System logs are on by default; AppLocker and PowerShell Script Block logging are optional.

---

### Attack Scenarios

The **Attack Scenarios** tab provides pre-built attack chains.

#### APT scenarios (generate Kibana security alerts)

These push structured `kibana.alert.*` documents to `.alerts-security.alerts-default`, together with correlated logs, so they show up in Kibana Security and are ready for Attack Discovery. Rule links work because the forge creates matching (disabled) detection rules through the Kibana API when a Kibana URL is configured.

| Scenario | Notes |
|---|---|
| **APT29 — Midnight Blizzard** | OAuth phishing → persistence → credential dump → lateral movement → C2 → exfiltration (15 alerts) |
| **APT — Living off the Land** | certutil → mshta → schtasks → log clearing → NTDS dump → WMI → exfil (11 alerts) |
| **Ransomware Outbreak** | Office macro → PowerShell → VSS/backup deletion → Defender disabled → encryption → SMB spread |

Each APT scenario uses publicly disclosed IOCs from CISA advisories, Mandiant and Microsoft MSTIC reporting (SHA256 hashes, C2 IPs and domains). They are included for SOC investigation demos only.

#### Raw log scenarios

Structured event logs viewable step by step: **Phishing Attack**, **Phishing + Lateral Movement**, **Data Exfiltration**.

#### Background noise

Pair any APT scenario with noise: Low, Medium, High, or Custom (a mix of Windows, Linux, email, firewall and database logs with a configurable count).

#### Email notifications

If you set an alert email and connector ID in the connection dialog, one email is sent per generated alert (silently — it never blocks a push).

---

### ML anomaly detection

The scenarios page has an **ML Anomaly Detection** section:

- **ML setup card** creates two demo jobs and their detection rules: *Rare Source IP per User* and *Unusual Login Hour per User*. The datafeed starts 7 days back so seeded history is processed.
- **Impossible Travel** and **Unusual Login Time** scenario cards generate the matching authentication events.

On Serverless this requires a Security or Observability project.

---

### AlertZero demo (v2, Serverless Security)

The **AlertZero** tab seeds data for all four Watches and runs the Workers on demand:

1. **Seed** five tagged custom rules (one deliberately noisy), a Defend-shaped attack chain with benign noise, and closed false-positive alerts for Rule Tuning.
2. **Pick the endpoint** the attack is attributed to: *Simulated* (generated agent, so Endpoint Analysis proposes isolate / kill / suspend without anything executing) or *Real enrolled host* (loaded from your project).
3. **Run Workers** through the Workflows API, one by one or in sequence.
4. **Approve in Kibana** (Security → AlertZero → Proposed actions) — approvals stay a human step.
5. **Reset** removes only what carries the `alertzero-demo` tag.

Runs are billed (workflow executions, Agent Builder, model tokens). Full guide, expected results and troubleshooting: **[docs/ALERTZERO.md](docs/ALERTZERO.md)**.

---

## Recommended Elastic setup for demos

### Index templates and data streams

The forge writes to the standard integration indices. Install the relevant integrations first. Minimum recommended: Elastic Defend (Endpoint), Windows, System, Fortinet FortiGate, Palo Alto Networks.

### For Attack Discovery demos

1. Enable **Elastic Security** in Kibana and configure an AI connector for Attack Discovery
2. Ensure `.alerts-security.alerts-default` exists (created when Elastic Security is enabled)
3. Push an APT scenario with **medium or high** background noise
4. Open **Kibana → Security → Attack Discovery** and run a discovery

Correlated alerts across `host.name`, `user.name`, MITRE tactics and IOCs are grouped into a single discovery with the full kill chain.

---

## Build

```bash
npm run build     # output in dist/
npm run lint
```

`dist/` is a static bundle, but see the note under [Quickstart](#2-start-the-dev-server): the app needs the dev server's proxy routes to reach your cluster.

---

## Project structure

```
elastic-demo-forge/
├── src/
│   ├── App.jsx            # Generators, scenarios, ML, and main UI (single-file architecture)
│   ├── elastic.js         # Connection config, auth headers, ES/Kibana fetch helpers (hosted + serverless)
│   ├── alertzero.js       # AlertZero: rules, seed data, Worker listing/running, reset
│   ├── AlertZeroPage.jsx  # AlertZero tab UI
│   ├── App.css, index.css, main.jsx
├── docs/
│   └── ALERTZERO.md       # AlertZero walkthrough
├── CHANGELOG.md
├── vite.config.js         # Dev server + /es-proxy and /kibana-proxy middleware
├── tailwind.config.js
└── package.json
```

Log generators, vendor ingest mappings, scenario generators and most UI live in `src/App.jsx`. Connection handling lives in `src/elastic.js` so the AlertZero module shares it.

---

## Adding a new vendor

1. Write a generator: `function generateMyVendorLogs(count, timeRangeMinutes) { ... }` — returns an array of raw log strings
2. Add an ingest mapping to `VENDOR_INGEST`: `{ getIndex(raw) { return 'logs-myvendor-default'; }, toDoc(raw) { return { '@timestamp': ..., message: raw, ... }; } }`
3. Add a vendor entry to `VENDORS` with `id`, `name`, `description`, `tags`, `indices`, and `generator`

---

## Security and data handling

- No backend of ours and no telemetry. The browser talks to the local dev server, which forwards requests only to the Elasticsearch and Kibana URLs you configure.
- Your connection settings, **including the API key or password, are stored in the browser's `localStorage`** (key `elastic_config_forge`) until you clear them. Use a dedicated, least-privilege key and clear site data on shared machines.
- The dev-server proxy accepts self-signed certificates (`rejectUnauthorized: false`) so local clusters work. Don't point it at an untrusted endpoint.
- The vendor cards load logos from the Simple Icons CDN; nothing else leaves your machine.
- The AlertZero tab **creates and deletes** objects (detection rules, demo data streams, tagged alerts) and can start billed Worker runs. It asks for confirmation before runs and before reset. Only use it against projects you own.
- IOCs are publicly disclosed threat intelligence from CISA, Mandiant and Microsoft — not operational malware.

---

## Disclaimer

This tool is intended for **authorised demo, testing and training purposes only** against Elastic deployments you own or have explicit permission to write to. The IOCs are publicly disclosed indicators included solely to demonstrate SOC investigation workflows in Elastic Security.

---

## License

MIT
