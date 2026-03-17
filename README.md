# Elastic Demo Forge

A browser-based log generator for **Elastic Security** demos. Produce realistic vendor log data and push it directly to Elasticsearch — no scripts, no pipelines, no infrastructure required.

![Elastic Demo Forge](https://img.shields.io/badge/Elastic-8.x%20%7C%209.x-005571?logo=elastic&logoColor=white) ![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black) ![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white) ![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-06B6D4?logo=tailwindcss&logoColor=white)

---

## What it does

Elastic Demo Forge gives you a point-and-click UI to:

- **Generate log data** from seven vendor sources — Fortinet FortiGate, Palo Alto PAN-OS, Cisco Switch, Microsoft Exchange/Email, Elastic Endpoint, Windows Event Logs, and Linux/Syslog
- **Push directly to Elasticsearch** via the `_bulk` API using an API key — no Logstash, no Beats, no agents
- **Simulate APT attack scenarios** that produce correlated Kibana security alerts ready for [Elastic Attack Discovery](https://www.elastic.co/guide/en/security/current/attack-discovery.html)
- **Generate background noise** alongside attack scenarios to make the detection story realistic

---

## Screenshots

> _Connect your Elastic cluster, choose a vendor and log volume, click Generate + Push._

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Node.js** | v18 or higher |
| **npm** | v9 or higher (bundled with Node.js) |
| **Elasticsearch** | 8.x or 9.x (Elastic Cloud, ECK, or self-managed) |
| **Kibana** | Required for Attack Discovery and Security dashboards |
| **Elastic Security** | Enabled on your cluster (free or paid tier) |

> **Tip:** The easiest way to get started is a free [Elastic Cloud trial](https://cloud.elastic.co/). A 14-day trial gives you a fully managed cluster with Kibana and Elastic Security pre-configured.

---

## Quickstart

### 1. Clone the repo

```bash
git clone https://github.com/<your-org>/elastic-demo-forge.git
cd elastic-demo-forge
```

### 2. Install dependencies

```bash
npm install
```

### 3. Start the dev server

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### 4. Connect to Elasticsearch

In the **Settings** panel (top right):

1. Paste your **Elasticsearch URL** (e.g. `https://my-cluster.es.us-east-1.aws.found.io`)
2. Paste an **API key** with write access to the target indices

#### Creating an API key

In Kibana, go to **Stack Management → API Keys → Create API key**, or run:

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
          "names": ["logs-*", ".alerts-security.alerts-default"],
          "privileges": ["create_doc", "auto_configure"]
        }]
      }
    }
  }'
```

> The `.alerts-security.alerts-default` index permission is required for APT scenario alerts.

---

## Features

### Log Generators

Each vendor card lets you configure:

| Setting | Description |
|---|---|
| **Log volume** | Low / Medium / High |
| **Randomness** | Controls the pool of unique hostnames, users, and IPs |
| **Time range** | Spread logs over 1–24 hours |
| **Hostname prefix** | e.g. `CORP-WIN` → generates `CORP-WIN-001`, `CORP-WIN-002`, … |
| **Max unique hosts** | Cap the hostname pool to force cross-event correlation |
| **Include admin users** | Mix in privileged account names (Administrator, svc_backup, etc.) |
| **Index override** | Send to a custom index instead of the default integration index |

#### Supported vendors and their default indices

| Vendor | Default Index | Elastic Integration |
|---|---|---|
| Fortinet FortiGate | `logs-fortinet.firewall-default` | [Fortinet FortiGate](https://www.elastic.co/docs/reference/integrations/fortinet) |
| Palo Alto PAN-OS | `logs-panw.panos-5.5.0` | [Palo Alto Networks](https://www.elastic.co/docs/reference/integrations/panw) |
| Cisco Switch | `logs-cisco.ios-default` | [Cisco](https://www.elastic.co/docs/reference/integrations/cisco) |
| Microsoft Exchange | `logs-o365.audit-default` | [Microsoft 365](https://www.elastic.co/docs/reference/integrations/o365) |
| Elastic Endpoint | `logs-endpoint.events.process-default` | [Elastic Defend](https://www.elastic.co/guide/en/security/current/install-endpoint.html) |
| Windows Event Logs | `logs-system.security-default` | [Windows](https://www.elastic.co/docs/reference/integrations/windows) |
| Linux / Syslog | `logs-system.auth-default` | [System](https://www.elastic.co/docs/reference/integrations/system) |

#### Windows log types

Security, Application, and System logs are enabled by default. AppLocker and PowerShell Script Block logging are optional and disabled by default (shown in red — enable them to simulate more advanced attack telemetry).

---

### Attack Scenarios

The **Scenarios** tab provides pre-built attack chains. Two types:

#### APT Scenarios (generate Kibana security alerts)

These push structured `kibana.alert.*` documents directly to `.alerts-security.alerts-default`, making them immediately visible in Kibana Security and ready for [Attack Discovery](https://www.elastic.co/guide/en/security/current/attack-discovery.html).

| Scenario | Tactics | Alerts |
|---|---|---|
| **APT29 — Midnight Blizzard** | Initial Access → Execution → Persistence → Defense Evasion → Privilege Escalation → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration | 15 |
| **APT — Living off the Land** | Execution → Persistence → Defense Evasion → Privilege Escalation → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration | 11 |

Each APT scenario uses **real, verified IOCs** from CISA advisories and public threat intelligence:

- **SHA256 hashes** — SUNBURST, SUPERNOVA, TEARDROP, RAINDROP, EnvyScout, NativeZone, BoomBox, GraphicalProton (CISA AA20-352A, AA21-148A, AA22-074A, AA23-347A)
- **C2 IP addresses** — 24 addresses attributed to APT29/NOBELIUM infrastructure
- **C2 and phishing domains** — including `avsvmcloud.com`, `theyardservice.com`, `deftsecurity.com`, and others from Mandiant/Microsoft MSTIC reporting

> All IOCs are publicly disclosed and detectable on [VirusTotal](https://www.virustotal.com). They are included for SOC investigation demo purposes only.

#### Raw Log Scenarios

These generate structured event logs viewable step-by-step in the UI:

- Phishing Attack
- Phishing + Lateral Movement
- Data Exfiltration
- Ransomware

#### Background noise

APT scenarios can be paired with background noise (Low / Medium / High) that generates concurrent logs across multiple vendors, giving Attack Discovery a realistic signal-to-noise environment to correlate through.

---

## Recommended Elastic setup for demos

### Index templates and data streams

Elastic Demo Forge writes to the standard integration indices. For the best experience, install the relevant [Elastic integrations](https://www.elastic.co/integrations) in Kibana (**Fleet → Integrations**) before pushing data — this ensures the index templates, ILM policies, and field mappings are in place.

Minimum recommended integrations:

- Elastic Defend (Endpoint)
- Windows
- System
- Fortinet FortiGate
- Palo Alto Networks

### For Attack Discovery demos

1. Enable **Elastic Security** in Kibana
2. Ensure the `.alerts-security.alerts-default` index exists (created automatically when Elastic Security is enabled)
3. Push an APT scenario with **medium or high** background noise
4. Open **Kibana → Security → Attack Discovery** and run a discovery

The correlated alerts across `host.name`, `user.name`, MITRE tactics, and IOCs will be grouped into a single APT discovery with the full kill chain.

---

## Build for production

```bash
npm run build
```

Output is written to `dist/`. Serve it with any static file host (Nginx, S3 + CloudFront, GitHub Pages, Netlify, etc.).

```bash
# Preview the production build locally
npm run preview
```

---

## Project structure

```
elastic-demo-forge/
├── src/
│   ├── App.jsx          # All generators, scenarios, and UI (single-file architecture)
│   ├── App.css          # Global styles
│   ├── main.jsx         # React entry point
│   └── index.css        # Tailwind base
├── index.html
├── vite.config.js
├── tailwind.config.js
└── package.json
```

All log generators, vendor ingest mappings, scenario generators, and UI components live in `src/App.jsx`.

---

## Adding a new vendor

1. Write a generator function: `function generateMyVendorLogs(count, timeRangeMinutes) { ... }` — returns an array of raw log strings
2. Add an ingest mapping to `VENDOR_INGEST`: `{ getIndex(raw) { return 'logs-myvendor-default'; }, toDoc(raw) { return { '@timestamp': ..., message: raw, ... }; } }`
3. Add a vendor entry to the `VENDORS` array with `id`, `name`, `description`, `tags`, `indices`, and `generator`

---

## Security and data handling

- **No data leaves your browser** except to the Elasticsearch cluster you configure
- No backend, no telemetry, no external API calls
- API keys are stored only in React state (cleared on page reload)
- IOCs included in this tool are publicly disclosed threat intelligence from CISA, Mandiant, and Microsoft — they are not operational malware

---

## Disclaimer

This tool is intended for **authorised demo, testing, and training purposes only** against Elasticsearch clusters you own or have explicit permission to write to. The IOCs (file hashes, IP addresses, domains) are publicly disclosed indicators from official threat intelligence sources and are included solely to demonstrate SOC investigation workflows in Elastic Security.

---

## License

MIT
