// AlertZero demo support: seed data, detection rules, and on-demand Worker runs.
// Serverless Security projects only (AlertZero has no REST API of its own; Workers are
// managed Elastic Workflows, which the Workflows API can list, run and report on).
import { fetchES, fetchKibana } from './elastic.js';

export const AZ_TAG = 'alertzero-demo'; // every rule/doc we create carries this so reset can find it
const JSON_H = { 'Content-Type': 'application/json' };

// Worker -> managed workflow id. Workers also run on their own schedules; "run" here is on-demand.
export const WORKERS = [
  { key: 'triage', watch: 'Triage', name: 'Alert Triage', id: 'system-security-floor-alert-triage-default' },
  { key: 'attack', watch: 'Triage', name: 'Attack Discovery', id: 'system-security-floor-attack-discovery-default' },
  { key: 'hunt', watch: 'Hunt', name: 'Continuous Threat Hunt', id: 'system-security-hunt-continuous-threat-hunt-default' },
  { key: 'tuning', watch: 'Detection', name: 'Rule Tuning', id: 'system-security-detection-rule-tuning-default' },
  { key: 'coverage', watch: 'Detection', name: 'Rule Coverage', id: 'system-security-detection-rule-coverage-default' },
  { key: 'forensics', watch: 'Forensics', name: 'Endpoint Analysis', id: 'system-security-forensics-endpoint-analysis-default' },
];
// Order for "run sequence". Endpoint Analysis is started by approving a handoff in the UI, so it is left out.
export const SEQUENCE = ['triage', 'attack', 'hunt', 'tuning', 'coverage'];

// ─── helpers ─────────────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));
const iso = minutesAgo => new Date(Date.now() - minutesAgo * 60000).toISOString();
function mulberry32(a) { return () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
async function jsonOf(res) { const t = await res.text(); try { return JSON.parse(t); } catch { return t; } }
const errText = d => (typeof d === 'string' ? d : d?.message || d?.error?.reason || d?.error || JSON.stringify(d)).toString().slice(0, 300);

async function bulkCreate(cfg, index, docs) {
  if (!docs.length) return { ok: 0, errors: 0 };
  const lines = docs.flatMap(d => [JSON.stringify({ create: { _index: index } }), JSON.stringify(d)]);
  const res = await fetchES(cfg, '/_bulk', { method: 'POST', body: lines.join('\n') + '\n' });
  const d = await jsonOf(res);
  if (!res.ok) throw new Error(`bulk ${index}: HTTP ${res.status} ${errText(d)}`);
  const errs = (d.items || []).filter(i => Object.values(i)[0]?.error);
  return { ok: docs.length - errs.length, errors: errs.length, firstError: errs[0] ? JSON.stringify(Object.values(errs[0])[0].error).slice(0, 300) : undefined };
}

// ─── detection rules ─────────────────────────────────────────────────────────
const mitre = (tid, tac, id, tech) => [{ framework: 'MITRE ATT&CK', tactic: { id: tid, name: tac, reference: `https://attack.mitre.org/tactics/${tid}/` }, technique: [{ id, name: tech, reference: `https://attack.mitre.org/techniques/${id}/` }] }];
const RULE_INDEX = ['logs-endpoint.events.*', 'logs-demo.*'];
export const RULES = [
  ['az-demo-office-spawns-powershell', 'AZ Demo - Office app spawning PowerShell', 'high', 73, 'process.parent.name:("winword.exe" or "excel.exe") and process.name:"powershell.exe"', mitre('TA0002', 'Execution', 'T1059', 'Command and Scripting Interpreter')],
  ['az-demo-run-key-persistence', 'AZ Demo - Registry Run key persistence', 'medium', 47, 'process.name:"reg.exe" and process.command_line:*CurrentVersion*Run*', mitre('TA0003', 'Persistence', 'T1547', 'Boot or Logon Autostart Execution')],
  ['az-demo-lsass-minidump', 'AZ Demo - LSASS dump via comsvcs.dll', 'critical', 99, 'process.command_line:*comsvcs.dll* and process.command_line:*MiniDump*', mitre('TA0006', 'Credential Access', 'T1003', 'OS Credential Dumping')],
  ['az-demo-psexec-service', 'AZ Demo - Remote service execution (PsExec-style)', 'high', 73, 'process.name:"PSEXESVC.exe"', mitre('TA0008', 'Lateral Movement', 'T1021', 'Remote Services')],
  // Deliberately noisy: fires on a benign IT inventory script on many hosts -> false positives -> Rule Tuning
  ['az-demo-ps-exec-policy-bypass', 'AZ Demo - PowerShell ExecutionPolicy Bypass', 'medium', 47, 'process.name:"powershell.exe" and process.command_line:*ExecutionPolicy* and process.command_line:*Bypass*', mitre('TA0005', 'Defense Evasion', 'T1562', 'Impair Defenses')],
];
export const NOISY_RULE_ID = 'az-demo-ps-exec-policy-bypass';

// Creates the tagged custom rules. Returns Map<rule_id, {id (uuid), name, severity, risk}>.
export async function createRules(cfg, log) {
  const out = new Map();
  for (const [rule_id, name, severity, risk_score, query, threat] of RULES) {
    const body = { rule_id, name, description: `${name} (AlertZero demo)`, type: 'query', language: 'kuery', query, index: RULE_INDEX, severity, risk_score, interval: '1m', from: 'now-3h', to: 'now', max_signals: 200, enabled: true, tags: [AZ_TAG, 'AlertZero Demo'], threat };
    const res = await fetchKibana(cfg, '/api/detection_engine/rules', { method: 'POST', body: JSON.stringify(body) });
    let d = await jsonOf(res);
    if (res.status === 409) { const r2 = await fetchKibana(cfg, `/api/detection_engine/rules?rule_id=${rule_id}`); d = await jsonOf(r2); log?.(`rule exists: ${name}`); }
    else if (res.ok) log?.(`rule created: ${name}`);
    else { log?.(`rule FAILED (${res.status}): ${name} — ${errText(d)}`); continue; }
    if (d?.id) out.set(rule_id, { id: d.id, name, severity, risk_score, tags: [AZ_TAG, 'AlertZero Demo'], query });
  }
  return out;
}

// ─── synthetic Defend-shaped events (attack chain + benign noise) ────────────
const SIM_VICTIM = 'ws-finance-07', SERVER = 'srv-fileshare-02', USER = 'jdoe';
const C2_IP = '203.0.113.45', C2_DOMAIN = 'cdn-update-sync.example'; // documentation ranges, not real infra

// Defend-shaped identity. Endpoint Analysis takes endpoint ids only from the evidence (`agent.id`) and drops
// every response action it cannot fill, so events without an agent never yield isolate/kill/suspend proposals.
const uuidFrom = rnd => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.floor(rnd() * 16); return (c === 'x' ? r : (r & 3 | 8)).toString(16); });
// Stable per host name, so every simulated host gets its own distinct host.id / agent.id (and the same ones on every run).
const hashStr = str => { let h = 2166136261; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
const identityFor = host => ({ hostId: uuidFrom(mulberry32(hashStr('host:' + host))), agentId: uuidFrom(mulberry32(hashStr('agent:' + host))) });
const agentOf = id => ({ id: id.agentId, type: 'endpoint', name: 'endpoint', version: id.version || '9.2.0' });

// Enrolled Elastic Defend endpoints in the project (for "real host" mode).
export async function listEndpoints(cfg) {
  const res = await fetchKibana(cfg, '/api/endpoint/metadata?page=0&pageSize=50');
  const d = await jsonOf(res);
  if (!res.ok) throw new Error(`list endpoints: HTTP ${res.status} ${errText(d)}`);
  return (d?.data || []).map(x => {
    const m = x.metadata || x;
    return { agentId: m.agent?.id, hostId: m.host?.id, name: m.host?.hostname || m.host?.name, ip: [].concat(m.host?.ip || [])[0], os: m.host?.os?.name, version: m.agent?.version, status: x.host_status };
  }).filter(e => e.agentId && e.name);
}

function procDoc(id, minutesAgo, host, user, name, cmd, parent, parentCmd = '', pid, ppid, rnd) {
  pid = pid || 2000 + Math.floor(rnd() * 7000); ppid = ppid || 1000 + Math.floor(rnd() * 999);
  const who = id(host);
  return {
    '@timestamp': iso(minutesAgo), tags: [AZ_TAG], agent: agentOf(who),
    event: { category: ['process'], type: ['start'], action: 'exec', kind: 'event', dataset: 'endpoint.events.process', module: 'endpoint' },
    host: { id: who.hostId, name: host, hostname: host, ip: [who.ip || '10.20.9.9'], os: { type: 'windows', family: 'windows', name: 'Windows' } },
    user: { name: user, domain: 'CORP' },
    process: { name, executable: `C:\\Windows\\System32\\${name}`, command_line: cmd, pid, entity_id: `${host}-${pid}`, parent: { name: parent, command_line: parentCmd, pid: ppid, entity_id: `${host}-${ppid}` } },
  };
}
function netDoc(id, minutesAgo, host, ip, port, procName, domain) {
  const who = id(host);
  const d = {
    '@timestamp': iso(minutesAgo), tags: [AZ_TAG], agent: agentOf(who),
    event: { category: ['network'], type: ['start'], action: 'connection_attempted', kind: 'event', dataset: 'endpoint.events.network', module: 'endpoint' },
    host: { id: who.hostId, name: host, hostname: host, os: { type: 'windows' } }, process: { name: procName },
    destination: { ip, port }, network: { direction: 'egress', transport: 'tcp' },
  };
  if (domain) d.dns = { question: { name: domain } };
  return d;
}

// endpoint: { mode: 'simulated' } (generated agent ids) or { mode: 'real', ...enrolled endpoint from listEndpoints }.
// Real mode seeds the attack chain onto that host's name and agent id, so a proposed isolate/kill targets it.
// victim: host name for the simulated chain. Attack Discovery attaches a new attack to an existing open investigation
// for the same entities, so use a new name per run to get a fresh investigation (and a fresh forensic handoff).
export async function seedEvents(cfg, { noiseHosts = 30, endpoint = { mode: 'simulated' }, victim = SIM_VICTIM } = {}, log) {
  const rnd = mulberry32(7);
  const ids = new Map();
  const id = host => { if (!ids.has(host)) ids.set(host, identityFor(host)); return ids.get(host); };
  const real = endpoint.mode === 'real' && endpoint.agentId;
  if (endpoint.mode === 'real' && !real) throw new Error('Pick an enrolled endpoint first.');
  const VICTIM = real ? endpoint.name : (victim || SIM_VICTIM);
  if (real) ids.set(VICTIM, { hostId: endpoint.hostId || identityFor(VICTIM).hostId, agentId: endpoint.agentId, ip: endpoint.ip, version: endpoint.version });
  else ids.set(VICTIM, { ...id(VICTIM), ip: '10.20.0.45' });
  ids.set(SERVER, { ...id(SERVER), ip: '10.20.0.12' });
  const P = (t, host, user, name, cmd, parent, parentCmd, pid, ppid) => procDoc(id, t, host, user, name, cmd, parent, parentCmd, pid, ppid, rnd);
  const N = (...a) => netDoc(id, ...a);
  const procs = [
    P(45, VICTIM, USER, 'powershell.exe', 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA', 'winword.exe', 'WINWORD.EXE /n Invoice_Q4.docm', 4242, 3100),
    P(40, VICTIM, USER, 'reg.exe', 'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe"', 'powershell.exe', '', 5150, 4242),
    P(30, VICTIM, USER, 'rundll32.exe', 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 692 C:\\Users\\jdoe\\AppData\\Local\\Temp\\l.dmp full', 'powershell.exe', '', 6001, 4242),
    P(15, SERVER, USER, 'PSEXESVC.exe', 'C:\\Windows\\PSEXESVC.exe', 'services.exe'),
  ];
  const nets = [
    N(44, VICTIM, C2_IP, 443, 'powershell.exe', C2_DOMAIN), N(29, VICTIM, C2_IP, 443, 'rundll32.exe', C2_DOMAIN),
    N(16, VICTIM, '10.20.0.12', 445, 'System'), N(12, VICTIM, C2_IP, 443, 'upd.exe', C2_DOMAIN),
  ];
  const pick = a => a[Math.floor(rnd() * a.length)];
  for (let i = 0; i < 10; i++) procs.push(P(5 + Math.floor(rnd() * 45), VICTIM, USER, pick(['chrome.exe', 'outlook.exe', 'teams.exe']), 'benign background', 'explorer.exe'));
  // Benign noise: IT inventory script -> noisy rule -> false positives
  for (let i = 0; i < noiseHosts; i++) {
    const host = `ws-${pick(['hr', 'sales', 'ops', 'eng'])}-${String(1 + Math.floor(rnd() * 40)).padStart(2, '0')}`;
    procs.push(P(1 + Math.floor(rnd() * 170), host, 'svc-inventory', 'powershell.exe', 'powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\CorpIT\\inventory.ps1', 'ccmexec.exe', 'CcmExec.exe'));
  }
  const a = await bulkCreate(cfg, 'logs-endpoint.events.process-demo', procs);
  const b = await bulkCreate(cfg, 'logs-endpoint.events.network-demo', nets);
  log?.(`events (${real ? `real host ${VICTIM}, agent ${endpoint.agentId}` : `simulated agent for ${VICTIM}`}): process ${a.ok} ok/${a.errors} err, network ${b.ok} ok/${b.errors} err${a.firstError ? ' — ' + a.firstError : ''}`);
  log?.('Rules run every minute; alerts appear in ~2-3 min.');
}

// ─── closed false-positive alerts for Rule Tuning ────────────────────────────
// Rule Tuning needs a rule with enough alerts closed as false positives. These carry the real rule uuid and
// `kibana.alert.rule.revision: 0` (its screening query groups by uuid + revision, so a missing revision is silently dropped).
export async function seedFalsePositives(cfg, { count = 90, ruleMap } = {}, log) {
  const rules = ruleMap || await createRules(cfg);
  const rule = rules.get(NOISY_RULE_ID);
  if (!rule) throw new Error('Noisy rule not found — create the demo rules first.');
  const rnd = mulberry32(11);
  const docs = [];
  for (let i = 0; i < count; i++) {
    const minutesAgo = 30 + Math.floor(rnd() * 60 * 24 * 5); // spread over ~5 days
    const host = `ws-${['hr', 'sales', 'ops', 'eng'][Math.floor(rnd() * 4)]}-${String(1 + Math.floor(rnd() * 40)).padStart(2, '0')}`;
    const ts = iso(minutesAgo);
    docs.push({
      '@timestamp': ts, event: { kind: 'signal', category: ['process'], action: 'exec', outcome: 'success' },
      kibana: { version: '9.7.0', space_ids: ['default'], alert: {
        uuid: crypto.randomUUID(), depth: 1, reason: `process event with process powershell.exe, by svc-inventory on ${host} created ${rule.severity} alert ${rule.name}.`,
        rule: { uuid: rule.id, rule_id: NOISY_RULE_ID, name: rule.name, description: `${rule.name} (AlertZero demo)`, category: 'Custom Query Rule', consumer: 'siem', producer: 'siem', rule_type_id: 'siem.queryRule', type: 'query', version: 1, revision: 0, enabled: true, tags: rule.tags, language: 'kuery', query: rule.query, index: RULE_INDEX },
        severity: rule.severity, risk_score: rule.risk_score, status: 'active',
        workflow_status: 'closed', workflow_reason: 'false_positive', workflow_status_updated_at: new Date(new Date(ts).getTime() + 3600000).toISOString(),
        original_time: ts,
      } },
      host: { name: host, hostname: host, os: { name: 'Windows', family: 'windows' } }, user: { name: 'svc-inventory', domain: 'CORP' },
      process: { name: 'powershell.exe', command_line: 'powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\CorpIT\\inventory.ps1', parent: { name: 'ccmexec.exe' } },
    });
  }
  const r = await bulkCreate(cfg, '.alerts-security.alerts-default', docs);
  log?.(`false-positive alerts: ${r.ok} ok/${r.errors} err${r.firstError ? ' — ' + r.firstError : ''}`);
  return r;
}

// ─── Hunt: threat reports + IOC seeding ──────────────────────────────────────
// Continuous Threat Hunt matches data against threat reports it builds itself (stored in .kibana-threat-reports).
// A manual run that names `reportIds` is a "bypass sweep": it hunts those reports even if they were hunted before.
const TIER_RANK = { discriminating: 0, uncertain: 1, reference: 2, denied: 3 };
export const sortIocs = iocs => [...iocs].sort((x, y) => (TIER_RANK[x.tier] ?? 9) - (TIER_RANK[y.tier] ?? 9));

// Usable reports (extraction_method workflow_v4), newest first. `extracted` is not indexed, so IOCs are read from _source.
export async function listThreatReports(cfg) {
  const body = { size: 200, sort: [{ '@timestamp': 'desc' }], _source: ['source', 'severity', '@timestamp', 'rank_score', 'extracted.iocs', 'evidence', 'lineage.extraction_method'] };
  const res = await fetchES(cfg, '/.kibana-threat-reports/_search', { method: 'POST', headers: JSON_H, body: JSON.stringify(body) });
  const d = await jsonOf(res);
  if (!res.ok) throw new Error(`threat reports: HTTP ${res.status} ${errText(d)}`);
  return (d.hits?.hits || []).filter(h => h._source?.lineage?.extraction_method === 'workflow_v4').map(h => {
    const s = h._source;
    const ev = (s.evidence || []).find(e => e.space_id === 'default') || (s.evidence || [])[0] || {};
    const url = s.source?.url || '';
    return {
      id: h._id, date: s['@timestamp'], severity: s.severity?.level || '?', rank: s.rank_score, source: s.source?.name || '?', url,
      title: decodeURIComponent(url.split('/').filter(Boolean).pop() || h._id).replace(/[-_]/g, ' '),
      huntStatus: ev.last_hunt_status || 'none', hits: ev.last_hunt_event_hit_count || 0, lastHunted: ev.last_hunted_at,
      iocs: sortIocs((s.extracted?.iocs || []).filter(i => i.value).map(i => ({ type: i.type, value: i.value, tier: i.tier || 'uncertain' }))),
    };
  });
}

// IOC -> argument for seedHuntIoc, or null when the type cannot be seeded (email, wallet).
export function iocSeedArg(ioc) {
  if (!ioc) return null;
  if (ioc.type === 'ip') return { ip: ioc.value };
  if (ioc.type === 'domain') return { domain: ioc.value };
  if (ioc.type === 'url') return { url: ioc.value };
  if (ioc.type === 'hash' && [32, 40, 64].includes(ioc.value.length)) return { hash: ioc.value };
  return null;
}

export async function seedHuntIoc(cfg, { domain, ip, sha256, hash, url }, log) {
  hash = hash || sha256;
  if (!domain && !ip && !hash && !url) throw new Error('Give at least one IOC');
  const doc = { '@timestamp': iso(0), tags: [AZ_TAG], host: { name: 'ws-eng-12', os: { type: 'windows' } }, user: { name: 'asmith' }, event: { category: ['network'], type: ['connection'], kind: 'event', dataset: 'demo.hunt' }, process: { name: 'svchost.exe' } };
  if (url) { try { domain = domain || new URL(url).hostname; } catch { /* not a parsable url */ } doc.url = { full: url }; }
  if (domain) { doc.dns = { question: { name: domain } }; doc.destination = { domain }; }
  if (ip) doc.destination = { ...(doc.destination || {}), ip, port: 443 };
  if (hash) { const algo = { 64: 'sha256', 40: 'sha1', 32: 'md5' }[hash.length] || 'sha256'; doc.file = { hash: { [algo]: hash }, name: 'payload.bin' }; doc.process.hash = { [algo]: hash }; }
  const r = await bulkCreate(cfg, 'logs-demo.hunt-default', [doc]);
  log?.(`hunt IOC event: ${r.ok} ok/${r.errors} err${r.firstError ? ' — ' + r.firstError : ''}`);
}

// ─── Proposals: preview and dismiss ──────────────────────────────────────────
// Every pending proposal is a `system-create-proposal` run parked at its approval gate (status waiting_for_input).
// Resuming the run answers the gate. This module can ONLY dismiss: approving would run the proposed action
// (isolate a host, kill a process, close alerts, edit a rule), so no approve path exists here.
const PROPOSAL_WORKFLOW = 'system-create-proposal';
const DISMISS_BODY = Object.freeze({ input: Object.freeze({ approved: false }) });
// What counts as "demo" for the scoped clean-up: demo rule names and the demo hosts this forge seeds.
const DEMO_RE = /AZ Demo|alertzero-demo|ws-finance-\d+|ws-eng-12|srv-fileshare-02|svc-inventory/i;

async function pool(items, limit, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (i < items.length) { const n = i++; out[n] = await fn(items[n], n); } }));
  return out;
}

export async function listPendingProposals(cfg, onProgress) {
  const ids = [];
  for (let page = 1; page < 50; page++) {
    const res = await fetchKibana(cfg, `/api/workflows/workflow/${PROPOSAL_WORKFLOW}/executions?statuses=waiting_for_input&size=100&page=${page}&omitStepRuns=true`);
    const d = await jsonOf(res);
    if (!res.ok) throw new Error(`list proposals: HTTP ${res.status} ${errText(d)}`);
    const rows = rowsOf(d);
    ids.push(...rows.map(r => ({ id: r.id, startedAt: r.startedAt })));
    if (rows.length < 100) break;
  }
  let done = 0;
  const items = await pool(ids, 6, async ({ id, startedAt }) => {
    const res = await fetchKibana(cfg, `/api/workflows/executions/${id}?omitStepExecutions=true`);
    const d = res.ok ? await jsonOf(res) : {};
    const i = d?.context?.inputs || {};
    onProgress?.(++done, ids.length);
    const comment = i.comment || '';
    return { id, startedAt, title: i.title || '(untitled)', category: i.category || '', action: i.actionWorkflowId || '', demo: DEMO_RE.test(`${i.title || ''} ${comment}`), snippet: comment.replace(/\s+/g, ' ').slice(0, 140) };
  });
  return items.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
}

// Dismisses (never approves) the given proposal runs. Returns { ok, failed: [{id, error}] }.
export async function dismissProposals(cfg, ids, onProgress) {
  let done = 0; const failed = [];
  await pool(ids, 3, async id => {
    try {
      const res = await fetchKibana(cfg, `/api/workflows/executions/${id}/resume`, { method: 'POST', body: JSON.stringify(DISMISS_BODY) });
      if (!res.ok) failed.push({ id, error: `HTTP ${res.status} ${errText(await jsonOf(res))}` });
    } catch (e) { failed.push({ id, error: e.message }); }
    onProgress?.(++done, ids.length);
  });
  return { ok: ids.length - failed.length, failed };
}

// ─── reset ───────────────────────────────────────────────────────────────────
const STREAMS = ['logs-endpoint.events.process-demo', 'logs-endpoint.events.network-demo', 'logs-demo.hunt-default'];
export async function resetDemo(cfg, { dryRun = true } = {}, log) {
  const filter = encodeURIComponent(`alert.attributes.tags:"${AZ_TAG}"`);
  const rr = await fetchKibana(cfg, `/api/detection_engine/rules/_find?per_page=200&filter=${filter}`);
  const rd = await jsonOf(rr);
  (rd?.data || []).forEach(r => log?.(`rule: ${r.name}`));
  const q = { query: { term: { 'kibana.alert.rule.tags': AZ_TAG } } };
  if (dryRun) {
    const c = await jsonOf(await fetchES(cfg, '/.alerts-security.alerts-default/_count', { method: 'POST', headers: JSON_H, body: JSON.stringify(q) }));
    log?.(`${rd?.data?.length || 0} rules, ${STREAMS.length} data streams, ~${c?.count ?? '?'} alerts would be removed (dry run)`);
    return;
  }
  const del = await fetchKibana(cfg, '/api/detection_engine/rules/_bulk_action', { method: 'POST', body: JSON.stringify({ action: 'delete', query: `alert.attributes.tags: "${AZ_TAG}"` }) });
  log?.(`rules delete: HTTP ${del.status}`);
  for (const s of STREAMS) { const r = await fetchES(cfg, `/_data_stream/${s}`, { method: 'DELETE', headers: JSON_H }); log?.(`data stream ${s}: HTTP ${r.status}`); }
  const ar = await fetchES(cfg, '/.alerts-security.alerts-default/_delete_by_query?conflicts=proceed', { method: 'POST', headers: JSON_H, body: JSON.stringify(q) });
  const ad = await jsonOf(ar);
  log?.(ar.ok ? `alerts deleted: ${ad.deleted}` : `alert cleanup not permitted here (HTTP ${ar.status}) — close/delete them in Kibana`);
}

// ─── Workers ─────────────────────────────────────────────────────────────────
const TERMINAL = new Set(['completed', 'failed', 'cancelled', 'timed_out', 'skipped']);
const rowsOf = d => (Array.isArray(d) ? d : d?.results || d?.data || []);

// Worker status: enabled flag from the managed list + the most recent execution of each.
export async function workerStatus(cfg) {
  const res = await fetchKibana(cfg, '/api/workflows?managed=managed&size=100');
  const d = await jsonOf(res);
  if (!res.ok) throw new Error(`list workflows: HTTP ${res.status} ${errText(d)}`);
  const byId = new Map(rowsOf(d).map(w => [w.id, w]));
  return Promise.all(WORKERS.map(async w => {
    const wf = byId.get(w.id);
    if (!wf) return { ...w, found: false };
    const er = await fetchKibana(cfg, `/api/workflows/workflow/${w.id}/executions?size=1&omitStepRuns=true`);
    const last = er.ok ? rowsOf(await jsonOf(er))[0] : null;
    return { ...w, found: true, enabled: wf.enabled, last: last ? { status: last.status, startedAt: last.startedAt, by: last.triggeredBy || last.executedBy } : null };
  }));
}

// Starts a Worker on demand. Returns the execution id (shape of the response is not documented, so be liberal).
export async function runWorker(cfg, worker, inputs = {}) {
  const res = await fetchKibana(cfg, `/api/workflows/workflow/${worker.id}/run`, { method: 'POST', body: JSON.stringify({ inputs }) });
  const d = await jsonOf(res);
  if (!res.ok) throw new Error(`run ${worker.name}: HTTP ${res.status} ${errText(d)}`);
  return d?.workflowExecutionId || d?.executionId || d?.id || null;
}

// Polls until the execution is terminal (or timeout). Falls back to the newest execution if the id isn't returned.
export async function waitForRun(cfg, worker, executionId, { timeoutMs = 600000, intervalMs = 5000, startedAfter = Date.now() - 5000 } = {}, onTick) {
  const t0 = Date.now();
  for (;;) {
    const r = await fetchKibana(cfg, `/api/workflows/workflow/${worker.id}/executions?size=5&omitStepRuns=true`);
    const rows = r.ok ? rowsOf(await jsonOf(r)) : [];
    const ex = executionId ? rows.find(x => x.id === executionId) : rows.find(x => new Date(x.startedAt).getTime() >= startedAfter);
    if (ex) { onTick?.(ex.status); if (TERMINAL.has(ex.status)) return ex; }
    if (Date.now() - t0 > timeoutMs) return { status: 'timeout' };
    await sleep(intervalMs);
  }
}
