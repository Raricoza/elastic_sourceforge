import { useState, useRef } from 'react';
import { isServerless } from './elastic.js';
import { WORKERS, SEQUENCE, createRules, listEndpoints, seedEvents, seedFalsePositives, seedHuntIoc, listThreatReports, iocSeedArg, resetDemo, workerStatus, runWorker, waitForRun } from './alertzero.js';

const inputCls = 'w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500';
function Btn({ children, onClick, disabled, tone = 'blue' }) {
  const t = tone === 'red' ? 'border-red-500/40 text-red-400 hover:bg-red-500/10' : 'border-blue-500/40 text-blue-300 hover:bg-blue-500/10';
  return <button onClick={onClick} disabled={disabled} className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${t}`}>{children}</button>;
}
function Card({ step, title, children }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2"><span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 text-[10px] font-bold flex items-center justify-center">{step}</span><h3 className="text-sm font-semibold text-white">{title}</h3></div>
      {children}
    </div>
  );
}
const SEV_TONE = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400' };
const HUNT_TONE = { hit: 'text-red-400', clean: 'text-green-400', incomplete: 'text-amber-400' };
const TIER_TONE = { discriminating: 'text-red-300', uncertain: 'text-amber-300', reference: 'text-gray-500', denied: 'text-gray-600' };
const STATUS_TONE = { completed: 'text-green-400', failed: 'text-red-400', running: 'text-blue-400', pending: 'text-gray-400' };

export default function AlertZeroPage({ elasticConfig: cfg }) {
  const [busy, setBusy] = useState('');
  const [lines, setLines] = useState([]);
  const [workers, setWorkers] = useState(null);
  // Rule Tuning needs the false-positive rate well above its 50% threshold: the noisy rule also raises ~1 open alert per noise host.
  const [fpCount, setFpCount] = useState(90);
  const [noiseHosts, setNoiseHosts] = useState(30);
  const [ioc, setIoc] = useState({ domain: '', ip: '', sha256: '' });
  const [reports, setReports] = useState(null);
  const [reportPick, setReportPick] = useState('');
  const [iocPick, setIocPick] = useState(0);
  const [onlyUseful, setOnlyUseful] = useState(true);
  const [epMode, setEpMode] = useState('simulated'); // 'simulated' | 'real'
  const [endpoints, setEndpoints] = useState(null);
  const [epPick, setEpPick] = useState('');
  const [victim, setVictim] = useState('ws-finance-07');
  const freshVictim = () => setVictim(`ws-finance-${String(10 + Math.floor(Math.random() * 89))}`);
  const stop = useRef(false);

  const ready = !!cfg?.url && !!cfg?.kibanaUrl;
  const log = m => setLines(l => [...l, `${new Date().toLocaleTimeString()}  ${m}`]);
  const wrap = (name, fn) => async () => {
    setBusy(name);
    try { await fn(); } catch (e) { log(`ERROR ${name}: ${e.message}`); } finally { setBusy(''); }
  };

  const endpointOpt = () => {
    if (epMode !== 'real') return { mode: 'simulated' };
    const e = endpoints?.find(x => x.agentId === epPick);
    if (!e) throw new Error('Load enrolled endpoints and pick one first.');
    return { mode: 'real', ...e };
  };
  const loadEps = wrap('load endpoints', async () => {
    const list = await listEndpoints(cfg);
    setEndpoints(list); setEpPick(list[0]?.agentId || '');
    log(`${list.length} enrolled endpoint(s): ${list.map(e => `${e.name} (${e.status || '?'})`).join(', ') || 'none'}`);
  });
  const refresh = wrap('status', async () => { setWorkers(await workerStatus(cfg)); log('worker status refreshed'); });
  const rules = wrap('rules', async () => { await createRules(cfg, log); });
  const events = wrap('events', async () => { await seedEvents(cfg, { noiseHosts, endpoint: endpointOpt(), victim }, log); });
  const fps = wrap('false positives', async () => { await seedFalsePositives(cfg, { count: fpCount }, log); });
  const hunt = wrap('hunt IOC', async () => { await seedHuntIoc(cfg, ioc, log); });
  const HUNT = WORKERS.find(w => w.key === 'hunt');
  const useful = r => r.iocs.filter(i => ['discriminating', 'uncertain'].includes(i.tier) && iocSeedArg(i));
  const shownReports = (reports || []).filter(r => !onlyUseful || useful(r).length);
  const picked = reports?.find(r => r.id === reportPick);
  const pickedIoc = picked?.iocs[iocPick];
  const loadReports = wrap('load reports', async () => {
    const list = await listThreatReports(cfg);
    setReports(list);
    const first = list.find(r => useful(r).length);
    setReportPick(first?.id || ''); setIocPick(0);
    log(`${list.length} threat report(s); ${list.filter(r => useful(r).length).length} with seedable discriminating/uncertain IOCs`);
  });
  const seedPicked = async () => {
    const arg = iocSeedArg(pickedIoc);
    if (!arg) throw new Error('That IOC type cannot be seeded (email / wallet).');
    await seedHuntIoc(cfg, arg, log);
  };
  const runPicked = async () => {
    if (!window.confirm(`Run Continuous Threat Hunt on "${picked.title}"? It re-hunts the report even if it was hunted before. Runs count toward workflow, Agent Builder and model-token billing.`)) return false;
    await runOne(HUNT, { reportIds: [picked.id] });
    log('Hunt: a hit or a detection gap appears under Proposed actions; Rule Coverage can turn gaps into proposals.');
    setReports(await listThreatReports(cfg));
    return true;
  };
  const seedIocOnly = wrap('seed report IOC', seedPicked);
  const huntOnly = wrap('hunt report', async () => { await runPicked(); });
  const seedAndHunt = wrap('seed + hunt', async () => { await seedPicked(); await new Promise(r => setTimeout(r, 4000)); await runPicked(); });
  const seedAll = wrap('seed all', async () => {
    const map = await createRules(cfg, log);
    await seedEvents(cfg, { noiseHosts, endpoint: endpointOpt(), victim }, log);
    await seedFalsePositives(cfg, { count: fpCount, ruleMap: map }, log);
  });
  const dry = wrap('reset (dry run)', async () => { await resetDemo(cfg, { dryRun: true }, log); });
  const wipe = wrap('reset', async () => {
    if (!window.confirm('Delete all AlertZero demo rules, demo data streams and tagged alerts from this project?')) return;
    await resetDemo(cfg, { dryRun: false }, log);
  });

  const runOne = async (w, inputs) => {
    const t0 = Date.now();
    log(`${w.name}: starting`);
    const id = await runWorker(cfg, w, inputs);
    log(`${w.name}: started${id ? ` (execution ${id})` : ''}`);
    let last = '';
    const ex = await waitForRun(cfg, w, id, { startedAfter: t0 - 5000 }, s => { if (s !== last) { last = s; log(`${w.name}: ${s}`); } });
    log(`${w.name}: finished — ${ex.status} (dispatch only: AI reviews run as child workflows and can take minutes; watch Proposed actions in Kibana)`);
    return ex;
  };
  const run = w => wrap(`run ${w.name}`, async () => {
    if (!window.confirm(`Run "${w.name}" now? Runs count toward workflow, Agent Builder and model-token billing.`)) return;
    await runOne(w);
  })();
  const runSeq = wrap('run sequence', async () => {
    if (!window.confirm('Run Alert Triage, Attack Discovery, Continuous Threat Hunt, Rule Tuning and Rule Coverage in order? This can take several minutes and counts toward workflow, Agent Builder and model-token billing.')) return;
    stop.current = false;
    for (const key of SEQUENCE) {
      if (stop.current) { log('sequence stopped'); break; }
      const ex = await runOne(WORKERS.find(w => w.key === key));
      if (ex.status !== 'completed') { log(`sequence halted: ${key} ended ${ex.status}`); break; }
    }
    log('Next: open Security → AlertZero → Proposed actions to review and approve. Approving the Attack Discovery handoff starts Endpoint Analysis.');
    setWorkers(await workerStatus(cfg));
  });

  if (!ready) return <div className="max-w-3xl mx-auto px-4 py-10 text-sm text-gray-400">Connect to a <b>Serverless (Security)</b> project first: both the Elasticsearch endpoint and the Kibana URL are required (Connect ES, top right).</div>;

  return (
    <div className="max-w-3xl mx-auto px-4 py-8 space-y-4">
      <div>
        <h1 className="text-lg font-bold text-white">AlertZero demo</h1>
        <p className="text-xs text-gray-500 mt-1">Seed data for all four Watches, then run the Workers on demand. Approving proposed actions stays a human step in Kibana.</p>
        {!isServerless(cfg) && <p className="text-xs text-amber-400 mt-2">⚠ This connection is not set to Serverless. AlertZero is a Security project feature (Preview); calls may fail.</p>}
      </div>

      <Card step="1" title="Seed demo data">
        <p className="text-[11px] text-gray-500">Creates 5 tagged custom rules (one deliberately noisy), a Defend-shaped attack chain plus benign noise, and closed false-positive alerts so Rule Tuning has input. Everything carries the <code>alertzero-demo</code> tag.</p>
        <div className="flex flex-wrap items-center gap-3 text-xs text-gray-400">
          <label className="flex items-center gap-2">Noise hosts <input type="number" min="0" max="500" value={noiseHosts} onChange={e => setNoiseHosts(+e.target.value)} className={inputCls + ' !w-20'} /></label>
          <label className="flex items-center gap-2">False-positive alerts <input type="number" min="0" max="500" value={fpCount} onChange={e => setFpCount(+e.target.value)} className={inputCls + ' !w-20'} /></label>
        </div>
        <div className="space-y-2 border border-gray-800 rounded-lg p-3">
          <p className="text-[11px] text-gray-400 font-medium">Endpoint for the attack chain</p>
          <div className="flex gap-2">
            {[['simulated', 'Simulated (generated agent)'], ['real', 'Real enrolled host']].map(([v, l]) => (
              <button key={v} onClick={() => setEpMode(v)} className={`flex-1 h-8 text-xs font-medium rounded-lg border transition-all ${epMode === v ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-800 border-gray-600 text-gray-400 hover:text-white'}`}>{l}</button>
            ))}
          </div>
          {epMode === 'simulated'
            ? <div className="space-y-2">
                <div className="flex gap-2 items-center text-xs text-gray-400">
                  <span>Victim host</span><input value={victim} onChange={e => setVictim(e.target.value.trim())} className={inputCls + ' flex-1'} />
                  <Btn onClick={freshVictim} disabled={!!busy}>New host</Btn>
                </div>
                <p className="text-[11px] text-gray-500">Use a new host name for each run: Attack Discovery attaches attacks on the same host to the existing open investigation, so there would be no new forensic handoff.</p>
                <p className="text-[11px] text-gray-500">Adds Defend-shaped <code>agent.id</code> / <code>host.id</code> so Endpoint Analysis proposes isolate / kill / suspend. The host is not enrolled, so approving a response action will not execute anything.</p>
              </div>
            : <>
                <div className="flex gap-2 items-center">
                  <Btn onClick={loadEps} disabled={!!busy}>Load enrolled endpoints</Btn>
                  <select value={epPick} onChange={e => setEpPick(e.target.value)} className={inputCls + ' flex-1'} disabled={!endpoints?.length}>
                    {!endpoints?.length && <option value="">— none loaded —</option>}
                    {endpoints?.map(e => <option key={e.agentId} value={e.agentId}>{e.name} · {e.os || 'os?'} · {e.status || 'status?'}</option>)}
                  </select>
                </div>
                <p className="text-[11px] text-amber-400">The attack chain is synthetic but is attributed to this real host. Approving a proposed isolate / kill / suspend would run for real on it. Use only a machine you own, and release it afterwards.</p>
              </>}
        </div>
        <div className="flex flex-wrap gap-2">
          <Btn onClick={seedAll} disabled={!!busy}>{busy === 'seed all' ? 'Seeding…' : 'Seed everything'}</Btn>
          <Btn onClick={rules} disabled={!!busy}>Rules only</Btn>
          <Btn onClick={events} disabled={!!busy}>Attack chain + noise only</Btn>
          <Btn onClick={fps} disabled={!!busy}>False positives only</Btn>
        </div>
      </Card>

      <Card step="2" title="Run Workers">
        <p className="text-[11px] text-gray-500">Workers already run on their own schedules; these buttons start them now through the Workflows API. Runs are billed (workflow executions, Agent Builder, model tokens). Endpoint Analysis starts when you approve the Attack Discovery handoff in Kibana, so it is not in the sequence.</p>
        <div className="flex flex-wrap gap-2">
          <Btn onClick={runSeq} disabled={!!busy}>{busy === 'run sequence' ? 'Running…' : 'Run sequence'}</Btn>
          {busy === 'run sequence' && <Btn tone="red" onClick={() => { stop.current = true; }}>Stop after current</Btn>}
          <Btn onClick={refresh} disabled={!!busy}>Refresh status</Btn>
        </div>
        <div className="divide-y divide-gray-800 border border-gray-800 rounded-lg">
          {WORKERS.map(w => {
            const s = workers?.find(x => x.key === w.key);
            return (
              <div key={w.key} className="flex items-center gap-3 px-3 py-2 text-xs">
                <span className="text-gray-500 w-16">{w.watch}</span>
                <span className="text-gray-200 flex-1">{w.name}</span>
                <span className={`w-40 truncate ${s?.found === false ? 'text-red-400' : STATUS_TONE[s?.last?.status] || 'text-gray-500'}`}>{!s ? '—' : s.found === false ? 'not found' : s.last ? `${s.last.status} · ${new Date(s.last.startedAt).toLocaleTimeString()}` : 'no runs'}</span>
                <Btn onClick={() => run(w)} disabled={!!busy || s?.found === false}>Run</Btn>
              </div>
            );
          })}
        </div>
      </Card>

      <Card step="3" title="Hunt on a threat report">
        <p className="text-[11px] text-gray-500">Continuous Threat Hunt hunts reports it builds itself from public feeds. A manual run that names a report forces it to be hunted again, even if it was hunted before. Pick a report and an IOC, seed a matching event, then run Hunt on that report.</p>
        <div className="flex flex-wrap items-center gap-3">
          <Btn onClick={loadReports} disabled={!!busy}>{busy === 'load reports' ? 'Loading…' : reports ? 'Reload reports' : 'Load threat reports'}</Btn>
          <label className="flex items-center gap-2 text-[11px] text-gray-400"><input type="checkbox" checked={onlyUseful} onChange={e => setOnlyUseful(e.target.checked)} />Only reports with discriminating / uncertain IOCs</label>
        </div>
        {reports && (
          <div className="max-h-56 overflow-auto divide-y divide-gray-800 border border-gray-800 rounded-lg">
            {!shownReports.length && <p className="px-3 py-2 text-xs text-gray-500">No matching reports.</p>}
            {shownReports.map(r => (
              <button key={r.id} onClick={() => { setReportPick(r.id); setIocPick(0); }} className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2 ${reportPick === r.id ? 'bg-blue-500/10' : 'hover:bg-gray-800/50'}`}>
                <span className="text-gray-500 w-12 shrink-0">{r.date.slice(5, 10)}</span>
                <span className={`w-14 shrink-0 ${SEV_TONE[r.severity] || 'text-gray-400'}`}>{r.severity}</span>
                <span className="flex-1 truncate text-gray-200" title={r.title}>{r.title}<span className="text-gray-500"> · {r.source}</span></span>
                <span className={`w-20 shrink-0 text-right ${HUNT_TONE[r.huntStatus] || 'text-gray-500'}`}>{r.huntStatus}</span>
                <span className="w-12 shrink-0 text-right text-gray-500">{useful(r).length} IOC</span>
              </button>
            ))}
          </div>
        )}
        {picked && (
          <div className="space-y-2 border border-gray-800 rounded-lg p-3">
            <p className="text-[11px] text-gray-400 break-all">{picked.id} · rank {picked.rank ?? '?'} · {picked.url}</p>
            <div className="max-h-40 overflow-auto space-y-1">
              {picked.iocs.map((i, n) => {
                const ok = !!iocSeedArg(i);
                return (
                  <label key={n} className={`flex items-center gap-2 text-[11px] font-mono ${ok ? 'text-gray-300' : 'text-gray-600'}`}>
                    <input type="radio" name="hunt-ioc" disabled={!ok} checked={iocPick === n} onChange={() => setIocPick(n)} />
                    <span className={`w-24 shrink-0 ${TIER_TONE[i.tier] || ''}`}>{i.tier}</span><span className="w-12 shrink-0">{i.type}</span><span className="truncate">{i.value}</span>
                  </label>
                );
              })}
              {!picked.iocs.length && <p className="text-[11px] text-gray-500">This report has no IOCs; you can still run Hunt on it.</p>}
            </div>
            {pickedIoc?.tier === 'uncertain' && pickedIoc.type === 'ip' && <p className="text-[11px] text-amber-400">Uncertain IPs are often version numbers misread from advisories (e.g. firmware 8.2.0.1). Prefer discriminating IOCs.</p>}
            {pickedIoc?.tier === 'reference' && <p className="text-[11px] text-amber-400">Reference IOCs are usually benign links (e.g. a vendor site); prefer discriminating or uncertain ones.</p>}
            <div className="flex flex-wrap gap-2">
              <Btn onClick={seedAndHunt} disabled={!!busy || !iocSeedArg(pickedIoc)}>{busy === 'seed + hunt' ? 'Running…' : 'Seed IOC + run Hunt'}</Btn>
              <Btn onClick={seedIocOnly} disabled={!!busy || !iocSeedArg(pickedIoc)}>Seed IOC only</Btn>
              <Btn onClick={huntOnly} disabled={!!busy}>Run Hunt on report</Btn>
            </div>
          </div>
        )}
        <details className="text-[11px] text-gray-500">
          <summary className="cursor-pointer">Seed an IOC manually</summary>
          <div className="grid grid-cols-3 gap-2 mt-2">
            {['domain', 'ip', 'sha256'].map(k => <input key={k} className={inputCls} placeholder={k} value={ioc[k]} onChange={e => setIoc({ ...ioc, [k]: e.target.value.trim() })} />)}
          </div>
          <div className="mt-2"><Btn onClick={hunt} disabled={!!busy || !(ioc.domain || ioc.ip || ioc.sha256)}>Seed IOC event</Btn></div>
        </details>
      </Card>

      <Card step="4" title="Reset">
        <p className="text-[11px] text-gray-500">Removes only what carries the <code>alertzero-demo</code> tag: rules, demo data streams and tagged alerts. Real Defend data is untouched.</p>
        <div className="flex gap-2"><Btn onClick={dry} disabled={!!busy}>Dry run</Btn><Btn tone="red" onClick={wipe} disabled={!!busy}>Reset…</Btn></div>
      </Card>

      <div className="bg-black/40 border border-gray-800 rounded-xl p-3 font-mono text-[11px] text-gray-300 min-h-[96px] max-h-72 overflow-auto whitespace-pre-wrap">
        {lines.length ? lines.join('\n') : <span className="text-gray-600">Activity log</span>}
      </div>
    </div>
  );
}
