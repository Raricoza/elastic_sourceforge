import { useState, useRef } from 'react';
import { isServerless } from './elastic.js';
import { WORKERS, SEQUENCE, createRules, listEndpoints, seedEvents, seedFalsePositives, seedHuntIoc, resetDemo, workerStatus, runWorker, waitForRun } from './alertzero.js';

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
const STATUS_TONE = { completed: 'text-green-400', failed: 'text-red-400', running: 'text-blue-400', pending: 'text-gray-400' };

export default function AlertZeroPage({ elasticConfig: cfg }) {
  const [busy, setBusy] = useState('');
  const [lines, setLines] = useState([]);
  const [workers, setWorkers] = useState(null);
  // Rule Tuning needs the false-positive rate well above its 50% threshold: the noisy rule also raises ~1 open alert per noise host.
  const [fpCount, setFpCount] = useState(90);
  const [noiseHosts, setNoiseHosts] = useState(30);
  const [ioc, setIoc] = useState({ domain: '', ip: '', sha256: '' });
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

  const runOne = async w => {
    const t0 = Date.now();
    log(`${w.name}: starting`);
    const id = await runWorker(cfg, w);
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

      <Card step="3" title="Hunt IOC (after the first Continuous Threat Hunt run)">
        <p className="text-[11px] text-gray-500">Hunt builds its own threat reports. Open one, pick an IOC no rule covers, seed a matching event here, then run Continuous Threat Hunt again.</p>
        <div className="grid grid-cols-3 gap-2">
          {['domain', 'ip', 'sha256'].map(k => <input key={k} className={inputCls} placeholder={k} value={ioc[k]} onChange={e => setIoc({ ...ioc, [k]: e.target.value.trim() })} />)}
        </div>
        <Btn onClick={hunt} disabled={!!busy || !(ioc.domain || ioc.ip || ioc.sha256)}>Seed IOC event</Btn>
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
