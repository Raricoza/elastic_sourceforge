// ─── Elastic Config ───────────────────────────────────────────────────────────
export const STORAGE_KEY='elastic_config_forge';
export function loadConfig(){try{return JSON.parse(localStorage.getItem(STORAGE_KEY)||'null');}catch{return null;}}
export function saveConfig(c){localStorage.setItem(STORAGE_KEY,JSON.stringify(c));}
// cfg.deployment: 'hosted' (Elastic Cloud Hosted / self-managed, default) | 'serverless'
export const isServerless=cfg=>cfg?.deployment==='serverless';
// Serverless only supports API keys; the versioned Kibana APIs also expect this header.
export const KIBANA_API_VERSION='2023-10-31';
export function buildHeaders(cfg){
  const auth=cfg.authMode==='basic'&&!isServerless(cfg)
    ?`Basic ${btoa(`${cfg.username||''}:${cfg.password||''}`)}`
    :`ApiKey ${cfg.apiKey||''}`;
  return{'Content-Type':'application/x-ndjson','Authorization':auth};
}
export function curlAuthFlag(cfg){
  return cfg.authMode==='basic'&&!isServerless(cfg)
    ?`-u "${cfg.username}:${cfg.password}"`
    :`-H "Authorization: ApiKey ${cfg.apiKey}"`;
}
// Route all ES requests through the Vite dev-server proxy (/es-proxy) so the
// browser never makes a cross-origin request — eliminates CORS failures and
// allows self-signed certificates on local clusters.
export function fetchES(cfg,path,opts={}){
  const headers={...buildHeaders(cfg),'X-ES-URL':cfg.url.replace(/\/$/,'')};
  return fetch(`/es-proxy${path}`,{...opts,headers:{...headers,...(opts.headers||{})}});
}
export function fetchKibana(cfg,path,opts={}){
  const base=(cfg.kibanaUrl||'').replace(/\/$/,'');
  const headers={...buildHeaders(cfg),'Content-Type':'application/json','kbn-xsrf':'true','X-Kibana-URL':base,...(isServerless(cfg)?{'elastic-api-version':KIBANA_API_VERSION}:{})};
  return fetch(`/kibana-proxy${path}`,{...opts,headers:{...headers,...(opts.headers||{})}});
}
