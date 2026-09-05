
const demoEmail=`From: "PayPal Security" <support@paypa1-security.com>
To: analyst@company.com
Reply-To: account@fake-domain.example
Return-Path: <mailer@relay.example>
Subject: Urgent: Verify Your Account
Date: Thu, 03 Sep 2026 09:31:02 +0530
Message-ID: <9f8a-demo-c31@example>
Received: from relay.example (185.91.24.17) by recipient.example;
Authentication-Results: spf=fail; dkim=none; dmarc=fail
X-Originating-IP: 185.91.24.17
MIME-Version: 1.0
Content-Type: text/html

URGENT: Your account will be suspended today. Verify your password immediately at https://paypa1-login.example/verify`;

let cases=[
{id:"TM-2026-00142",sender:"support@paypa1-security.com",subject:"Urgent: Verify Your Account",threat:"Credential Phishing",score:96,loc:"Singapore",status:"ACTIVE",indicators:8,community:"PayPal Security",raw:demoEmail},
{id:"TM-2026-00143",sender:"alerts@paypa1-security.com",subject:"Final Notice: Account Verification Required",threat:"Credential Phishing",score:94,loc:"Singapore",status:"ACTIVE",indicators:7,community:"PayPal Security",raw:"From: PayPal Security <alerts@paypa1-security.com>\nTo: analyst@company.com\nReply-To: account@fake-domain.example\nSubject: Final Notice: Account Verification Required\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail\nReceived: from relay.example (185.91.24.17)\n\nYour account requires immediate verification. Sign in now at https://paypa1-login.example/verify"},
{id:"TM-2026-00139",sender:"security@microsoft-login.co",subject:"Microsoft 365 Password Expiration Notice",threat:"Credential Theft",score:91,loc:"Netherlands",status:"CONTAINED",indicators:7,community:"Microsoft 365",raw:"From: Microsoft Security <security@microsoft-login.co>\nTo: analyst@company.com\nReply-To: login@fake-m365.example\nSubject: Microsoft 365 Password Expiration Notice\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail\nReceived: from 45.81.11.8\n\nYour password expires today. Sign in now."},
{id:"TM-2026-00135",sender:"accounts@vendor-example.com",subject:"Invoice Attached — Payment Required",threat:"Malicious Attachment",score:88,loc:"United States",status:"REVIEW",indicators:5,community:"Vendor Billing",raw:"From: accounts@vendor-example.com\nTo: analyst@company.com\nSubject: Invoice Attached — Payment Required\nReceived: from 104.21.44.9\n\nInvoice attached."},
{id:"TM-2026-00128",sender:"updates@newsletter-example.com",subject:"September Product Updates",threat:"Suspicious",score:62,loc:"United Kingdom",status:"REVIEW",indicators:2,community:"Product Newsletter",raw:"From: updates@newsletter-example.com\nTo: analyst@company.com\nSubject: September Product Updates\nReceived: from 198.51.100.24\n\nHere are the latest product updates and links."},
{id:"TM-2026-00131",sender:"hr@company.com",subject:"Updated employee benefits",threat:"Safe",score:8,loc:"India",status:"ALLOWED",indicators:0,community:"Internal HR",raw:"From: hr@company.com\nTo: analyst@company.com\nSubject: Updated employee benefits\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\n\nPlease review the updated benefits."}
];
let watch=[
{v:"fake-domain.example",type:"Domain",matches:4,status:"MATCH FOUND"},
{v:"185.91.24.17",type:"IP",matches:3,status:"WATCHING"},
{v:"paypa1-login.example",type:"URL",matches:2,status:"WATCHING"}
];
let reports=[{name:"TM-2026-00142 Forensic Report",id:"TM-2026-00142",date:"Just now"}];

function $(id){return document.getElementById(id)}
function go(id){
  const page=document.getElementById(id);
  if(!page){toast("Page unavailable");return false}
  try{if(id!=="map" && typeof tmCloseGeo==="function")tmCloseGeo()}catch(e){}
  document.querySelectorAll(".page").forEach(x=>x.classList.remove("active"));
  page.classList.add("active");
  document.querySelectorAll(".nav button").forEach(x=>x.classList.toggle("on",x.dataset.page===id));
  if(id==="inbox")renderInbox();
  if(id==="dashboard")renderRecent();
  if(id==="awareness")renderAwarenessPage();
  window.scrollTo(0,0);
  return false;
}
document.querySelectorAll(".nav button").forEach(b=>{b.type="button";b.addEventListener("click",function(e){e.preventDefault();e.stopPropagation();go(this.dataset.page);});});
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function sev(n){return n>=93?"critical":n>=80?"high":n>=50?"medium":"safe"}
function renderRecent(){ $("recentBody").innerHTML=cases.slice(0,4).map(c=>`<tr class="click" onclick="openCase('${c.id}')"><td class="mono">${c.id}</td><td>${esc(c.subject)}</td><td><span class="badge ${sev(c.score)}">${esc(c.threat.toUpperCase())}</span></td><td><b>${c.score}</b></td><td>${c.loc}</td><td>${c.status}</td></tr>`).join("")}
function senderCommunity(c){
  return c.community || ((c.sender||"").split("@")[1] || "Unknown community").toLowerCase();
}
function isHarmful(c){
  return c.score>=80 && !/^(safe|likely safe)$/i.test(c.threat||"");
}
function canReportToSpam(c){
  const community=senderCommunity(c);
  const repeated=cases.filter(x=>senderCommunity(x)===community).length>=2;
  return c.score>=93 && isHarmful(c) && repeated;
}
function reportToSpam(id){
  const c=cases.find(x=>x.id===id);
  if(!c || !canReportToSpam(c)){toast("Report to Spam is available only for repeated, very-high-risk harmful mail");return}
  c.status="SPAM";
  renderInbox();
  renderRecent();
  toast("Reported to Spam — removed from Inbox (demo)");
}
function renderInbox(){
  let q=($("inboxSearch")?.value||"").toLowerCase();
  $("inboxBody").innerHTML=cases.filter(c=>c.status!=="SPAM" && (c.sender+c.subject+c.threat+c.loc).toLowerCase().includes(q)).map(c=>{
    const spamAction=canReportToSpam(c)?`<button class="btn danger" title="Repeated from the same sender community and classified as very-high-risk harmful mail" onclick="event.stopPropagation();reportToSpam('${c.id}')">Report to Spam</button>`:"";
    return `<tr class="click" onclick="openCase('${c.id}')"><td>${esc(c.sender)}</td><td>${esc(c.subject)}</td><td><span class="badge ${sev(c.score)}">${esc(c.threat.toUpperCase())}</span></td><td><b>${c.score}/100</b></td><td>${c.loc}</td><td><button class="btn" onclick="event.stopPropagation();openCase('${c.id}')">Investigate</button>${spamAction}</td></tr>`;
  }).join("")
}
function getReportCase(){return window.currentCase || cases[0] || null}
function renderReports(){
 const c=getReportCase(), el=$("fullReport");
 if(!el)return;
 if(!c){el.innerHTML=`<div class="empty"><h3>No forensic investigation available</h3><p class="muted">Complete an investigation first. The report will be populated from the preserved evidence.</p></div>`;return;}
 const ex=extract(c.raw||""); const h=ex.p.h||{}; const auth=(h["authentication-results"]||"UNKNOWN");
 const urls=ex.urls.length?ex.urls.map(x=>`<div class="find"><span>URL</span><b class="mono">${esc(x)}</b><i class="source obs">OBSERVED</i></div>`).join(""):`<div class="find"><span>URLs</span><b>NONE OBSERVED</b></div>`;
 const ips=ex.ips.length?ex.ips.map(x=>`<div class="find"><span>IP</span><b class="mono">${esc(x)}</b><i class="source obs">OBSERVED</i></div>`).join(""):`<div class="find"><span>IP</span><b>UNKNOWN</b></div>`;
 const domains=ex.domains.length?ex.domains.slice(0,8).map(x=>`<div class="find"><span>Domain</span><b class="mono">${esc(x)}</b><i class="source obs">OBSERVED</i></div>`).join(""):`<div class="find"><span>Domains</span><b>NONE OBSERVED</b></div>`;
 const reasons=(window.lastAnalysis&&window.lastAnalysis.reasons)||[];
 el.innerHTML=`<div class="sectionHead"><div><div class="ey">TRACE MAIL AI · FORENSIC CASE</div><h2>${esc(c.id)} · ${esc(c.subject)}</h2><div class="sub">Generated ${esc(c.createdAt?new Date(c.createdAt).toLocaleString():"Available evidence")}</div></div><span class="badge ${sev(c.score)}">${esc(c.threat.toUpperCase())} · ${c.score}/100</span></div>
 <div class="three" style="margin-top:14px"><div class="card"><div class="ey">CLASSIFICATION</div><h3>${esc(c.threat)}</h3><div class="muted small">Explainable risk score: ${c.score}/100</div></div><div class="card"><div class="ey">SENDER</div><h3 class="mono" style="font-size:14px">${esc(c.sender)}</h3><div class="muted small">OBSERVED from message headers</div></div><div class="card"><div class="ey">INFRASTRUCTURE</div><h3>${esc(c.loc||"UNKNOWN")}</h3><div class="muted small">Observed infrastructure geolocation · confidence ${c.geoConfidence==null?"UNKNOWN":c.geoConfidence+"%"}</div></div></div>
 <div class="two section"><div><h3>1 · Executive Finding</h3><p class="muted">This email is classified as <b>${esc(c.threat)}</b> with a risk score of <b>${c.score}/100</b>. The assessment is based on preserved email evidence and explainable forensic signals.</p><div class="find"><span>Evidence confidence</span><b>EVIDENCE-GROUNDED</b></div><div class="find"><span>Attacker physical location</span><b>UNKNOWN</b></div><div class="find"><span>User interaction</span><b>UNKNOWN / NOT OBSERVED</b></div></div><div><h3>2 · Authentication Evidence</h3><pre class="mono" style="white-space:pre-wrap;color:#294153;background:#f7fafc;border:1px solid #dbe3ea;padding:12px;border-radius:8px">${esc(auth)}</pre></div></div>
 <div class="two section"><div><h3>3 · Message Headers</h3><div class="find"><span>From</span><b>${esc(h.from||c.sender||"UNKNOWN")}</b></div><div class="find"><span>Reply-To</span><b>${esc(h["reply-to"]||"UNKNOWN")}</b></div><div class="find"><span>Return-Path</span><b>${esc(h["return-path"]||"UNKNOWN")}</b></div><div class="find"><span>Message-ID</span><b>${esc(h["message-id"]||"UNKNOWN")}</b></div><div class="find"><span>Date</span><b>${esc(h.date||"UNKNOWN")}</b></div></div><div><h3>4 · Indicators of Compromise</h3>${ips}${domains}${urls}</div></div>
 <div class="section"><h3>5 · Why This Email Is Suspicious</h3>${reasons.length?reasons.map(r=>`<div class="find"><span>${esc(r[0])}</span><b><span class="badge ${r[1]==="Observed"?"obs":"inf"}">${esc(r[1])}</span></b></div>`).join(""):`<div class="find"><span>Analysis signals</span><b>See investigation evidence</b></div>`}</div>
 <div class="section"><h3>6 · Infrastructure & Geo Location</h3><div class="find"><span>Observed infrastructure location</span><b>${esc(c.loc||"UNKNOWN")}</b></div><div class="find"><span>Geo confidence</span><b>${c.geoConfidence==null?"UNKNOWN":c.geoConfidence+"%"}</b></div><p class="small muted">IP geolocation identifies observable infrastructure, which may be a VPN, proxy, cloud service, relay, mail server or compromised host. It does not establish the attacker's physical location.</p></div>
 <div class="section"><h3>7 · Forensic Evidence Integrity</h3><div class="find"><span>Raw email preserved</span><b>YES</b></div><div class="find"><span>Evidence handling</span><b>Original content retained as untrusted evidence</b></div><div class="find"><span>External response</span><b>Human authorization required</b></div></div>
 <div class="authorize">REPORT STATUS · Evidence-backed forensic summary. OBSERVED, ENRICHED, INFERRED and UNKNOWN values are kept distinct. No unsupported attacker-location claim is made.</div>`;
}

function openCase(id){let c=cases.find(x=>x.id===id);if(!c)return;window.currentCase=c;renderInvestigation(c);setTimeout(markSensitive,0)}
function renderInvestigation(c){const ex=extract(c.raw||"");const h=ex.p.h;const ip=ex.ips[0]||"UNKNOWN";const reply=h["reply-to"]||"UNKNOWN";const geo=(c.geoConfidence==null?"UNKNOWN":String(c.geoConfidence)+"%");$("modalTitle").textContent=`${c.id} · ${c.subject}`;$("modalBody").innerHTML=`
<div class="rolePanel"><b>🔐 Access-controlled investigation</b><div class="rbacNote">Role determines whether sensitive IOCs, infrastructure and response controls are visible.</div></div><div class="two"><div class="card"><div class="sectionHead"><h3>Risk Assessment</h3><span class="badge ${sev(c.score)}">${c.threat.toUpperCase()}</span></div><div class="risk"><div class="ring" style="background:conic-gradient(var(--red) 0 ${c.score}%,#24323b ${c.score}%)"><b>${c.score}</b></div><div style="flex:1"><div class="find"><span>Sender identity</span><b>18/20</b></div><div class="find"><span>Authentication</span><b>20/20</b></div><div class="find"><span>URL</span><b>18/20</b></div><div class="find"><span>Domain</span><b>14/15</b></div></div></div></div>
<div class="card"><h3>Why?</h3><div class="find"><span>SPF</span><b class="red">FAIL</b></div><div class="find"><span>Reply-To</span><b class="red">MISMATCH</b></div><div class="find"><span>Domain</span><b class="red">LOOKALIKE</b></div><div class="find"><span>URL</span><b class="amber">SUSPICIOUS</b></div><div class="find"><span>Language</span><b class="amber">URGENCY</b></div></div></div>
<div class="card section"><div class="tabs"><button class="tab on" onclick="switchModalTab(this,'mOverview')">Overview</button><button class="tab" onclick="switchModalTab(this,'mHeaders')">Headers</button><button class="tab" onclick="switchModalTab(this,'mGraph')">Attack Graph</button><button class="tab" onclick="switchModalTab(this,'mTimeline')">Timeline</button></div>
<div id="mOverview" class="tabbody on"><div class="two"><div><div class="kv"><span>From</span><b>${esc(c.sender)} <i class="source obs">OBSERVED</i></b></div><div class="kv"><span>Reply-To</span><b>${esc(reply)} <i class="source obs">OBSERVED</i></b></div><div class="kv"><span>IP</span><b class="mono">${esc(ip)} <i class="source obs">OBSERVED</i></b></div></div><div><div class="kv"><span>Infrastructure</span><b>${esc(c.loc||"UNKNOWN")} <i class="source enr">ENRICHED</i></b></div><div class="kv"><span>Geo confidence</span><b>${esc(geo)}</b></div><div class="kv"><span>Physical attacker</span><b>UNKNOWN</b></div></div></div></div>
<div id="mHeaders" class="tabbody"><pre class="mono" style="white-space:pre-wrap;color:#294153;background:#f7fafc;border:1px solid #dbe3ea;padding:12px;border-radius:8px">${esc(c.raw)}</pre></div>
<div id="mGraph" class="tabbody"><div class="graph"><div class="node n1"><b>EMAIL</b><small>Observed</small></div><div class="node n2"><b>SENDER</b><small>${esc(c.sender.split("@")[1]||"domain")}</small></div><div class="node n3"><b>IP</b><small>${esc(ip)}</small></div><div class="node n4"><b>ASN</b><small>ASXXXXX</small></div><div class="node n5"><b>DOMAIN</b><small>fake-domain.example</small></div><div class="node n6"><b>URL</b><small>login.example</small></div><i class="edge e1"></i><i class="edge e2"></i><i class="edge e3"></i><i class="edge e4"></i><i class="edge e5"></i></div></div>
<div id="mTimeline" class="tabbody"><div class="timeline"><div class="event"><b>09:31:02</b><br>Email timestamp <span class="badge obs">OBSERVED</span></div><div class="event"><b>09:31:04</b><br>Mail server received message</div><div class="event"><b>09:31:06</b><br>Relay detected</div><div class="event"><b>UNKNOWN</b><br>User interaction <span class="badge unknown">NOT OBSERVED</span></div></div></div></div>
<div class="section three"><div class="card"><h3 style="font-size:13px">What we know</h3><p>Header anomalies and suspicious link indicators are observed.</p></div><div class="card"><h3 style="font-size:13px">What we infer</h3><p>Credential phishing is the most likely interpretation.</p></div><div class="card"><h3 style="font-size:13px">What we don't know</h3><p>Physical attacker location, clicks and credential theft.</p></div></div>
<div class="response-grid">
 <div class="response-card"><b>🔒 Quarantine</b><small>Contain the message after analyst approval.</small></div>
 <div class="response-card"><b>🚫 Block IOC</b><small>Block confirmed domain, URL or IP in connected controls.</small></div>
 <div class="response-card"><b>🔎 Hunt Organization</b><small>Search matching indicators across the monitored mailbox.</small></div>
</div><div class="authorize">⚠ HUMAN AUTHORIZATION REQUIRED · TraceMail recommends actions but does not silently execute destructive changes.</div>
<div class="actions section"><button class="btn danger" onclick="authorizeAction('Quarantine')">Quarantine</button><button class="btn" onclick="addWatchFromCase()">Add IOC to Watchlist</button><button class="btn primary" onclick="downloadReport()">Generate Report</button></div>`;$("modal").classList.add("show")}
function showForensicReportInInvestigation(){
  const c=window.currentCase||cases[0];
  if(!c){toast("No investigation available yet");return}
  const el=$("investigationReport");
  if(!el)return;
  const ex=extract(c.raw||"");
  const h=ex.p.h||{};
  const auth=h["authentication-results"]||"UNKNOWN";
  const reasons=(window.lastAnalysis&&window.lastAnalysis.reasons)||[];
  const ips=ex.ips.length?ex.ips.map(x=>`<div class="find"><span>IP</span><b class="mono">${esc(x)}</b><i class="source obs">OBSERVED</i></div>`).join(""):"<div class=\"find\"><span>IP</span><b>UNKNOWN</b></div>";
  const domains=ex.domains.slice(0,8).map(x=>`<div class="find"><span>Domain</span><b class="mono">${esc(x)}</b><i class="source obs">OBSERVED</i></div>`).join("");
  const urls=ex.urls.map(x=>`<div class="find"><span>URL</span><b class="mono">${esc(x)}</b><i class="source obs">OBSERVED</i></div>`).join("");
  const reasonHtml=reasons.length?reasons.map(r=>`<div class="find"><span>${esc(r[0])}</span><b>${esc(r[1])}</b></div>`).join(""):"<div class=\"find\"><span>Analysis signals</span><b>See investigation evidence</b></div>";
  el.style.display="block";
  el.innerHTML=`<div class="sectionHead"><div><div class="ey">TRACEMAIL AI · FORENSIC REPORT</div><h2>${esc(c.id)} · ${esc(c.subject)}</h2><div class="sub">Complete evidence-backed report generated from this investigation.</div></div><div class="actions"><button class="btn" onclick="viewForensicPDF()">Open PDF</button><button class="btn primary" onclick="downloadReport()">Export PDF</button></div></div>
  <div class="three" style="margin-top:14px"><div class="card"><div class="ey">THREAT</div><h3>${esc(c.threat)}</h3><div class="muted small">Risk score ${c.score}/100</div></div><div class="card"><div class="ey">SENDER</div><h3 class="mono" style="font-size:13px">${esc(c.sender)}</h3><div class="muted small">OBSERVED</div></div><div class="card"><div class="ey">GEO LOCATION</div><h3>${esc(c.loc||"UNKNOWN")}</h3><div class="muted small">Observed infrastructure · confidence ${c.geoConfidence==null?"UNKNOWN":c.geoConfidence+"%"}</div></div></div>
  <div class="two section"><div><h3>Executive Finding</h3><p class="muted">The message is classified as <b>${esc(c.threat)}</b> with a risk score of <b>${c.score}/100</b>, based on preserved email evidence and explainable forensic signals.</p><div class="find"><span>Attacker physical location</span><b>UNKNOWN</b></div><div class="find"><span>User interaction</span><b>UNKNOWN / NOT OBSERVED</b></div></div><div><h3>Authentication Evidence</h3><pre class="mono" style="white-space:pre-wrap;color:#294153;background:#f7fafc;border:1px solid #dbe3ea;padding:12px;border-radius:8px">${esc(auth)}</pre></div></div>
  <div class="two section"><div><h3>Message Headers</h3><div class="find"><span>From</span><b>${esc(h.from||c.sender||"UNKNOWN")}</b></div><div class="find"><span>Reply-To</span><b>${esc(h["reply-to"]||"UNKNOWN")}</b></div><div class="find"><span>Return-Path</span><b>${esc(h["return-path"]||"UNKNOWN")}</b></div><div class="find"><span>Message-ID</span><b>${esc(h["message-id"]||"UNKNOWN")}</b></div><div class="find"><span>Date</span><b>${esc(h.date||"UNKNOWN")}</b></div></div><div><h3>Indicators of Compromise</h3>${ips}${domains}${urls}</div></div>
  <div class="section"><h3>Why This Email Is Suspicious</h3>${reasonHtml}</div><div class="authorize">Evidence types remain separated as OBSERVED, ENRICHED, INFERRED and UNKNOWN. IP geolocation identifies observable infrastructure and does not establish the attacker's physical location.</div>`;
  el.scrollIntoView({behavior:"smooth",block:"start"});
}
function switchModalTab(btn,id){document.querySelectorAll(".modalBox .tab").forEach(x=>x.classList.remove("on"));document.querySelectorAll(".modalBox .tabbody").forEach(x=>x.classList.remove("on"));btn.classList.add("on");$(id).classList.add("on")}
function closeModal(){$("modal").classList.remove("show")}
$("modal").addEventListener("click",e=>{if(e.target.id==="modal")closeModal()});
function loadDemo(){$("raw").value=demoEmail;toast("Demo email loaded")}
document.getElementById("investigationEml")?.addEventListener("change",async e=>{const f=e.target.files?.[0];if(!f)return;if(!/\.eml$/i.test(f.name)){toast("Please select a valid .eml file");return}try{$("raw").value=await f.text();$("currentEvidenceLabel").textContent=f.name+" · local email evidence";toast("EML loaded locally — ready for analysis")}catch(err){toast("Unable to read the EML file")}});

function parseEmail(raw){let lines=raw.replace(/\r/g,"").split("\n"),h={},bodyStart=0;for(let i=0;i<lines.length;i++){if(lines[i].trim()===""){bodyStart=i+1;break}let m=lines[i].match(/^([^:]+):\s*(.*)$/);if(m)h[m[1].toLowerCase()]=(h[m[1].toLowerCase()]?h[m[1].toLowerCase()]+" ":"")+m[2]}return {h,body:lines.slice(bodyStart).join("\n")}}
function extract(raw){let p=parseEmail(raw),h=p.h;let ips=[...new Set((raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[]))];let urls=[...new Set((raw.match(/https?:\/\/[^\s"'<>]+/gi)||[]))];let domains=[...new Set((raw.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi)||[]))];return {p,ips,urls,domains,raw}}
function scoreEmail(x){let h=x.p.h,score=5,reasons=[];let auth=(h["authentication-results"]||"").toLowerCase();if(auth.includes("spf=fail")){score+=22;reasons.push(["SPF authentication failed","Observed"])}if(auth.includes("dkim=none")||auth.includes("dkim=fail")){score+=15;reasons.push(["DKIM missing or failed","Observed"])}if(auth.includes("dmarc=fail")){score+=15;reasons.push(["DMARC failed","Observed"])}let from=h["from"]||"",reply=h["reply-to"]||"";if(reply&&from&&reply.split("@")[1]!==from.split("@")[1]){score+=16;reasons.push(["Reply-To domain differs from sender domain","Observed"])}if(x.urls.length){score+=15;reasons.push(["URL detected in message","Observed"])}if(/urgent|suspend|verify|password|payment|immediately|expires|account/i.test(x.p.body)){score+=12;reasons.push(["Urgency or credential/financial pressure detected","Inferred"])}if(/paypa1|micros0ft|microsoft-login|secure-login|verify-account/i.test(from+x.urls.join(" "))){score+=10;reasons.push(["Possible lookalike/brand impersonation pattern","Inferred"])}score=Math.min(99,score);let threat=score>=80?"High Risk":score>=50?"Suspicious":"Likely Safe";if(/invoice|attachment/i.test(h["subject"]||"")&&score>=60)threat="Malicious Attachment";return {score,threat,reasons,x}}
function loadSelectedCase(){const c=window.currentCase||cases[0];if(!c){toast("No investigation is available");return}window.currentCase=c;$("raw").value=c.raw||"";$("currentEvidenceLabel").textContent=c.id+" · "+c.subject;toast("Investigation evidence loaded")}
function analyzeInput(){let raw=$("raw").value.trim();if(!raw){toast("Paste an email or load a demo first");return}let stages=["Evidence acquisition","Header forensics","IOC extraction","AI threat analysis","Threat cause & awareness model","Infrastructure enrichment","Risk calculation","Attack-chain reconstruction"];$("analysisStatus").textContent="ANALYZING";$("pipeline").innerHTML=stages.map((s,i)=>`<div style="margin:12px 0"><div class="find"><span>${i+1}. ${s}</span><b id="st${i}">QUEUED</b></div><div class="progress"><i id="pr${i}"></i></div></div>`).join("");let i=0;let timer=setInterval(()=>{if(i>0){$("st"+(i-1)).textContent="COMPLETE";$("pr"+(i-1)).style.width="100%"}if(i<stages.length){$("st"+i).textContent="RUNNING";$("pr"+i).style.width="55%";i++}else{clearInterval(timer);$("analysisStatus").textContent="COMPLETE";let result=scoreEmail(extract(raw)); localStorage.setItem("tmLastAnalysis",JSON.stringify(result)); showNewResult(result);}},420)}
function awarenessFor(r){
 let t=(r.threat||'').toLowerCase();
 if(t.includes('attachment')) return {problem:'Malicious attachment / payload delivery',why:'Attackers disguise executable or weaponized files as invoices, documents or routine attachments to get the victim to open them.',method:'Social engineering creates urgency or trust around the attachment; the malicious file can then attempt code execution or credential theft.',watch:'Unexpected attachments, unusual file types, requests to enable macros/scripts, password-protected archives, and urgent requests from unknown senders.',learn:'Verify the sender through a separate channel and avoid opening unexpected attachments. Treat file type and context as evidence, not proof of safety.'};
 if(t.includes('phish')||t.includes('credential')||t.includes('high risk')) return {problem:'Credential phishing / account impersonation',why:'Attackers imitate a trusted brand or person and create urgency so the user gives credentials, OTPs or sensitive information to a fake destination.',method:'Lookalike domains, Reply-To manipulation, authentication failures and convincing language are combined to bypass human trust.',watch:'Urgent verification requests, mismatched sender/Reply-To domains, lookalike spellings, unexpected login links and requests for passwords or OTPs.',learn:'Never use links from unexpected security emails to sign in. Open the official site/app directly and verify unusual requests independently.'};
 return {problem:'Suspicious email activity',why:'Attackers can exploit trust, urgency, impersonation or unsafe links to influence users into taking risky actions.',method:'Multiple weak signals are combined; a single signal alone may be harmless, but their combination can indicate malicious intent.',watch:'Unexpected requests, sender inconsistencies, suspicious URLs, unusual authentication results and pressure to act quickly.',learn:'Pause before acting, verify the sender independently, and report suspicious messages instead of interacting with them.'};
}
function renderAwarenessPage(){
  const el=$("awarenessPageContent"); if(!el)return;
  let r=null; try{r=JSON.parse(localStorage.getItem("tmLastAnalysis")||"null")}catch(e){}
  if(!r){r=scoreEmail(extract(demoEmail));}
  const a=awarenessFor(r);
  el.innerHTML=`<div class="card awareness"><div class="sectionHead"><h2>Why did this problem occur?</h2><span class="badge ${sev(r.score)}">${esc(r.threat.toUpperCase())}</span></div>
  <div class="awGrid">
   <div class="awBox"><b>1 · What is the problem?</b><p>${esc(a.problem)}</p></div>
   <div class="awBox"><b>2 · Why does it occur?</b><p>${esc(a.why)}</p></div>
   <div class="awBox"><b>3 · How does the attack work?</b><p>${esc(a.method)}</p></div>
   <div class="awBox"><b>4 · What should you watch for?</b><p>${esc(a.watch)}</p></div>
  </div><div class="awLearn"><b>🛡 Future Awareness:</b> ${esc(a.learn)}</div></div>
  <div class="three section">
   <div class="card"><div class="ey">THREAT</div><h3>${esc(r.threat)}</h3><div class="muted small">Risk score: ${r.score}/100</div></div>
   <div class="card"><div class="ey">EVIDENCE</div><h3>${r.reasons.length}</h3><div class="muted small">signals supporting the assessment</div></div>
   <div class="card"><div class="ey">PURPOSE</div><h3>Prevent recurrence</h3><div class="muted small">Turn investigation findings into user awareness</div></div>
  </div>`;
}
function showNewResult(r){window.lastAnalysis=r;let sender=(r.x.p.h["from"]||"unknown").replace(/^.*</,"").replace(">","");let subject=r.x.p.h.subject||"Untitled";$("newResult").className="";$("newResult").innerHTML=`<div class="card"><div class="sectionHead"><h2>Investigation Complete</h2><span class="badge ${sev(r.score)}">${r.threat.toUpperCase()}</span></div><div class="risk"><div class="ring" style="background:conic-gradient(var(--red) 0 ${r.score}%,#24323b ${r.score}%)"><b>${r.score}</b></div><div><div class="ey">EXPLAINABLE RISK SCORE</div><h3>${esc(subject)}</h3><div class="muted">${esc(sender)}</div><div class="small muted" style="margin-top:7px">Evidence → Analysis → Intelligence → Action</div></div></div></div><div class="two"><div class="card section"><h3 style="font-size:13px">Why is it dangerous?</h3>${r.reasons.slice(0,4).map(z=>`<div class="find"><span>${esc(z[0])}</span><b><span class="badge ${z[1]==="Observed"?"obs":"inf"}">${z[1]}</span></b></div>`).join("")}</div><div class="card section"><h3 style="font-size:13px">Extracted IOCs</h3><div class="find"><span>IP</span><b>${r.x.ips.length?r.x.ips[0]:"None"}</b></div><div class="find"><span>Domain</span><b>${r.x.domains.length?esc(r.x.domains[0]):"None"}</b></div><div class="find"><span>URL</span><b>${r.x.urls.length?esc(r.x.urls[0]):"None"}</b></div></div></div><div class="card section awareness"><div class="sectionHead"><h3 style="font-size:13px">🧠 Threat Cause & Awareness Model</h3><span class="modelTag">USER AWARENESS</span></div><div id="awarenessContent"></div></div><div class="card section"><div class="sectionHead"><h3 style="font-size:13px">Investigation Intelligence</h3><span class="badge inf">INFERRED</span></div><div class="three"><div class="card"><b>Attack DNA</b><div class="muted small">Campaign fingerprint</div></div><div class="card"><b>Mutation</b><div class="muted small">Infrastructure changes tracked</div></div><div class="card"><b>Blast Radius</b><div class="muted small">Related targets identified</div></div></div><div class="find"><span>Infrastructure</span><b>Observed infrastructure → <span class="badge enr">GEOLOCATION</span></b></div><div class="find"><span>Attacker physical location</span><b>UNKNOWN</b></div></div><div class="card section"><div class="sectionHead"><h3 style="font-size:13px">AI Forensic Copilot</h3><span class="badge obs">EVIDENCE-GROUNDED</span></div><p class="muted" style="margin:0 0 10px">“${r.score >= 90 ? 'High-risk phishing is supported by authentication anomalies, sender mismatch and suspicious infrastructure.' : 'The threat classification is supported by the extracted forensic signals.'}”</p><div class="small muted">Recommended: quarantine if authorized · block confirmed IOC · hunt for matching indicators</div></div><div class="actions section"><button class="btn primary" onclick='saveAnalysis(${JSON.stringify({subject,score:r.score,threat:r.threat,raw:r.x.raw})})'>Save Investigation</button><button class="btn" onclick="go('map')">Trace Geo Location</button><button class="btn" onclick="viewForensicPDF()">Forensic Report</button></div>`;setTimeout(markSensitive,0)}
function normalizeSender(v){let s=String(v||"").trim();let m=s.match(/<([^>]+)>/);return (m?m[1]:s).trim().toLowerCase()}
function saveAnalysis(o){let id="TM-2026-"+String(143+cases.length).padStart(5,"0");let parsed=parseEmail(o.raw),ex=extract(o.raw);cases.unshift({id,sender:normalizeSender(parsed.h.from),subject:o.subject,threat:o.threat,score:o.score,loc:"Unknown",geoConfidence:null,status:"ACTIVE",indicators:ex.ips.length+ex.urls.length,raw:o.raw,createdAt:new Date().toISOString()});renderRecent();window.currentCase=cases[0];renderReports();toast("Investigation "+id+" saved");go("inbox")}
function currentRole(){return localStorage.getItem('tmRole')||'analyst'}
function connect(p){
  if(p==='Gmail'){ go('link'); } else toast(p+' connection is available in demo mode');
}
function startMailLink(){
  const email=($('mailAddress')?.value||'').trim();
  if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){toast('Enter a valid email address first');return}
  localStorage.setItem('tmPendingEmail',email);
  $('mailStatusBadge').textContent='READY FOR OAUTH'; $('mailStatusBadge').className='badge obs';
  $('mailStatusText').innerHTML='Mailbox <b>'+esc(email)+'</b> is ready. Starting secure Google authorization…';
  const backend=(window.TRACEMAIL_CONFIG&&window.TRACEMAIL_CONFIG.OAUTH_START)||'/auth/google/start?email='+encodeURIComponent(email);
  if(window.TRACEMAIL_CONFIG?.DEMO_OAUTH){
    setTimeout(()=>{ $('mailStatusBadge').textContent='DEMO CONNECTED'; $('mailStatusBadge').className='badge safe'; $('mailStatusText').textContent='Demo mailbox connected. Use Secure Inbox to continue the investigation workflow.'; toast('Demo mailbox connected'); },500);
  }else{ window.location.href=backend; }
}
function authorizeAction(action){
  if(currentRole()!=='admin'){toast('Administrator role required for response actions');return}
  const ok=confirm('Authorize '+action+'?\n\nDEMO ACTION: no real mailbox or security control will be changed.');
  if(ok)toast(action+' approved in demo — no external system changed');
}
function addWatchFromCase(){
  if(currentRole()==='viewer'){toast('Analyst access required to add IOCs to the watchlist');return}
  const item={v:'185.91.24.17',type:'IP',matches:1,status:'WATCHING'};
  if(!watch.some(x=>x.v===item.v)){watch.unshift(item);toast('IOC added to watchlist');}else toast('IOC is already on the watchlist');
}

function toggleDemoMode(){
  const b=document.getElementById('modeBadge');
  if(!b)return;
  const demo=b.textContent.includes('DEMO');
  b.textContent=demo?'LIVE INTEGRATION NOT CONNECTED':'DEMO ENVIRONMENT';
  b.style.color='var(--amber)';
  toast(demo?'Live mode selected — no provider is connected':'Demo mode restored');
}

const FORENSIC_PDF="./TraceMail_AI_Forensic_Report_TM-2026-00142.pdf";function viewForensicPDF(){window.open(FORENSIC_PDF,"_blank","noopener,noreferrer")};function downloadReport(){let c=cases[0];if(!c){toast("No investigation available yet");go("reports");return}let a=document.createElement("a");a.href=FORENSIC_PDF;a.download=c.id+"_forensic_report.pdf";document.body.appendChild(a);a.click();a.remove();reports.unshift({name:c.id+" Forensic Report",id:c.id,date:new Date().toLocaleString()});renderReports();toast("Structured forensic PDF exported")}
function toast(s){$("toast").textContent=s;$("toast").classList.add("show");setTimeout(()=>$("toast").classList.remove("show"),2600)}
renderRecent();renderInbox();document.addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){e.preventDefault();go("inbox");$("inboxSearch")?.focus();}});

