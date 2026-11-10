'use strict';

// Shared mock domain and controls. Each document selects a distinct navigation model.
const direction = document.body.dataset.direction;
const directionNames = {library:'Library',table:'Key Table',settings:'Key Settings',split:'Split View',menubar:'Menu Bar'};
const navigationNames={reference:'Reference Source List',compact:'Compact Source List',titlebar:'Title-bar Picker',strip:'Horizontal Key Strip',drill:'Key Browser'};
Object.assign(directionNames,navigationNames);
const navigationStudy=Object.hasOwn(navigationNames,direction);
if(navigationStudy){document.body.classList.add('navigation-study');}
const params = new URLSearchParams(location.search);
if (params.has('thumb')) document.body.classList.add('thumb');
if(navigationStudy&&!params.has('thumb'))document.title='Clavis — '+navigationNames[direction];
const $ = id => document.getElementById(id);
const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const paths = {
  search:'<circle cx="10" cy="10" r="6.5"/><path d="m15 15 5 5"/>',
  key:'<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-4-4 3-3m-6 0 3-3"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
  person:'<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
  bot:'<rect x="4" y="6" width="16" height="14" rx="4"/><path d="M12 3v3M8 11v2m8-2v2m-7 4h6M1 11v5m22-5v5"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  lock:'<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  down:'<path d="m6 9 6 6 6-6"/>',
  back:'<path d="m15 5-7 7 7 7"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  close:'<path d="m6 6 12 12M18 6 6 18"/>',
  copy:'<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V4H4v12h4"/>',
  terminal:'<path d="m5 7 5 5-5 5m8 0h6"/>',
  code:'<path d="m8 6-6 6 6 6m8-12 6 6-6 6m-3-16-2 20"/>',
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 1v2m0 18v2M1 12h2m18 0h2M4 4l2 2m12 12 2 2M4 20l2-2M18 6l2-2"/>',
  layers:'<path d="m12 2 10 6-10 6L2 8zm-9 11 9 5 9-5M3 18l9 5 9-5"/>',
  settings:'<circle cx="12" cy="12" r="4"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2"/>',
  pause:'<path d="M8 5v14m8-14v14"/>',
  play:'<path d="m7 4 13 8-13 8z"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
  fingerprint:'<path d="M4 13v-1a8 8 0 0 1 16 0v3M7 18v-6a5 5 0 0 1 10 0v7M10 21v-9a2 2 0 0 1 4 0v9M4 16v3m16-1v3"/>',
  inbox:'<path d="M4 4h16l2 15H2zm-1 9h5l2 3h4l2-3h5"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.key}</svg>`;
const appStyles = {Terminal:['terminal','black'],Xcode:['code','blue'],Codex:['code','black'],Claude:['bot','peach'],Antigravity:['layers','purple'],'GitHub Actions':['terminal','green']};
const appIcon = name => {const [symbol,color] = appStyles[name] || ['grid','blue'];return `<span class="app-icon ${color}">${icon(symbol)}</span>`;};
const opNames = {ssh:'SSH authentication',git:'Git signing'};
const tags = ops => `<span class="tokens row">${ops.map(o => `<span class="badge">${opNames[o]}</span>`).join('')}</span>`;
let keys = [
  {id:1,name:'Personal SSH',ops:['ssh'],enabled:true,policy:'Every request',last:'14:32'},
  {id:2,name:'Personal Git',ops:['git'],enabled:true,policy:'Every request',last:'14:28'},
  {id:3,name:'Development SSH',ops:['ssh'],enabled:true,policy:'Every request',last:'14:25'},
  {id:4,name:'GitHub Bot',ops:['git'],enabled:true,policy:'Every request',last:'14:24'},
  {id:5,name:'Deployment',ops:['ssh'],enabled:true,policy:'Every request',last:'13:57'},
];
let profiles = [
  {id:'dev',name:'Development Tools',members:['Terminal','Xcode'],grants:[{key:1,ops:['ssh']},{key:2,ops:['git']}]},
  {id:'agents',name:'Coding Agents',members:['Claude','Codex'],grants:[{key:3,ops:['ssh']},{key:4,ops:['git']}]},
  {id:'ci',name:'CI Automation',members:['GitHub Actions'],grants:[{key:5,ops:['ssh']}]},
];
let directGrants = [];
let activity = [
  {app:'Terminal',key:1,op:'ssh',result:'Allowed',time:'14:32',source:'Development Tools'},
  {app:'Xcode',key:2,op:'git',result:'Allowed',time:'14:28',source:'Development Tools'},
  {app:'Claude',key:3,op:'ssh',result:'Allowed',time:'14:25',source:'Coding Agents'},
  {app:'Codex',key:2,op:'git',result:'Denied',time:'14:24',source:'No applicable grant'},
  {app:'Codex',key:4,op:'git',result:'Allowed',time:'14:24',source:'Coding Agents'},
  {app:'GitHub Actions',key:5,op:'ssh',result:'Allowed',time:'13:57',source:'CI Automation'},
];
let state = {page:'keys',selected:2,search:'',profile:'agents',scope:'once',requestKey:4,requestApp:'Antigravity',requestOp:'git',requestProfile:'agents',evidence:'verified',paused:false,revision:0,reviewRevision:0,filter:'All',menuOpen:true,manager:false,memberScopeOnly:false};
if(navigationStudy){state.page=direction==='drill'?'keys':'activity';state.historyKey=null;state.drillOpen=false;}
let toastTimer;
let menuAnchor;
const keyBy = id => keys.find(k => k.id === Number(id));
const profileBy = id => profiles.find(p => p.id === id);
const effective = (ops,k) => k.enabled ? ops.filter(o => k.ops.includes(o)) : [];
const traffic = () => `<div class="traffic" aria-label="Window controls"><button data-action="hide-window" aria-label="Close prototype window"><i></i></button><button data-action="hide-window" aria-label="Minimize prototype window"><i></i></button><button data-action="zoom" aria-label="Zoom prototype window"><i></i></button></div>`;
function notify(message) {$('toast').textContent = message;clearTimeout(toastTimer);toastTimer = setTimeout(() => $('toast').textContent = '',5000);}
function log(app,key,op,result,source) {activity.unshift({app,key,op,result,source,time:new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',hour12:false})});}
function grantedOps(app,k) {return [...new Set([...directGrants.filter(g => g.app===app && g.key===k.id).flatMap(g=>g.ops),...profiles.filter(p=>p.members.includes(app)).flatMap(p=>p.grants.filter(g=>g.key===k.id).flatMap(g=>g.ops))])].filter(o=>effective([o],k).length);}
function frame() {
  document.body.innerHTML = `<div class="macbar"><strong aria-hidden="true">●</strong><b class="brand">Clavis</b><button class="bar-link" data-action="file-menu">File</button><button class="bar-link" data-action="nav" data-page="keys">View</button><button class="bar-link" data-action="selected-settings">Key Settings</button><div class="bar-right"><button data-action="toggle-menu" class="${direction==='menubar'?'selected':''}" aria-label="Open Clavis menu">${icon('key')}</button>${icon('layers')}<span>Wed 28 Oct &nbsp; 14:35</span></div></div>
    <div class="studybar"><a href="../index.html">${icon('back')} All five directions</a><span class="study-id">${String((navigationStudy?Object.keys(navigationNames):Object.keys(directionNames)).indexOf(direction)+1).padStart(2,'0')} / ${directionNames[direction]} · Interactive study</span><div class="lab-controls"><select id="scenario" aria-label="Request evidence scenario"><option value="verified">Verified ancestry</option><option value="deny">Ancestor deny</option><option value="uncertain">Incomplete ancestry</option></select><button class="pill" data-action="theme" aria-label="Switch light and dark appearance">${icon('sun')}<span>Appearance</span></button><button class="pill" data-action="transparency" aria-pressed="false" aria-label="Toggle reduced transparency">${icon('layers')}<span>Glass</span></button></div></div>
    <div id="app"></div><div class="study-disclaimer">Mock data · No real keys, signing or authentication · CSS material approximation</div><div id="toast" class="toast glass" role="status" aria-live="polite"></div>
    <dialog id="sheet" aria-labelledby="sheet-title"></dialog><div id="context-menu" class="context-menu glass" role="menu" aria-label="Actions" hidden></div>`;
  $('scenario').value = state.evidence;
  render();
}
function sidebar() {
  const nav=[['keys','key','Keys'],['profiles','grid','Application Profiles'],['activity','clock','Activity']];
  return `<aside class="sidebar glass">${traffic()}<div class="sidebar-heading">Clavis</div><nav aria-label="Main navigation">${nav.map(([id,symbol,label])=>`<button class="nav-btn ${state.page===id?'active':''}" data-action="nav" data-page="${id}" ${state.page===id?'aria-current="page"':''} aria-label="${label}">${icon(symbol)}<span>${label}</span>${id==='keys'?`<span class="count">${keys.length}</span>`:''}</button>`).join('')}</nav>${direction==='settings'&&state.page==='keys'?`<div class="nav-title">KEYS</div><div class="sidebar-key-list">${keyItems()}</div>`:''}<div class="sidebar-bottom"><div class="row"><span class="dot ${state.paused?'paused':''}"></span>${state.paused?'Requests paused':'Agent active'}</div><div class="row muted">${icon('shield')} Private keys stay on this Mac</div><button class="review-btn" data-action="pause">${icon(state.paused?'play':'pause')}${state.paused?'Resume requests':'Pause requests'}</button></div></aside>`;
}
function toolbar() {
  const title={keys:'Keys',profiles:'Application Profiles',activity:'Activity'}[state.page];
  return `<div class="toolbar glass">${direction==='split'?traffic():''}<div><h1>${title}</h1></div>${direction==='split'?`<nav class="segmented" aria-label="Main navigation">${[['keys','Keys'],['profiles','Profiles'],['activity','Activity']].map(([id,name])=>`<button data-action="nav" data-page="${id}" class="${state.page===id?'active':''}">${name}</button>`).join('')}</nav>`:''}<div class="spacer"></div>${state.page==='keys'?'<input id="search" type="search" placeholder="Search keys" aria-label="Search keys">':''}<button class="pill" data-action="request">${icon('inbox')}<span class="button-label">Preview access</span></button><button class="circle" data-action="create" aria-label="Create key">${icon('plus')}</button><button class="circle" data-action="more" aria-label="More actions">${icon('settings')}</button></div>`;
}
function render() {
  if(navigationStudy){renderNavigationStudy();return;}
  if(direction==='menubar'&&!state.manager){renderMenuBar();return;}
  $('app').innerHTML=`<section class="window ${direction}" aria-label="Clavis ${directionNames[direction]} prototype">${direction==='split'?'':sidebar()}<div class="main">${toolbar()}<div id="workspace" class="body"></div><div class="bottomline"><span>${state.paused?'Requests paused':`${keys.filter(k=>k.enabled).length} enabled keys`}</span><span>All changes are local to this prototype</span></div></div></section>`;
  if(state.page==='keys'){
    if(direction==='table')renderKeyTable();
    else if(direction==='settings')renderKeySettings();
    else renderLibrary();
  }
  if(state.page==='profiles')renderProfiles();
  if(state.page==='activity')renderActivity();
  if($('search')){$('search').value=state.search;$('search').addEventListener('input',e=>{state.search=e.target.value;updateSearch();});}
}
function visibleKeys(){return keys.filter(k=>`${k.name} ${k.ops.map(o=>opNames[o]).join(' ')}`.toLowerCase().includes(state.search.toLowerCase()));}
function keyItems(){return visibleKeys().map(k=>`<button class="key-item ${state.selected===k.id?'selected':''}" data-action="key" data-id="${k.id}" aria-pressed="${state.selected===k.id}"><span class="key-small">${icon('key')}</span><span><strong>${escapeHTML(k.name)}</strong><small>${k.ops.map(o=>o==='ssh'?'SSH':'Git signing').join(' + ')} · P-256</small></span><span class="spacer"></span><span class="status-dot ${k.enabled?'':'off'}" title="${k.enabled?'Enabled':'Disabled'}"></span></button>`).join('')||'<div class="empty">No matching keys.</div>';}
function updateSearch(){
  if(direction==='table')renderKeyTable();
  else if(direction==='settings')document.querySelector('.sidebar-key-list').innerHTML=keyItems();
  else if($('key-items'))$('key-items').innerHTML=keyItems();
}
function renderLibrary(){
  $('workspace').className='split';
  $('workspace').innerHTML=`<section class="key-list" aria-label="Key list"><div class="row between" style="padding:5px 10px"><b class="small">All keys</b><span class="muted small">${visibleKeys().length}</span></div><div id="key-items">${keyItems()}</div><button class="nav-btn muted" data-action="create">${icon('plus')}<span>Add a key</span></button></section><section class="body" aria-label="Key inspector">${keyDetails(keyBy(state.selected))}</section>`;
}
function renderKeyTable(){
  $('workspace').className='body key-table-workspace';
  $('workspace').innerHTML=`<div class="row between"><div><h2>Keys</h2><p class="lede">Select a key to review its settings and application access.</p></div><button class="secondary" data-action="create">${icon('plus')} Add key</button></div><div class="key-browser-table"><table><caption class="sr-only">Cryptographic keys</caption><thead><tr><th>Name</th><th>Purpose</th><th>Algorithm</th><th>Status</th><th>Last used</th></tr></thead><tbody>${visibleKeys().map(k=>`<tr class="${state.selected===k.id?'selected':''}"><td><button class="table-key-button" data-action="inspect" data-id="${k.id}">${icon('key')}<b>${escapeHTML(k.name)}</b></button></td><td>${k.ops.map(o=>opNames[o]).join(', ')}</td><td class="small muted">P-256</td><td><span class="badge ${k.enabled?'green':'neutral'}">${k.enabled?'Enabled':'Disabled'}</span></td><td class="small muted">${k.last}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">No matching keys.</td></tr>'}</tbody></table></div><div class="row between section-label"><span>SELECTED KEY · ${escapeHTML(keyBy(state.selected).name)}</span><button class="review-btn" data-action="inspect" data-id="${state.selected}">Open key settings ${icon('chevron')}</button></div><div class="table-selection-summary"><div class="row"><span class="mini-icon">${icon('fingerprint')}</span><span class="stack"><b class="small">${escapeHTML(keyBy(state.selected).policy)}</b><span class="small muted">Authentication for this key</span></span></div><div class="row"><span class="mini-icon">${icon('grid')}</span><span class="stack"><b class="small">${profiles.filter(p=>p.grants.some(g=>g.key===state.selected)).map(p=>escapeHTML(p.name)).join(', ')||'No profiles'}</b><span class="small muted">Application access</span></span></div><button class="secondary" data-action="key-history" data-id="${state.selected}">${icon('clock')} Show activity</button></div>`;
}
function renderKeySettings(){
  const k=keyBy(state.selected);$('workspace').className='body settings-workspace';
  $('workspace').innerHTML=`<div class="key-settings-title"><div class="key-emblem">${icon('key')}</div><h2>${escapeHTML(k.name)}</h2><span class="badge ${k.enabled?'green':'neutral'}">${k.enabled?'Enabled':'Disabled'}</span><p class="lede">${k.ops.map(o=>opNames[o]).join(', ')} · ECDSA P-256</p></div><div class="settings-sections">${keyDetails(k,true)}</div>`;
}
function accessRows(k) {
  const sources = [...profiles.filter(p=>p.grants.some(g=>g.key===k.id)).map(p=>({name:p.name,subtitle:p.members.join(', ')||'No members',ops:effective(p.grants.find(g=>g.key===k.id).ops,k),id:p.id,type:'profile'})),...directGrants.filter(g=>g.key===k.id).map(g=>({name:g.app,subtitle:'Direct grant',ops:effective(g.ops,k),id:g.id,type:'direct'}))];
  return sources.length?sources.map(s=>`<div class="data-row"><div class="row">${s.type==='profile'?`<span class="mini-icon">${icon('grid')}</span>`:appIcon(s.name)}<div><strong>${escapeHTML(s.name)}</strong><small>${escapeHTML(s.subtitle)}</small></div></div><div class="row">${s.ops.length?tags(s.ops):'<span class="badge neutral">No effective access</span>'}<button class="icon-button" data-action="${s.type==='profile'?'profile':'revoke'}" data-id="${s.id}" aria-label="${s.type==='profile'?'Manage':'Revoke'} ${escapeHTML(s.name)}">${icon(s.type==='profile'?'chevron':'close')}</button></div></div>`).join(''):'<div class="empty">No applications have access to this key yet.</div>';
}
function keyDetails(k,compact=false) {
  return `<div class="detail-hero"><div class="key-emblem">${icon('key')}</div><div><div class="eyebrow">KEY SETTINGS</div><h2>${escapeHTML(k.name)}</h2><div class="row"><span class="small muted">${k.ops.map(o=>opNames[o]).join(' & ')}</span><span class="badge ${k.enabled?'green':'neutral'}">${k.enabled?'Enabled':'Disabled'}</span></div></div><div class="spacer"></div><button class="circle" data-action="key-menu" data-id="${k.id}" aria-label="Key actions">${icon('settings')}</button></div>
    <div class="panel"><div class="data-row"><span>Key enabled</span><button class="native-switch ${k.enabled?'checked':''}" role="switch" aria-checked="${k.enabled}" aria-label="Enable ${escapeHTML(k.name)}" data-action="toggle-key" data-id="${k.id}"><span></span></button></div><div class="data-row"><span>Public key</span><button class="review-btn" data-action="copy" data-id="${k.id}">${icon('copy')} Copy public key</button></div><div class="data-row"><span class="muted">Fingerprint</span><span class="mono">SHA256:${['M6Xq','P9aV','k4Xt','H7jQ','C2mN'][((k.id-1)%5)]}…${(k.id*1937).toString(16)} <span class="muted">(fixture)</span></span></div>${compact?'':`<div class="data-row"><span class="muted">Algorithm · Storage</span><span class="small">ECDSA P-256 · Secure Enclave</span></div>`}</div>
    <div class="section-label">AUTHENTICATION</div><div class="panel"><button class="data-row full-button" data-action="policy" data-id="${k.id}"><span class="row">${icon('fingerprint')}<span class="stack"><b>${escapeHTML(k.policy)}${k.duration?' · '+escapeHTML(k.duration):''}</b><span class="small muted">${k.policy==='Every request'?'Authenticate each signing operation':'Preview policy · experimental'}</span></span></span>${icon('chevron')}</button></div>
    <div class="row between section-label"><span>APPLICATION ACCESS</span><button class="review-btn" data-action="request" data-id="${k.id}">${icon('plus')} Add access</button></div><div class="panel">${accessRows(k)}</div>
    ${compact?'':`<div class="row between section-label"><span>RECENT ACTIVITY</span><button class="review-btn" data-action="key-history" data-id="${k.id}">Show all</button></div>${activity.filter(e=>e.key===k.id).slice(0,2).map(e=>`<div class="row recent">${appIcon(e.app)}<span class="${e.result==='Allowed'?'green':'danger'}">${icon(e.result==='Allowed'?'check':'close')}</span><span>${e.app} <span class="muted">· ${opNames[e.op]}</span></span><span class="spacer"></span><span class="small muted">${e.time}</span></div>`).join('')||'<p class="hint">No signing activity for this key.</p>'}`}
    <p class="hint">Application permission and key authentication are checked separately.</p>`;
}
function profileScope(p,app=null) {
  return p.grants.map(g=>{const k=keyBy(g.key),ops=effective(g.ops,k);return `<div class="data-row"><div><strong>${escapeHTML(k.name)}</strong><small>${app&&ops.length?`${ops.every(o=>grantedOps(app,k).includes(o))?'Already accessible':'New access'}`:''}</small></div>${ops.length?tags(ops):'<span class="badge neutral">Key disabled</span>'}</div>`;}).join('')||'<div class="empty">No keys are granted to this profile.</div>';
}
function renderProfiles() {
  const p=profileBy(state.profile);
  $('workspace').innerHTML=`<div class="row between"><div><h2>Application profiles</h2><p class="lede">A reusable group of applications, with explicit access to selected keys.</p></div><button class="secondary" data-action="create-profile">${icon('plus')} New profile</button></div><div class="segmented" role="group" aria-label="Select profile">${profiles.map(profile=>`<button class="${p.id===profile.id?'active':''}" data-action="profile" data-id="${profile.id}" aria-pressed="${p.id===profile.id}">${escapeHTML(profile.name)}</button>`).join('')}</div><div class="columns-2" style="margin-top:20px"><section><div class="row between section-label"><span>APPLICATIONS · ${p.members.length}</span><button class="review-btn" data-action="add-member" data-id="${p.id}">${icon('plus')} Add application</button></div><div class="panel">${p.members.map(app=>`<div class="data-row"><div class="row">${appIcon(app)}<div><b>${app}</b><small>Verified signing identity · fixture</small></div></div><button class="icon-button" data-action="remove-member" data-profile="${p.id}" data-app="${app}" aria-label="Remove ${app} from ${escapeHTML(p.name)}">${icon('close')}</button></div>`).join('')||'<div class="empty">No members. Add a verified application to begin.</div>'}</div><p class="hint">Membership grants no authentication exemption. Child processes are covered by the ancestry rules.</p></section><section><div class="section-label">KEYS & OPERATIONS</div><div class="panel">${profileScope(p)}</div><p class="hint">Adding a member expands access to every key and operation shown here. Future grants to this profile also include its members.</p></section></div>`;
}
const policyOptions=['Every request','Until screen lock or sleep','For a duration','Once per day','Unattended'];
function renderActivity(){
  $('workspace').className='history-workspace';
  const historyURL=navigationStudy?`history.html?content-only=1&theme=${document.documentElement.dataset.theme||'light'}#tokens`:'history.html#tokens';
  $('workspace').innerHTML=`<iframe id="history-frame" src="${historyURL}" title="Signing activity with token filters"></iframe>`;
  $('history-frame').addEventListener('load',syncHistory);
}
function syncHistory(){
  const frame=$('history-frame');if(!frame)return;
  frame.contentWindow.postMessage({type:'clavis-history',theme:document.documentElement.dataset.theme||'light',opaque:document.documentElement.classList.contains('opaque'),hideSource:navigationStudy,keys:keys.map(k=>({id:String(k.id),name:k.name,purpose:k.ops.map(o=>opNames[o]).join(', ')})),scope:state.historyKey||null,events:activity.map((e,index)=>({id:'current-'+index,date:'2026-10-28',time:e.time.length===5?e.time+':00':e.time,key:String(e.key),keyName:keyBy(e.key).name,host:e.op==='git'?'github.com':'production.internal',status:e.result==='Allowed'?'Approved':'Rejected',category:e.op==='git'?'Git':'SSH',operation:opNames[e.op],process:e.app+' → '+(e.op==='git'?'git → ssh-keygen':'ssh'),app:e.app,executable:e.op==='git'?'/usr/bin/ssh-keygen':'/usr/bin/ssh'}))},location.protocol==='file:'?'*':location.origin);
}
function renderMenuBar() {
  $('app').innerHTML=`<section class="compact-stage" aria-label="Menu bar prototype"><div class="ghost-window"><div class="toolbar glass">${traffic()}<span class="spacer"></span><b class="small">clavis — zsh</b><span class="spacer"></span></div><div class="terminal-body"><span class="muted">~/Projects/Clavis</span><br><strong>❯ git commit -S -m "Update access policies"</strong><br>Waiting for signing authorization…<br><br><span class="muted">Clavis is available from the menu bar.</span></div></div>${state.menuOpen?`<section class="popover glass" aria-label="Clavis menu"><div class="row between popover-head"><div class="row"><span class="mini-icon">${icon('key')}</span><h2>Clavis</h2></div><span class="small ${state.paused?'orange':'green'}"><span class="dot ${state.paused?'paused':''}"></span>${state.paused?'Paused':'Agent active'}</span></div><div class="pop-section"><div class="row between"><span class="pop-title">ACCESS REQUEST</span><span class="badge neutral">1</span></div><div class="pop-request"><div class="row">${appIcon('Antigravity')}<div><b class="small">Antigravity</b><div class="small muted" style="margin-top:4px">Git signing · GitHub Bot</div></div></div><p>New application access requires your approval.</p><button class="primary" data-action="request" style="width:100%">Review request</button></div></div><div class="pop-section"><div class="row between"><span class="pop-title">KEYS</span><span class="small muted">${keys.length}</span></div>${keys.slice(0,4).map(k=>`<button class="pop-key" data-action="inspect" data-id="${k.id}"><span class="mini-icon">${icon('key')}</span><span><strong>${escapeHTML(k.name)}</strong><small>${k.ops.map(o=>o==='ssh'?'SSH':'Git').join(' + ')}</small></span><span class="spacer"></span>${icon('chevron')}</button>`).join('')}</div><div class="pop-section"><button class="row full-button" data-action="pause">${icon(state.paused?'play':'pause')}<span>${state.paused?'Resume requests':'Pause all requests'}</span><span class="spacer"></span><span class="small muted">${state.paused?'Paused':'On'}</span></button></div><div class="pop-footer"><button class="review-btn" data-action="manager">Open Clavis…</button><button class="icon-button" data-action="manager-policies" aria-label="Authentication settings">${icon('settings')}</button></div></section>`:'<button class="pill reopen-menu" data-action="toggle-menu">Open Clavis menu</button>'}</section>`;
}
function showSheet(title,body,footer,eyebrow='Clavis') {
  $('sheet').innerHTML=`<div class="dialog-head glass"><div class="row between"><span class="eyebrow">${eyebrow}</span><button class="icon-button" data-action="close-sheet" aria-label="Close dialog">${icon('close')}</button></div><h2 id="sheet-title">${title}</h2></div><div class="dialog-body">${body}</div><div class="dialog-footer">${footer}</div>`;
  if(!$('sheet').open)$('sheet').showModal();
}
function openRequest(keyId=4,app='Antigravity',scope='once',profileId='agents',membershipOnly=false) {
  state.requestKey=Number(keyId);state.requestOp=keyBy(keyId).ops[0];state.requestApp=app;state.scope=scope;state.requestProfile=profileId;state.memberScopeOnly=membershipOnly;state.reviewRevision=state.revision;
  requestSheet();
}
function requestSheet() {
  const k=keyBy(state.requestKey),app=state.requestApp,p=profileBy(state.requestProfile);
  const body=`<div class="request-identity">${appIcon(app)}<div><h3>${escapeHTML(app)}</h3><span class="small ${state.evidence==='verified'?'green':'danger'}">${state.memberScopeOnly?'Verified application identity · fixture':state.evidence==='verified'?'Verified signing identity · mock evidence':state.evidence==='deny'?'Explicit restriction in ancestry':'Ancestry incomplete'}</span></div></div>${state.memberScopeOnly?'':`<div class="row small between"><span class="muted">Requesting key</span><b>${escapeHTML(k.name)}</b></div><div class="row small between" style="margin-top:10px"><span class="muted">Operation</span><b>${opNames[state.requestOp]}</b></div><details class="chain"><summary>${icon('chevron')} Process ancestry and signing evidence</summary><div class="chain-path"><b>${escapeHTML(app)}</b> · application principal<br>　↳ shell → git → ${state.requestOp==='git'?'ssh-keygen':'ssh'} · direct peer<br><span class="muted">Signing ID: app.fixture.client · Team ID: MOCKTEAM01<br>Peer PID: 4821 (fixture) · Verified code-signing requirement<br>Every required ancestor is checked; any applicable deny wins.</span></div></details><p class="scope-caption">Trust includes child processes launched by ${escapeHTML(app)}. A process name or path alone never establishes trust.</p>`}<div class="scope-tabs" role="group" aria-label="Approval scope">${[['once','Allow Once'],['key','Always for This Key'],['profile','Add to Profile']].map(([id,name])=>`<button data-action="scope" data-id="${id}" class="${state.scope===id?'active':''}" aria-pressed="${state.scope===id}" ${membershipOnlyScope(id)?'disabled':''}>${name}</button>`).join('')}</div><div id="scope-content"></div><p class="scope-caption">${state.scope==='once'?'No persistent grant is saved.':''} ${state.memberScopeOnly?'Profile membership changes require authentication. Confirmation simulates it.':"The key's authentication requirement still applies. Confirmation simulates authentication."}</p>`;
  showSheet(state.memberScopeOnly?`Add ${escapeHTML(app)} to ${escapeHTML(p.name)}`:`${escapeHTML(app)} wants to use your key.`,body,`<button class="secondary danger" data-action="deny-request">${state.memberScopeOnly?'Cancel':'Deny'}</button><button id="approve" class="primary" data-action="approve-request">${state.scope==='once'?'Allow Once':state.scope==='key'?'Allow for This Key':'Add to Profile'} · Simulate</button>`,'Access request');
  updateScope();
}
function membershipOnlyScope(id) {return state.memberScopeOnly && id!=='profile';}
function updateScope() {
  const k=keyBy(state.requestKey),app=state.requestApp,p=profileBy(state.requestProfile);
  let error = state.memberScopeOnly?'':state.paused?'Requests are paused. Resume before approving.':!k.enabled?'This key is disabled. An access grant cannot enable it.':state.evidence==='deny'?'An explicit deny in verified ancestry overrides every allow.':state.evidence==='uncertain'?'Ancestry is incomplete. This draft refuses authorization; persistent trust is unavailable.':'';
  if(state.scope==='profile'&&!state.memberScopeOnly&&!p.grants.some(g=>g.key===k.id&&effective(g.ops,k).includes(state.requestOp)))error='This profile does not grant the requested key and operation. Choose a different scope.';
  const content=state.scope==='profile'?`<label class="form-field">Application profile<select id="request-profile">${profiles.map(profile=>`<option value="${profile.id}" ${profile.id===p.id?'selected':''}>${escapeHTML(profile.name)}</option>`).join('')}</select></label><p class="scope-caption"><b>Complete access through ${escapeHTML(p.name)}</b> · ${p.members.includes(app)?'Already a member':'Adding a new member'}</p><div class="scope-preview">${profileScope(p,app)}</div><p class="scope-caption">Future key grants to this profile will include ${escapeHTML(app)}. Other grants remain independent.</p>`:`<div class="scope-preview"><div class="data-row"><div><b>${escapeHTML(k.name)}</b><small>${state.scope==='once'?'This request only':'Persistent direct grant'}</small></div>${tags([state.requestOp])}</div></div>${state.scope==='key'?`<div class="scope-op">${k.ops.map(o=>`<label><input type="checkbox" name="grant-op" value="${o}" checked ${o===state.requestOp?'disabled':''}> ${opNames[o]}</label>`).join('')}</div>`:''}`;
  $('scope-content').innerHTML=`${content}${error?`<div class="notice error" role="status">${error}</div>`:''}`;
  $('approve').disabled=!!error;
  if($('request-profile'))$('request-profile').onchange=e=>{state.requestProfile=e.target.value;updateScope();$('request-profile').focus();};
}
function approveRequest() {
  if($('approve').disabled)return;
  if(state.reviewRevision!==state.revision){state.reviewRevision=state.revision;requestSheet();notify('Access changed. Review the refreshed scope before confirming again.');return;}
  const k=keyBy(state.requestKey),app=state.requestApp;
  if(state.scope==='key') {
    const ops=[...$('sheet').querySelectorAll('[name=grant-op]:checked')].map(el=>el.value);
    directGrants.push({id:crypto.randomUUID(),app,key:k.id,ops});state.revision++;
  }
  if(state.scope==='profile') {const p=profileBy(state.requestProfile);if(!p.members.includes(app)){p.members.push(app);state.revision++;}}
  if(!state.memberScopeOnly)log(app,k.id,state.requestOp,'Allowed',state.scope==='once'?'One request · simulated':state.scope==='key'?'Direct grant · simulated':profileBy(state.requestProfile).name+' · simulated');
  $('sheet').close();render();notify(state.memberScopeOnly?'Profile membership saved in this prototype.':`Simulated approval · ${state.scope==='once'?'one request, no grant saved':state.scope==='key'?'direct access saved':'profile membership saved'}. Key authentication simulated.`);
}
function openPolicy(id,preselect=null) {
  const k=keyBy(id),index=preselect===null?Math.max(0,policyOptions.indexOf(k.policy)):Number(preselect);
  showSheet('Authentication policy',`<p class="scope-caption">${escapeHTML(k.name)}</p><label class="form-field">Ask for authentication<select id="policy-choice">${policyOptions.map((name,i)=>`<option value="${i}" ${i===index?'selected':''}>${name}${i>0?' · experimental preview':''}</option>`).join('')}</select></label><label id="duration-field" class="form-field" ${index!==2?'hidden':''}>Maximum reuse window<select id="duration">${['5 minutes','15 minutes','1 hour'].map(d=>`<option ${k.duration===d?'selected':''}>${d}</option>`).join('')}</select></label><div id="policy-explanation" class="notice"></div><p class="scope-caption">Application grants are unchanged. Hardware-enforced policy changes may require generating a replacement key. This only edits mock UI state.</p>`,`<button class="secondary" data-action="close-sheet">Cancel</button><button class="primary" data-action="save-policy" data-id="${id}">Save preview policy</button>`,'Key settings');
  const explain=()=>{const i=Number($('policy-choice').value);$('duration-field').hidden=i!==2;$('policy-explanation').textContent=['Fresh authentication is required for each signing request.','Experimental. Lock, sleep and restart end reuse. macOS can reject a context earlier.','Experimental. The configured interval is an upper bound, not a macOS retention guarantee.','Experimental. Rolling versus calendar-day semantics remain undecided; do not treat this preview as a supported duration.','Experimental. Requires validated key creation and no-prompt access across restart. Existing protected keys cannot become unattended with a toggle.'][i];};
  $('policy-choice').onchange=explain;explain();
}
function createSheet() {
  showSheet('Create a key',`<form id="key-form"><label class="form-field">Name<input id="key-name" required maxlength="80" placeholder="Work Git signing" autocomplete="off"></label><label class="form-field">Purpose<select id="key-purpose"><option value="ssh">SSH authentication</option><option value="git">Git signing</option></select></label><div class="data-row"><span class="muted small">Storage & algorithm</span><span class="small">Secure Enclave · P-256</span></div><p class="scope-caption">Starts enabled, with Every request authentication and no application grants. No cryptographic material is created by this prototype.</p></form>`,`<button class="secondary" data-action="close-sheet">Cancel</button><button type="submit" form="key-form" class="primary">Create mock key</button>`,'Key management');
  $('key-form').onsubmit=e=>{e.preventDefault();const name=$('key-name').value.trim();if(!name){$('key-name').setCustomValidity('Enter a key name.');$('key-name').reportValidity();return;}const id=Math.max(...keys.map(k=>k.id))+1;keys.push({id,name,ops:[$('key-purpose').value],enabled:true,policy:'Every request',last:'Never'});state.selected=id;state.page='keys';state.search='';state.revision++;state.manager=true;$('sheet').close();render();notify('Mock key created. No applications have access.');};
  $('key-name').oninput=()=>$('key-name').setCustomValidity('');$('key-name').focus();
}
function addMember(id) {
  const p=profileBy(id),available=Object.keys(appStyles).filter(app=>!p.members.includes(app));
  showSheet('Add application',`<p class="scope-caption">Choose a mock verified application for ${escapeHTML(p.name)}. The next step lists its complete access.</p><label class="form-field">Application<select id="member-app">${available.map(app=>`<option>${app}</option>`).join('')}</select></label>`,`<button class="secondary" data-action="close-sheet">Cancel</button><button class="primary" data-action="review-member" data-id="${id}" ${!available.length?'disabled':''}>Review access…</button>`,'Application profile');
}
function removeMember(profileId,app) {
  const p=profileBy(profileId);
  showSheet(`Remove ${escapeHTML(app)}?`,`<p class="scope-caption">Remove from ${escapeHTML(p.name)}. These profile-supplied permissions are removed; any direct or other profile access remains.</p><div class="scope-preview">${profileScope(p)}</div><p class="scope-caption">Requests and approvals affected by this membership change are invalidated in the model.</p>`,`<button class="secondary" data-action="close-sheet">Cancel</button><button class="secondary danger" data-action="confirm-remove-member" data-profile="${profileId}" data-app="${app}">Remove from profile</button>`,'Revoke profile membership');
}
function contextMenu(anchor,items) {
  menuAnchor=anchor;const rect=anchor.getBoundingClientRect();$('context-menu').innerHTML=items;$('context-menu').hidden=false;$('context-menu').style.top=Math.min(rect.bottom+7,innerHeight-150)+'px';$('context-menu').style.left=Math.max(12,Math.min(rect.left,innerWidth-240))+'px';$('context-menu').querySelector('button')?.focus();
}
function menuItem(action,symbol,label,id='') {return `<button role="menuitem" data-action="${action}" data-id="${id}">${icon(symbol)}${label}</button>`;}
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-action]');
  if(!b){if(!$('context-menu').contains(e.target))$('context-menu').hidden=true;return;}
  const action=b.dataset.action,id=b.dataset.id;
  if(!['more','key-menu','file-menu'].includes(action))$('context-menu').hidden=true;
  if(action==='nav'){state.page=b.dataset.page;state.manager=true;if(navigationStudy&&direction==='drill'&&state.page==='keys')state.drillOpen=false;if(state.page==='activity')state.historyKey=null;render();}
    if(action==='inspect'&&direction==='table'){state.selected=Number(id);render();showSheet('Key inspector',keyDetails(keyBy(id)),`<button class="primary" data-action="close-sheet">Done</button>`);return;}
  if(navigationStudy&&['key','inspect','nav-key'].includes(action)){changeNavigationKey(id);return;}
  if(action==='pick-key'){openKeyPicker(b);return;}
  if(action==='browse-keys'){state.page='keys';state.drillOpen=false;render();return;}
  if(action==='all-key-activity'){if(state.page==='activity'&&$('history-frame')){state.historyKey=null;$('history-frame').contentWindow.postMessage({type:'clavis-history-scope',scope:'all'},location.protocol==='file:'?'*':location.origin);updateNavigationSelection(null);}else{state.page='activity';state.historyKey=null;render();}return;}
  if(action==='key'||action==='inspect'){state.selected=Number(id);state.page='keys';if(direction==='menubar')state.manager=true;render();}
  if(action==='profile'){if($('sheet').open)$('sheet').close();state.profile=id;state.page='profiles';state.manager=true;render();}
  if(action==='request')openRequest(id||4);
  if(action==='scope'){state.scope=id;requestSheet();$('sheet').querySelector(`[data-action=scope][data-id="${id}"]`)?.focus();}
  if(action==='approve-request')approveRequest();
  if(action==='deny-request'){if(!state.memberScopeOnly)log(state.requestApp,state.requestKey,state.requestOp,'Denied','User denied · simulated');$('sheet').close();render();notify(state.memberScopeOnly?'Membership change cancelled.':'Request denied. No new grant saved.');}
    if(action==='close-sheet')$('sheet').close();
  if(action==='create')createSheet();
  if(action==='policy')openPolicy(id,b.dataset.policy??null);
  if(action==='save-policy'){const k=keyBy(id),choice=Number($('policy-choice').value);k.policy=policyOptions[choice];k.duration=choice===2?$('duration').value:null;state.revision++;$('sheet').close();render();notify(choice===0?'Every request policy selected.':'Experimental preview selected. No macOS retention capability is asserted.');}
  if(action==='theme'){document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark';b.setAttribute('aria-label',document.documentElement.dataset.theme==='dark'?'Switch to light appearance':'Switch to dark appearance');syncHistory();}
  if(action==='transparency'){document.documentElement.classList.toggle('opaque');b.setAttribute('aria-pressed',document.documentElement.classList.contains('opaque'));b.querySelector('span').textContent=document.documentElement.classList.contains('opaque')?'Solid':'Glass';syncHistory();}
  if(action==='pause'){state.paused=!state.paused;state.revision++;render();notify(state.paused?'Requests paused in this prototype. Pending approvals are invalidated.':'Requests resumed in this prototype. No authentication session restored.');}
    if(action==='add-member')addMember(id);
  if(action==='review-member'){const p=profileBy(id);openRequest(p.grants[0]?.key||4,$('member-app').value,'profile',id,true);}
  if(action==='remove-member')removeMember(b.dataset.profile,b.dataset.app);
  if(action==='confirm-remove-member'){const p=profileBy(b.dataset.profile);p.members=p.members.filter(a=>a!==b.dataset.app);state.revision++;$('sheet').close();render();notify('Profile membership removed. Other grant sources remain independent.');}
  if(action==='revoke'){const g=directGrants.find(g=>g.id===id);directGrants=directGrants.filter(g=>g.id!==id);state.revision++;render();notify(`Direct grant for ${g.app} removed. Check remaining profile access in the inspector.`);}
  if(action==='copy'){
    // Intentionally not a cryptographic public key: this fixture must not be installed for real use.
    const fixture=`CLAVIS-PROTOTYPE-PUBLIC-KEY-FIXTURE:${keyBy(id).name}:NOT-A-REAL-KEY`;
    try{await navigator.clipboard.writeText(fixture);notify('Copied a labeled, nonfunctional public-key fixture.');}catch{showSheet('Public key fixture',`<p class="scope-caption">Clipboard unavailable in this browser context. Select this nonfunctional fixture to copy manually.</p><textarea class="copy-fixture" readonly>${escapeHTML(fixture)}</textarea>`,`<button class="primary" data-action="close-sheet">Done</button>`);}
  }
  if(action==='more'||action==='file-menu')contextMenu(b,menuItem('create','plus','Create a key…')+menuItem('request','inbox','Review access request…')+menuItem('pause',state.paused?'play':'pause',state.paused?'Resume requests':'Pause requests'));
  if(action==='key-menu')contextMenu(b,menuItem('policy','fingerprint','Authentication policy…',id)+menuItem('toggle-key',keyBy(id).enabled?'pause':'play',keyBy(id).enabled?'Disable key…':'Enable key…',id)+menuItem('copy','copy','Copy public key fixture',id));
  if(action==='toggle-key'){const k=keyBy(id);showSheet(`${k.enabled?'Disable':'Enable'} ${escapeHTML(k.name)}?`,`<p class="scope-caption">${k.enabled?'New signing requests will be denied. Existing grants remain configured but have no effective operations.':'Existing grants become effective again. Review all permissions below before enabling.'}</p><div class="panel">${accessRows({...k,enabled:true})}</div>`,`<button class="secondary" data-action="close-sheet">Cancel</button><button class="primary" data-action="confirm-toggle-key" data-id="${id}">${k.enabled?'Disable':'Enable'} key</button>`,'Key state');}
  if(action==='confirm-toggle-key'){keyBy(id).enabled=!keyBy(id).enabled;state.revision++;$('sheet').close();render();notify('Key state updated in this prototype. Existing grants were preserved.');}
  if(action==='manager'){state.manager=true;state.page='keys';render();}
  if(action==='manager-policies'||action==='selected-settings')openPolicy(state.selected);
  if(action==='key-history'){if($('sheet').open)$('sheet').close();state.historyKey=String(id);state.page='activity';state.manager=true;render();}
  if(action==='toggle-menu'){if(direction==='menubar'){if(state.manager){state.manager=false;state.menuOpen=true;}else state.menuOpen=!state.menuOpen;render();}else openRequest();}
  if(action==='hide-window'){$('app').innerHTML='<div class="hidden-window"><button class="pill glass" data-action="reopen">Reopen Clavis window</button></div>';}
  if(action==='reopen')render();
  if(action==='zoom')document.querySelector('.window')?.classList.toggle('zoomed');
  if(action==='create-profile'){
    showSheet('New application profile','<form id="profile-form"><label class="form-field">Name<input id="profile-name" maxlength="60" required></label><p class="scope-caption">Starts with no applications or key grants.</p></form>','<button class="secondary" data-action="close-sheet">Cancel</button><button form="profile-form" type="submit" class="primary">Create profile</button>');
    $('profile-form').onsubmit=e=>{e.preventDefault();const name=$('profile-name').value.trim();if(!name)return;const id=crypto.randomUUID();profiles.push({id,name,members:[],grants:[]});state.profile=id;state.revision++;$('sheet').close();render();notify('Empty application profile created.');};
  }
});
document.addEventListener('change',e=>{if(e.target.id==='scenario'){state.evidence=e.target.value;if($('sheet').open&&$('scope-content'))updateScope();else render();}});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'&&!$('context-menu').hidden){$('context-menu').hidden=true;menuAnchor?.focus();}
  if(!$('context-menu').hidden&&['ArrowDown','ArrowUp','Home','End'].includes(e.key)){e.preventDefault();const items=[...$('context-menu').querySelectorAll('button')];const current=items.indexOf(document.activeElement);const next=e.key==='Home'?0:e.key==='End'?items.length-1:(current+(e.key==='ArrowDown'?1:-1)+items.length)%items.length;items[next]?.focus();}
  if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();if($('sheet').open)return;if(state.page==='activity')$('history-frame')?.contentWindow.postMessage({type:'clavis-history-focus'},location.protocol==='file:'?'*':location.origin);else $('search')?.focus();}
  if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='n'){e.preventDefault();if(!$('sheet').open)createSheet();}
});
// Navigation studies intentionally omit the earlier application-navigation sidebar.
function studyTabs() {
  return `<nav class="study-tabs" aria-label="Window navigation">${[['keys','key',direction==='drill'?'Keys':'Key settings'],['activity','clock','Activity'],['profiles','grid','Profiles']].map(([page,symbol,label])=>`<button data-action="nav" data-page="${page}" class="${state.page===page?'active':''}" aria-pressed="${state.page===page}">${icon(symbol)}<span>${label}</span></button>`).join('')}</nav>`;
}
function selectedScopeName() {
  return state.page==='activity'&&!state.historyKey?'All keys':keyBy(state.page==='activity'?state.historyKey:state.selected)?.name||'All keys';
}
function sourceItems() {
  return visibleKeys().map(k=>{const active=state.page==='activity'?String(k.id)===state.historyKey:state.page==='keys'&&state.selected===k.id;return `<button class="source-key ${active?'active':''}" data-action="nav-key" data-id="${k.id}" aria-pressed="${active}"><span class="source-key-icon">${icon(k.enabled?'lock':'key')}</span><span class="stack"><strong>${escapeHTML(k.name)}</strong><small>${k.ops.map(o=>opNames[o]).join(' + ')} · P-256</small></span></button>`;}).join('')||'<p class="empty">No matching keys.</p>';
}
function sourcePane() {
  return `<aside class="source-pane ${direction==='compact'?'narrow-source':''}" aria-label="Key source list"><div class="source-titlebar">${traffic()}<div class="spacer"></div><button class="circle" data-action="pause" aria-label="${state.paused?'Resume':'Pause'} signing">${icon(state.paused?'play':'lock')}</button><button class="circle" data-action="create" aria-label="Create key">${icon('plus')}</button></div><div class="source-search">${icon('search')}<input id="search" type="search" placeholder="Search" aria-label="Search keys"></div><div class="source-label row between"><span>Keys</span><span>${keys.length}</span></div><div id="source-items" class="source-items">${sourceItems()}</div><div class="source-bottom"><button class="source-footer-button" data-action="nav" data-page="profiles">${icon('grid')}<span>Application profiles</span>${icon('chevron')}</button><div class="source-agent"><span class="dot ${state.paused?'paused':''}"></span>${state.paused?'Requests paused':'Agent active'}</div></div></aside>`;
}
function keyPickerButton() {
  return `<button class="key-picker-title" data-action="pick-key" aria-haspopup="menu" aria-label="Choose a key"><span class="small-key-icon">${icon('key')}</span><span class="selected-key-title">${escapeHTML(selectedScopeName())}</span>${icon('down')}</button>`;
}
function navigationToolbar() {
  const pageTitle=state.page==='activity'?'Activity':state.page==='profiles'?'Application Profiles':direction==='drill'&&!state.drillOpen?'Keys':keyBy(state.selected).name;
  const source=['reference','compact'].includes(direction);
  const browserBack=direction==='drill'&&state.page==='keys'&&state.drillOpen;
  const leading=source?`<div class="reference-title"><h1>${escapeHTML(pageTitle)}</h1>${state.page==='activity'?'<span class="history-sample">Sample history</span>':''}</div>`:`${traffic()}${browserBack?`<button class="circle" data-action="browse-keys" aria-label="Back to all keys">${icon('back')}</button>`:''}${direction==='titlebar'?keyPickerButton():`<h1>${direction==='strip'?'Clavis':escapeHTML(pageTitle)}</h1>`}`;
  const modeActions=source&&direction==='reference'?`<div class="reference-actions" role="group" aria-label="Window navigation"><button class="circle ${state.page==='keys'?'active':''}" data-action="nav" data-page="keys" aria-label="Key settings" title="Key settings">${icon('key')}</button><button class="circle ${state.page==='activity'?'active':''}" data-action="nav" data-page="activity" aria-label="Activity" title="Activity">${icon('clock')}</button><button class="circle ${state.page==='profiles'?'active':''}" data-action="nav" data-page="profiles" aria-label="Application profiles" title="Application profiles">${icon('grid')}</button></div>`:studyTabs();
  return `<header class="navigation-toolbar ${source?'with-source':''} ${direction==='compact'?'compact-toolbar':''}"><div class="toolbar-leading row">${leading}</div>${direction==='compact'?modeActions:''}<div class="spacer"></div>${direction==='drill'&&state.page==='keys'&&!state.drillOpen?'<input class="browser-search" id="search" type="search" placeholder="Search keys" aria-label="Search keys">':''}${direction==='drill'&&state.page==='activity'?keyPickerButton():''}${direction!=='compact'?modeActions:''}<span class="toolbar-separator"></span><button class="circle" data-action="create" aria-label="Create key" title="Create key">${icon('plus')}</button><button class="circle" data-action="more" aria-label="More actions" title="More actions">${icon('settings')}</button></header>`;
}
function keyStrip() {
  return `<div class="key-strip" role="group" aria-label="Key selection"><button class="strip-all ${state.page==='activity'&&!state.historyKey?'active':''}" data-action="all-key-activity">All keys</button>${keys.map(k=>`<button class="strip-key ${state.page==='activity'?state.historyKey===String(k.id)?'active':'':state.selected===k.id?'active':''}" data-action="nav-key" data-id="${k.id}" aria-pressed="${state.page==='activity'?state.historyKey===String(k.id):state.selected===k.id}">${icon('key')}<span>${escapeHTML(k.name)}</span></button>`).join('')}</div>`;
}
function renderNavigationStudy() {
  const source=['reference','compact'].includes(direction);
  $('app').innerHTML=`<section class="window navigation-window ${direction}" aria-label="Clavis ${navigationNames[direction]} prototype">${source?sourcePane():''}<div class="main">${navigationToolbar()}${direction==='strip'?keyStrip():''}<div id="workspace" class="body"></div><div class="navigation-status"><span>${state.paused?'Requests paused':`${keys.filter(k=>k.enabled).length} keys`}</span><span>${state.page==='activity'?'Signing history':'Private keys stay on this Mac'}</span></div></div></section>`;
  if(state.page==='activity')renderActivity();
  if(state.page==='profiles')renderProfiles();
  if(state.page==='keys'){
    if(direction==='drill'&&!state.drillOpen)renderKeyTable();
    else {$('workspace').className='body navigation-key-detail';$('workspace').innerHTML=keyDetails(keyBy(state.selected));}
  }
  if($('search')){$('search').value=state.search;$('search').oninput=e=>{state.search=e.target.value;if($('source-items'))$('source-items').innerHTML=sourceItems();else if(direction==='drill'&&!state.drillOpen)renderKeyTable();};}
}
function updateNavigationSelection(scope) {
  document.querySelectorAll('.source-key,.strip-key').forEach(button=>{const active=String(button.dataset.id)===String(scope);button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active));});
  document.querySelectorAll('.strip-all').forEach(button=>button.classList.toggle('active',!scope));
  document.querySelectorAll('.selected-key-title').forEach(node=>node.textContent=scope?keyBy(scope).name:'All keys');
}
function changeNavigationKey(id) {
  state.selected=Number(id);
  if(state.page==='activity'&&$('history-frame')){
    state.historyKey=String(id);
    $('history-frame').contentWindow.postMessage({type:'clavis-history-scope',scope:String(id)},location.protocol==='file:'?'*':location.origin);
    updateNavigationSelection(id);
  }else{state.page='keys';state.drillOpen=true;render();}
}
function openKeyPicker(anchor) {
  contextMenu(anchor,`<div class="picker-caption">Choose a key</div><button class="picker-all" role="menuitem" data-action="all-key-activity">${icon('grid')} All keys <small>Activity</small></button>${keys.map(k=>`<button role="menuitem" class="picker-key" data-action="nav-key" data-id="${k.id}">${icon('key')}<span class="stack"><b>${escapeHTML(k.name)}</b><small>${k.ops.map(o=>opNames[o]).join(', ')}</small></span>${state.selected===k.id?icon('check'):''}</button>`).join('')}`);
}
window.addEventListener('message',e=>{
  if(parent!==window&&e.source===parent&&e.data?.type==='clavis-theme-preview'){document.documentElement.dataset.theme=e.data.theme==='dark'?'dark':'light';syncHistory();return;}
  if(e.source!==$('history-frame')?.contentWindow||e.data?.type!=='clavis-history-selected')return;
  state.historyKey=e.data.scope==='all'?null:String(e.data.scope);
  if(state.historyKey)state.selected=Number(state.historyKey);
  if(navigationStudy)updateNavigationSelection(state.historyKey);
});

frame();
