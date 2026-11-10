'use strict';
const $ = s => document.querySelector(s);
const icon = name => `<svg aria-hidden="true"><use href="#icon-${name}"/></svg>`;
const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const keys = [
 {id:1,name:'Github',profile:'Personal',ssh:true,git:true,confirmation:'Strict biometrics',blocked:[],created:'Oct 21, 2026'},
 {id:2,name:'Github Sign',profile:'Bot',ssh:false,git:true,confirmation:'Approved sessions',blocked:[],created:'Oct 24, 2026'}
];
let selected=1, showingHistory=false, allHistory=false, toastTimer, sheetAction;
const current = () => keys.find(key=>key.id===selected);
const purpose = key => key.ssh && key.git ? 'SSH & Git signing' : key.ssh ? 'SSH authentication' : key.git ? 'Git signing' : 'Disabled';
const tile = key => `<span class="key-tile ${key.profile==='Bot'?'bot':''}">${icon(key.profile==='Bot'?'cpu':'person')}</span>`;
function toast(message){clearTimeout(toastTimer);$('#toast').textContent=message;$('#toast').hidden=false;toastTimer=setTimeout(()=>$('#toast').hidden=true,2400);}
function renderList(){
 const query=$('#search').value.toLowerCase().trim();
 const visible=keys.filter(k=>`${k.name} ${k.profile} ${purpose(k)}`.toLowerCase().includes(query));
 $('#key-list').innerHTML=visible.map(key=>`<button class="key-row ${key.id===selected?'selected':''}" data-key="${key.id}" aria-current="${key.id===selected?'true':'false'}">${tile(key)}<span class="key-info"><strong>${escapeHTML(key.name)}</strong><small>${purpose(key)}</small></span></button>`).join('');
 $('#no-results').hidden=visible.length>0;$('#key-count').textContent=keys.length;
 requestAnimationFrame(updateFooterGlass);
}
function switchControl(field,label){return `<label class="switch"><input type="checkbox" role="switch" aria-label="${label}" data-field="${field}" ${current()[field]?'checked':''}><span></span></label>`;}
const headerVariants = {
 balanced:'40px icon · 22px title · A balanced step up from the previous header.',
 prominent:'48px icon · 24px title · More presence for the selected key.',
 badge:'40px icon · 22px title · Key type sits beside the name in a quiet badge.',
 stacked:'44px icon · 23px title · Type, name, and hardware on three distinct lines.',
 quiet:'40px neutral icon · 24px title · Emphasis on the name, with less icon color.'
};
function renderKeyHeader(){
 const key=current(),variant=document.body.dataset.header,layout=document.body.dataset.layout||'current';
 const rename=`<button class="plain icon-only" id="rename" aria-label="Rename key" title="Rename key">${icon('pencil')}</button>`;
 const badge=variant==='badge'?`<span class="header-type-badge">${key.profile}</span>`:'';
 const eyebrow=variant==='stacked'?`<span class="header-eyebrow">${key.profile} key</span>`:'';
 const fullMetadata=`${key.profile} key · Secure Enclave · ECDSA P-256`;
 const metadata=layout==='light'?`${key.profile} · Secure Enclave`:(variant==='badge'||variant==='stacked')?'Secure Enclave · ECDSA P-256':`${key.profile} key · Secure Enclave · ECDSA P-256`;
 $('#key-header').innerHTML=`<div class="hero">${tile(key)}<div>${eyebrow}<h1><span id="key-name">${escapeHTML(key.name)}</span>${badge}${rename}</h1><p title="${fullMetadata}">${metadata}</p></div></div>`;
 $('.header-metadata-strip').textContent=fullMetadata;
 $('.header-metadata-strip').setAttribute('aria-hidden',layout!=='two-tier');
}
function selectHeaderVariant(variant){
 if(!Object.hasOwn(headerVariants,variant))variant='balanced';
 document.body.dataset.header=variant;
 document.querySelectorAll('button[data-header]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.header===variant));
 $('#variant-description').textContent=headerVariants[variant];
 renderKeyHeader();
 const url=new URL(location.href);url.searchParams.set('header',variant);history.replaceState(null,'',url);
}
document.querySelectorAll('button[data-header]').forEach(button=>button.onclick=()=>selectHeaderVariant(button.dataset.header));
function renderInspector(){
 const key=current();
 renderKeyHeader();
 $('#inspector').innerHTML=`<section class="section"><div class="section-heading"><h2>Public Key</h2><a class="link" href="https://github.com/settings/ssh/new" target="_blank" rel="noopener">Add to GitHub…</a></div><div class="group">
 <div class="row"><span class="row-label">Public key</span><span class="value mono" title="Sample public key">ecdsa-sha2-nistp256… ${escapeHTML(key.name)}</span><button class="small-button" data-copy="public">Copy Key</button></div>
 <div class="row"><span class="row-label">Fingerprint</span><span class="value mono">SHA256:jursBOWw1M8…i5LDx0E</span><button class="plain icon-only copy-icon" data-copy="fingerprint" aria-label="Copy fingerprint">${icon('copy')}</button></div>
 <div class="row"><span class="row-label">Public key file</span><span class="value mono">~/.ssh/${key.name.toLowerCase().replace(/\s+/g,'-')}.pub</span><button class="plain icon-only copy-icon" data-copy="path" aria-label="Copy public key file path">${icon('copy')}</button></div></div></section>
 <p class="helper compact-hardware">Algorithm: ECDSA P-256 · Private key stored in Secure Enclave</p><section class="section"><div class="section-heading"><h2>Confirmation</h2></div><div class="group">
 <div class="row"><label for="profile">Key profile</label><select id="profile"><option ${key.profile==='Personal'?'selected':''}>Personal</option><option ${key.profile==='Bot'?'selected':''}>Bot</option></select></div>
 <div class="row"><label for="confirmation">Confirmation level</label><select id="confirmation">${(key.profile==='Personal'?['Strict biometrics','User presence']:['Approved sessions','Every request']).map(c=>`<option ${c===key.confirmation?'selected':''}>${c}</option>`).join('')}</select></div>
 <div class="row"><span class="row-label">SSH authentication</span>${switchControl('ssh','SSH authentication')}</div><div class="row"><span class="row-label">Git signing</span>${switchControl('git','Git signing')}</div></div>
 <p class="helper" id="confirmation-help">${confirmationHelp(key)}</p></section>
 <section class="section"><div class="section-heading"><h2>${key.profile==='Personal'?'Never Allow':'Application Access'}</h2></div><div class="group">
 ${key.blocked.length?key.blocked.map((app,index)=>`<div class="row app-row"><span class="app-icon">${app==='Terminal'?'›_':'⌘'}</span><span>${escapeHTML(app)}</span><button class="plain icon-only copy-icon" data-remove-app="${index}" aria-label="Remove ${escapeHTML(app)}" style="margin-left:auto">${icon('minus')}</button></div>`).join(''):`<div class="empty-apps">${key.profile==='Personal'?'No blocked applications':'No applications configured'}<small>${key.profile==='Personal'?'Personal apps can request confirmation.':'Add an application to configure access for this bot key.'}</small></div>`}
 <div class="list-footer"><button class="plain icon-only" id="add-app" aria-label="Add application">${icon('plus')}</button><span class="divider"></span><button class="plain icon-only" disabled aria-label="Remove selected application">${icon('minus')}</button></div></div></section>
 <section class="section"><div class="section-heading"><h2>Recent Activity</h2><button class="link" id="show-history">Show All History…</button></div><div class="group"><div class="row"><span>Created</span><span class="value">${key.created}</span></div><div class="row"><span>Last used</span><span class="value">Today at 00:46</span></div></div></section>
 <div class="danger-row"><span>The private key never leaves your Mac.</span><button id="delete-key">Delete Key…</button></div>`;
}
function confirmationHelp(key){return key.profile==='Bot'?'Sample session policy. Access changes in this preview are temporary.':key.confirmation==='Strict biometrics'?'Touch ID only. Invalidated if enrolled fingerprints change.':'Confirm each request with Touch ID or your Mac password.';}
function renderHistory(){
 const key=current();$('#history-view').innerHTML=`<h1 class="history-heading">History</h1><p class="history-subtitle">Activity for ${allHistory?'all keys':escapeHTML(key.name)} <button class="link" id="all-keys">${allHistory?'· Show selected key':'· Show all keys'}</button></p><div class="section-heading"><h2>Today</h2><span class="history-status">${icon('shield')}Sample activity</span></div><div class="group">${['SSH authentication','Git commit signed','SSH authentication'].map((event,i)=>`<div class="activity"><span class="activity-icon">${icon('check')}</span><div><strong>${event}</strong><p>${escapeHTML(allHistory?keys[i%keys.length].name:key.name)} · ${i===1?'Visual Studio Code':'Terminal'} · Approved</p></div><time>${['00:46','00:32','00:18'][i]}</time></div>`).join('')}</div><p class="helper">Illustrative events only. This prototype does not read Clavis history.</p>`;
}
function render(){renderList();renderInspector();renderHistory();$('#inspector').hidden=showingHistory;$('#history-view').hidden=!showingHistory;$('#back').hidden=!showingHistory;$('#history').hidden=showingHistory;}
function setHistory(value){if(value)allHistory=false;showingHistory=value;render();$('#content').scrollTop=0;}
function openSheet(title,content,actionLabel,action){
 $('#sheet-content').innerHTML=`<h2>${title}</h2>${content}`;$('#submit-sheet').textContent=actionLabel;sheetAction=action;$('#sheet').showModal();
}
$('#sheet-form').addEventListener('submit',event=>{event.preventDefault();if(sheetAction()!==false)$('#sheet').close();});
$('#sheet').addEventListener('input',event=>{if(event.target instanceof HTMLInputElement)event.target.setCustomValidity('');});
$('#cancel-sheet').onclick=()=>$('#sheet').close();
function newKey(){openSheet('New key','<p>Create a sample key to explore the layout.</p><label>Key name<input id="new-name" placeholder="e.g. Work" maxlength="60" required autofocus></label><label>Key profile<select id="new-profile"><option>Personal</option><option>Bot</option></select></label>','Create key',()=>{
 const name=$('#new-name').value.trim();if(!name){$('#new-name').setCustomValidity('Enter a key name.');$('#new-name').reportValidity();return false;}
 const profile=$('#new-profile').value;const id=Math.max(...keys.map(k=>k.id))+1;keys.push({id,name,profile,ssh:true,git:true,confirmation:profile==='Personal'?'Strict biometrics':'Approved sessions',blocked:[],created:'Today'});selected=id;showingHistory=false;$('#search').value='';render();toast('Sample key created');
 });}
$('#new-key').onclick=newKey;$('#search').addEventListener('input',renderList);
$('#key-list').onclick=event=>{const row=event.target.closest('[data-key]');if(row){selected=Number(row.dataset.key);allHistory=false;render();$('#content').scrollTop=0;}};
$('#history').onclick=()=>setHistory(true);$('#back').onclick=()=>setHistory(false);
$('#lock').onclick=()=>{$('#lock-screen').hidden=false;$('.sidebar').inert=true;$('.main-pane').inert=true;$('#unlock').focus();};
$('#unlock').onclick=()=>{$('#lock-screen').hidden=true;$('.sidebar').inert=false;$('.main-pane').inert=false;$('#lock').focus();toast('Preview unlocked');};
$('#inspector').addEventListener('change',event=>{
 const key=current();if(event.target.dataset.field){key[event.target.dataset.field]=event.target.checked;renderList();}
 if(event.target.id==='profile'){key.profile=event.target.value;key.confirmation=key.profile==='Bot'?'Approved sessions':'Strict biometrics';render();}
 if(event.target.id==='confirmation'){key.confirmation=event.target.value;$('#confirmation-help').textContent=confirmationHelp(key);}
});
$('.main-pane').addEventListener('click',async event=>{
 const key=current(),button=event.target.closest('button');if(!button)return;
 if(button.dataset.copy){
 const type=button.dataset.copy;const value=type==='public'?`ecdsa-sha2-nistp256 SAMPLE-PUBLIC-KEY-ONLY ${key.name}`:type==='fingerprint'?'SHA256:SAMPLE-FINGERPRINT-ONLY':`~/.ssh/${key.name.toLowerCase().replace(/\s+/g,'-')}.pub`;
 try{await navigator.clipboard.writeText(value);toast('Sample '+(type==='path'?'path':type==='public'?'public key':'fingerprint')+' copied');}catch{toast('Clipboard unavailable in this browser');}
 }
 if(button.id==='show-history')setHistory(true);
 if(button.id==='rename'){
 const target=$('#key-name'),input=document.createElement('input');input.className='rename-input';input.value=key.name;input.maxLength=60;input.setAttribute('aria-label','Key name');target.replaceWith(input);input.focus();input.select();let finished=false;
 const finish=save=>{if(finished)return;finished=true;if(save&&input.value.trim())key.name=input.value.trim();render();};input.onblur=()=>finish(true);input.onkeydown=e=>{if(e.key==='Enter')finish(true);if(e.key==='Escape')finish(false);};
 }
 if(button.id==='add-app')openSheet(key.profile==='Personal'?'Block application':'Add application','<p>Choose a sample application. This only changes the preview.</p><label>Application<select id="app-choice"><option>Terminal</option><option>Visual Studio Code</option><option>iTerm</option></select></label>','Add',()=>{const app=$('#app-choice').value;if(!key.blocked.includes(app))key.blocked.push(app);renderInspector();});
 if(button.dataset.removeApp!==undefined){key.blocked.splice(Number(button.dataset.removeApp),1);renderInspector();}
 if(button.id==='delete-key')openSheet('Delete sample key?',`<p>Remove “${escapeHTML(key.name)}” from this preview? Reloading restores the original sample keys.</p>`,'Delete',()=>{if(keys.length===1){toast('Keep one sample key to explore the layout');return;}keys.splice(keys.indexOf(key),1);selected=keys[0].id;render();toast('Sample key removed');});
});
$('#history-view').onclick=event=>{if(event.target.closest('#all-keys')){allHistory=!allHistory;renderHistory();}};
$('#settings').onclick=()=>{openSheet('Clavis Settings','<p>Appearance controls are below the window in this design study. Native settings would open in a separate settings view.</p><p>All key and policy changes here are held in memory and reset on reload.</p>','Done',()=>{});$('#cancel-sheet').hidden=true;};
$('#sheet').addEventListener('close',()=>$('#cancel-sheet').hidden=false);
document.querySelectorAll('[data-theme]').forEach(button=>{if(button.tagName!=='BUTTON')return;button.onclick=()=>{document.body.dataset.theme=button.dataset.theme;document.querySelectorAll('button[data-theme]').forEach(b=>b.setAttribute('aria-pressed',b===button));};});
document.querySelectorAll('button[data-wallpaper]').forEach(button=>button.onclick=()=>{document.body.dataset.wallpaper=button.dataset.wallpaper;document.querySelectorAll('button[data-wallpaper]').forEach(b=>b.setAttribute('aria-pressed',b===button));});
$('#material').onchange=event=>document.body.dataset.material=event.target.value;
$('#inactive').onchange=event=>document.body.classList.toggle('inactive',event.target.checked);
$('#show-notes').onclick=()=>$('#notes').showModal();$('#close-notes').onclick=()=>$('#notes').close();
document.addEventListener('keydown',event=>{if(!(event.metaKey||event.ctrlKey)||$('dialog[open]')||!$('#lock-screen').hidden)return;if(event.key==='f'){event.preventDefault();$('#search').focus();}if(event.key==='n'){event.preventDefault();newKey();}if(event.key==='l'){event.preventDefault();$('#lock').click();}});
selectHeaderVariant(new URLSearchParams(location.search).get('header')||'balanced');
render();

$('#content').addEventListener('scroll',()=>$('.toolbar').classList.toggle('scrolled',$('#content').scrollTop>3),{passive:true});

// Keep the sidebar background untouched; graduate only the glass over underlapping rows.
function updateFooterGlass(){
 const footer=$('.sidebar-footer'),region=footer.getBoundingClientRect();
 const underlap=[...document.querySelectorAll('#key-list .key-row')].some(row=>{const r=row.getBoundingClientRect();return r.bottom>region.top-20&&r.top<region.bottom;});
 footer.classList.toggle('has-underlap',underlap);
}
$('#key-list').addEventListener('scroll',updateFooterGlass,{passive:true});
new ResizeObserver(updateFooterGlass).observe($('.sidebar'));

const headerLayouts={current:'56px bar · Original two-line identity',comfortable:'64px bar · More vertical padding, same identity size',light:'56px bar · Smaller identity and shorter metadata', 'two-tier':'56px action row + 24px metadata strip · Controls stay close to the top'};
function selectHeaderLayout(layout){
 if(!Object.hasOwn(headerLayouts,layout))layout='current';
 document.body.dataset.layout=layout;
 document.querySelectorAll('button[data-layout]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.layout===layout));
 $('#layout-description').textContent=headerLayouts[layout];
 renderKeyHeader();
 const url=new URL(location.href);if(layout==='current')url.searchParams.delete('layout');else url.searchParams.set('layout',layout);history.replaceState(null,'',url);
}
document.querySelectorAll('button[data-layout]').forEach(b=>b.onclick=()=>selectHeaderLayout(b.dataset.layout));
selectHeaderLayout(new URLSearchParams(location.search).get('layout')||'current');
