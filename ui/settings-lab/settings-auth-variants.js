'use strict';
const av=id=>document.getElementById(id);
const approvalDirections={
 1:{name:'Morphing capsule',description:'A sliding glass capsule with a biometric end-cap and an expanding password field.',width:358,glass:true},
 2:{name:'Authentication drawer',description:'A bottom glass drawer with a separate biometric well and an explicit authentication button.',width:364,glass:true},
 3:{name:'Access rail',description:'A narrow sliding glass panel with a dedicated Touch ID control.',width:252,glass:true},
 4:{name:'Control morph',description:'An inline authentication row that takes the place of the initiating control.',width:0},
 5:{name:'Inline authentication',description:'An inline request with a primary Touch ID action and password fallback.',width:0},
 6:{name:'Command palette',description:'A keyboard-first choice between Touch ID and password.',width:332},
 7:{name:'Authentication tile',description:'A centered fingerprint tile with a full-width password fallback.',width:256},
 8:{name:'Authentication request',description:'A compact authentication request with Touch ID and password fallback.',width:302}
};
const avFinger='<svg viewBox="0 0 40 44" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M7 14C10 1 30 1 34 14M4 21C4 1 37 1 37 21M8 22c0-17 25-17 25 0 0 6-1 12-3 17M12 22c0-11 17-11 17 0 0 8-1 14-4 19M16 22c0-6 9-6 9 0 0 8-1 13-4 18M20 21c0 10-1 16-4 20M4 25c0 5-1 9-2 11M8 25c0 6-1 11-3 15M12 25c0 7-1 13-3 16M16 26c0 5-1 10-3 15M34 27c0 4-1 8-2 12M37 27c0 3 0 5-1 8"/></g></svg>';
let approvalVariant='1',approvalPending=null,approvalPhase='idle',approvalHideTimer;
const approvalPanel=document.createElement('section');approvalPanel.className='approval-panel';approvalPanel.id='approval-panel';approvalPanel.hidden=true;approvalPanel.tabIndex=-1;
approvalPanel.setAttribute('role','dialog');approvalPanel.setAttribute('aria-labelledby','approval-intent');approvalPanel.setAttribute('aria-describedby','approval-status');
document.querySelector('.app-window').appendChild(approvalPanel);
const approvalPasswordDrawer=createDemoPasswordDrawer({prefix:'approval',onVerified:()=>approvalCommit()});
new ResizeObserver(()=>{if(!approvalPanel.hidden)approvalPlace();}).observe(approvalPanel);
approvalPanel.addEventListener('transitionend',event=>{if(event.target===approvalPanel&&approvalPanel.dataset.visible==='true')approvalPanel.dataset.settled='true';});
const approvalBaseRender=render;
render=function(){if(approvalPanel.closest('#inspector'))document.querySelector('.app-window').appendChild(approvalPanel);approvalBaseRender();const control=document.querySelector('#confirmation');if(control){control.disabled=true;control.title='Read-only policy in the native inspector';}approvalMarkSource();};
const approvalFieldName=field=>({ssh:'SSH authentication',git:'Git signing',profile:'Key profile'}[field]);
const approvalValue=value=>typeof value==='boolean'?(value?'Enabled':'Disabled'):value;
const approvalStatusHTML=()=>'<span id="approval-status" class="approval-status" role="status" aria-live="polite"></span>';
const approvalFingerHTML=()=>`<span class="approval-finger" id="approval-finger">${avFinger}</span>`;
const approvalPasswordHTML=()=>'<button id="approval-password" class="approval-password" data-approval-action="password">Password…</button>';
const approvalCancelHTML=(x=false)=>`<button id="approval-cancel" class="approval-cancel ${x?'cancel-x':''}" data-approval-action="cancel" aria-label="Cancel pending change">${x?'×':'Cancel'}</button>`;
const approvalStartHTML=(text='Use Touch ID')=>`<button class="approval-start" data-approval-action="touch">${icon('shield')}<span>${text}</span></button>`;
function approvalTemplate(){
 if(!approvalPending)return;
 const p=approvalPending,key=keys.find(k=>k.id===p.id);if(!key)return;
 const intent='<h2 id="approval-intent">Authentication required</h2>';
 const instruction='<p class="authentication-request-copy" id="approval-change">Use Touch ID or enter your password to continue.</p>';
 const password=approvalPasswordHTML(),finger=approvalFingerHTML(),status=approvalStatusHTML();
 let markup='';
 if(approvalVariant==='1')markup=`<div class="capsule-lane"><div class="capsule-copy">${intent}${instruction}</div><div class="capsule-auth">${finger}</div>${approvalCancelHTML(true)}</div><div class="capsule-under">${status}${password}</div>`;
 if(approvalVariant==='2')markup=`<div class="review-heading">${intent}${approvalCancelHTML(true)}</div><div class="review-split"><div class="review-content">${instruction}<div class="review-actions">${approvalStartHTML()}${password}</div></div><div class="review-biometric">${finger}${status}</div></div>`;
 if(approvalVariant==='3')markup=`<div class="request-heading">${intent}${approvalCancelHTML(true)}</div>${instruction}<button class="rail-biometric" data-approval-action="touch">${finger}<span>${status}<small>Place your finger on Touch ID</small></span></button><div class="rail-footer">${password}</div>`;
 if(approvalVariant==='4')markup=`<div class="morph-row"><div class="morph-copy">${intent}${instruction}</div><button class="morph-biometric" data-approval-action="touch" aria-label="Authenticate with Touch ID">${finger}</button>${approvalCancelHTML(true)}</div><div class="morph-status">${status}${password}</div>`;
 if(approvalVariant==='5')markup=`<div class="request-heading">${intent}${approvalCancelHTML(true)}</div>${instruction}<div class="receipt-actions">${approvalStartHTML()}${password}</div><div class="receipt-status">${finger}${status}</div>`;
 if(approvalVariant==='6')markup=`<div class="command-breadcrumb"><span class="command-glyph">⌘</span>${intent}${approvalCancelHTML(true)}</div><div class="command-intent">${instruction}</div><div class="command-methods" role="group" aria-label="Authentication method"><button data-approval-action="touch" class="command-method" data-method="touch">${finger}<span>Authenticate with Touch ID<small id="approval-status" class="approval-status" role="status" aria-live="polite"></small></span><kbd>↵</kbd></button><button data-approval-action="password" class="command-method" id="approval-password" data-method="password">${icon('lock')}<span>Use password</span><kbd>↓</kbd></button></div><div class="command-hint"><kbd>↑</kbd><kbd>↓</kbd><span>Choose a method</span><kbd>esc</kbd><span>Cancel</span></div>`;
 if(approvalVariant==='7')markup=`<div class="tile-dismiss">${approvalCancelHTML(true)}</div><div class="auth-tile-symbol">${finger}</div>${intent}${status}<div class="tile-actions">${password}</div>`;
 if(approvalVariant==='8')markup=`<div class="connected-header">${intent}${approvalCancelHTML(true)}</div>${instruction}<div class="connected-footer"><span class="settings-auth-cue">${finger}${status}</span>${password}</div>`;
 approvalPasswordDrawer.element.remove();approvalPanel.innerHTML=markup;approvalPanel.appendChild(approvalPasswordDrawer.element);
}
function approvalSource(){return approvalPending?document.querySelector(approvalPending.field==='profile'?'#profile':`[data-field="${approvalPending.field}"]`)?.closest('.row'):null;}
function approvalMarkSource(){document.querySelectorAll('.approval-source').forEach(e=>e.classList.remove('approval-source'));if(approvalPending&&approvalPhase!=='success')approvalSource()?.classList.add('approval-source');}
function approvalBlockWindow(block){document.querySelector('.sidebar').inert=block;document.querySelector('.toolbar').inert=block;document.querySelectorAll('#inspector button,#inspector input,#inspector select,#inspector a').forEach(e=>{if(!approvalPanel.contains(e))e.inert=block;});}
function approvalPlace(){
 if(approvalPanel.hidden)return;
 const w=document.querySelector('.app-window'),wr=w.getBoundingClientRect(),mr=document.querySelector('.main-pane').getBoundingClientRect(),d=approvalDirections[approvalVariant];
 const mainX=mr.left-wr.left-1,mainW=mr.width,width=Math.min(d.width||mainW-24,mainW-24);
 if(['4','5'].includes(approvalVariant)&&approvalPending){const source=approvalSource();if(source&&approvalPanel.previousElementSibling!==source)source.after(approvalPanel);approvalPanel.style.width='';approvalPanel.style.left='';approvalPanel.style.top='';const viewport=document.querySelector('#content'),pr=approvalPanel.getBoundingClientRect(),vr=viewport.getBoundingClientRect();if(pr.bottom>vr.bottom-10)viewport.scrollTop+=pr.bottom-vr.bottom+10;else if(pr.top<vr.top+62)viewport.scrollTop-=vr.top+62-pr.top;return;}
 if(approvalPanel.parentElement!==w)w.appendChild(approvalPanel);
 approvalPanel.style.width=`${width}px`;const height=approvalPanel.offsetHeight,maxTop=Math.max(58,w.clientHeight-height-12);
 let left=mainX+(mainW-width)/2,top=67;
 if(approvalVariant==='2')top=w.clientHeight-height-16;
 if(approvalVariant==='3'){left=w.clientWidth-width-14;top=70;}
 if(approvalVariant==='6')top=76;
 if(approvalVariant==='7')top=74;
 if(approvalVariant==='8')top=74;
 approvalPanel.style.left=`${Math.max(mainX+10,left)}px`;approvalPanel.style.top=`${Math.max(56,Math.min(top,maxTop))}px`;
}
function approvalSetPhase(phase){
 const wasOpen=approvalPasswordDrawer.isOpen;approvalPhase=phase;approvalPanel.dataset.phase=phase;
 if(phase==='password'&&!wasOpen)approvalPasswordDrawer.setOpen(true);else if(phase!=='password'&&wasOpen)approvalPasswordDrawer.setOpen(false);
 const status={review:'Review before authenticating',choose:'Choose an authentication method',ready:'Authentication required',waiting:'Touch ID to confirm',failed:'Not recognized · Try again',unavailable:'Touch ID unavailable',password:'Enter demo password',success:'Change applied','save-error':'Not saved · Try again'};
 av('approval-status').textContent=phase==='success'?'Authentication complete':phase==='waiting'?'Waiting for Touch ID':status[phase]||status.waiting;
 av('approval-intent').textContent=phase==='success'?'Authenticated':'Authentication required';
 av('approval-finger').innerHTML=phase==='success'?'<svg class="result-icon"><use href="#icon-check"/></svg>':phase==='password'?'<svg class="result-icon"><use href="#icon-lock"/></svg>':avFinger;
 const password=av('approval-password');password.hidden=phase==='success';
 if(approvalVariant==='6')password.querySelector('span').textContent=phase==='password'?'Return to Touch ID':phase==='save-error'?'Try again':'Use password';
 else password.textContent=phase==='password'?'Touch ID':phase==='save-error'?'Retry':'Password…';
 const cancel=av('approval-cancel');cancel.setAttribute('aria-label',phase==='success'?'Close approval result':'Cancel pending change');

 av('auth-sim-success').textContent=phase==='password'?'Password accepted':'Touch ID match';
 for(const id of ['auth-sim-success','auth-sim-failure','auth-sim-unavailable','auth-sim-save-error'])av(id).disabled=!approvalPending||['success','save-error','review','choose','ready'].includes(phase);
 av('auth-study-status').textContent=phase==='success'?'Applied in this preview only':phase==='save-error'?'Authentication succeeded · Save failed · Original setting preserved':phase==='password'?'Password preview · Enter clavis, then Verify':['review','choose','ready'].includes(phase)?'Review the change and choose an authentication action':'Pending change · Original setting remains effective';
 approvalMarkSource();approvalPlace();
}
function approvalInitialPhase(){return approvalVariant==='6'?'choose':['2','3','4','5'].includes(approvalVariant)?'ready':'waiting';}
function approvalReveal(){
 clearTimeout(approvalHideTimer);approvalPanel.classList.add('resetting');approvalPanel.dataset.settled='false';approvalPanel.dataset.visible='false';approvalPanel.hidden=false;approvalPanel.dataset.approval=approvalVariant;approvalPanel.classList.toggle('glass',!!approvalDirections[approvalVariant].glass);
 approvalTemplate();approvalPlace();approvalBlockWindow(true);void approvalPanel.offsetWidth;
 requestAnimationFrame(()=>requestAnimationFrame(()=>{if(approvalPending){approvalPanel.classList.remove('resetting');approvalPanel.dataset.visible='true';if(matchMedia('(prefers-reduced-motion: reduce)').matches)approvalPanel.dataset.settled='true';const target=approvalPasswordDrawer.isOpen?approvalPanel.querySelector('.demo-password-entry input'):approvalVariant==='6'?approvalPanel.querySelector('[data-method="touch"]'):approvalPanel;target.focus({preventScroll:true});}}));
}
function approvalBegin(field,target){const key=current();if(key[field]===target)return;approvalPasswordDrawer.setOpen(false);approvalPending={id:key.id,field,before:key[field],after:target};approvalPhase=approvalInitialPhase();approvalReveal();approvalSetPhase(approvalPhase);}
function approvalReplay(){if(approvalPending&&approvalPhase!=='success'){approvalPasswordDrawer.setOpen(false);approvalReveal();approvalSetPhase(approvalInitialPhase());return;}const f=av('auth-scenario').value,k=current();approvalBegin(f,f==='profile'?(k.profile==='Personal'?'Bot':'Personal'):!k[f]);}
function approvalCancel(){const pending=approvalPending,applied=approvalPhase==='success';approvalPasswordDrawer.setOpen(false);approvalPanel.dataset.visible='false';approvalPending=null;approvalPhase='idle';approvalBlockWindow(false);approvalMarkSource();if(['4','5'].includes(approvalVariant)){approvalPanel.hidden=true;document.querySelector('.app-window').appendChild(approvalPanel);}else approvalHideTimer=setTimeout(()=>{if(!approvalPending)approvalPanel.hidden=true;},280);av('auth-study-status').textContent=applied?'Change applied in the preview':'Cancelled · Original setting preserved';for(const id of ['auth-sim-success','auth-sim-failure','auth-sim-unavailable','auth-sim-save-error'])av(id).disabled=true;if(pending)document.querySelector(pending.field==='profile'?'#profile':`[data-field="${pending.field}"]`)?.focus({preventScroll:true});}
function approvalCommit(saveError=false){if(!approvalPending||['success','save-error','review','choose','ready'].includes(approvalPhase))return;const p=approvalPending,k=keys.find(k=>k.id===p.id);if(!k||k[p.field]!==p.before){approvalCancel();av('auth-study-status').textContent='Setting changed · Review a new request';return;}if(saveError){approvalSetPhase('save-error');return;}k[p.field]=p.after;if(p.field==='profile')k.confirmation=k.profile==='Bot'?'Approved sessions':'Strict biometrics';render();approvalSetPhase('success');approvalBlockWindow(true);}
function chooseApprovalVariant(variant){if(!Object.hasOwn(approvalDirections,variant))variant='1';approvalVariant=variant;approvalPasswordDrawer.reset();document.querySelectorAll('button[data-approval]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.approval===variant));av('approval-variant-description').textContent=approvalDirections[variant].description;const url=new URL(location.href);url.searchParams.set('approval',variant);history.replaceState(null,'',url);if(approvalPending){approvalPasswordDrawer.setOpen(false);approvalReveal();approvalSetPhase(approvalPhase==='success'?'success':approvalInitialPhase());}else approvalReplay();}
function approvalAction(action){if(action==='cancel')approvalCancel();if(action==='password')approvalSetPhase(approvalPhase==='save-error'?'waiting':approvalPhase==='password'?'waiting':'password');if(action==='touch'&&approvalPhase!=='success')approvalSetPhase('waiting');if(action==='continue'){if(approvalPhase==='success')approvalCancel();else approvalSetPhase(approvalPhase==='review'||approvalPhase==='save-error'?'waiting':'review');}}
approvalPanel.addEventListener('click',event=>{const button=event.target.closest('[data-approval-action]');if(button)approvalAction(button.dataset.approvalAction);});
approvalPanel.addEventListener('keydown',event=>{if(approvalVariant!=='6'||!event.target.closest('.command-method'))return;if(['ArrowDown','ArrowUp'].includes(event.key)){event.preventDefault();const methods=[...approvalPanel.querySelectorAll('.command-method')],index=methods.indexOf(event.target.closest('.command-method'));methods[(index+(event.key==='ArrowDown'?1:methods.length-1))%methods.length].focus();}});
document.querySelectorAll('button[data-approval]').forEach(b=>b.onclick=()=>chooseApprovalVariant(b.dataset.approval));
document.addEventListener('change',event=>{if(!event.target.matches('#profile,[data-field="ssh"],[data-field="git"]'))return;event.stopImmediatePropagation();const field=event.target.id==='profile'?'profile':event.target.dataset.field,target=field==='profile'?event.target.value:event.target.checked;if(field==='profile')event.target.value=current().profile;else event.target.checked=current()[field];approvalBegin(field,target);},true);
document.addEventListener('keydown',event=>{if(!approvalPending)return;if(event.key==='Escape'){event.preventDefault();event.stopImmediatePropagation();approvalCancel();}else if((event.metaKey||event.ctrlKey)&&['n','l','f',',','h'].includes(event.key.toLowerCase())){event.preventDefault();event.stopImmediatePropagation();}},true);
av('auth-sim-success').onclick=()=>approvalCommit();av('auth-sim-save-error').onclick=()=>approvalCommit(true);av('auth-sim-failure').onclick=()=>approvalSetPhase('failed');av('auth-sim-unavailable').onclick=()=>approvalSetPhase('unavailable');av('auth-replay').onclick=approvalReplay;
av('auth-scenario').onchange=()=>{if(approvalPending)approvalCancel();const f=av('auth-scenario').value,k=current();approvalBegin(f,f==='profile'?(k.profile==='Personal'?'Bot':'Personal'):!k[f]);};av('auth-reset').onclick=()=>location.reload();av('auth-appearance').onclick=()=>{const light=document.body.dataset.theme!=='light';document.body.dataset.theme=light?'light':'dark';av('auth-appearance').textContent=light?'Dark appearance':'Light appearance';};
window.addEventListener('resize',approvalPlace);document.querySelector('#content').addEventListener('scroll',approvalPlace,{passive:true});new ResizeObserver(approvalPlace).observe(document.querySelector('.app-window'));
selectHeaderVariant('prominent');selectHeaderLayout('light');render();chooseApprovalVariant(new URLSearchParams(location.search).get('approval')||'1');

av('show-notes').onclick=()=>{av('notes').innerHTML='<button class="plain close-notes" id="approval-references-close" aria-label="Close references">×</button><p class="eyebrow">RESEARCH / 2026-11-05</p><h1>Different structures.<br>Different interactions.</h1><p>Apple: contextual surfaces and functional glass. Raycast: keyboard-first actions. 1Password: focused biometric hierarchy. These are Clavis explorations, not copies of those interfaces.</p><div class="note-grid"><div><b>Apple</b><p><a href="https://developer.apple.com/design/human-interface-guidelines/popovers/" target="_blank" rel="noopener">Contextual popovers ↗</a><br><a href="https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass" target="_blank" rel="noopener">Adopting Liquid Glass ↗</a></p></div><div><b>Product references</b><p><a href="https://manual.raycast.com/action-panel" target="_blank" rel="noopener">Raycast Action Panel ↗</a><br><a href="https://support.1password.com/touch-id-mac/" target="_blank" rel="noopener">1Password Touch ID ↗</a></p></div></div><a href="settings-auth-design-research.md" target="_blank" rel="noopener">Full sources and design rationale ↗</a>';av('notes').showModal();av('approval-references-close').onclick=()=>av('notes').close();};
