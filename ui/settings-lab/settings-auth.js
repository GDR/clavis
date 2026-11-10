'use strict';
// This separate study reuses the window shell. No authentication or persistence occurs.
const authSheet=document.querySelector('#key-auth-sheet');
document.body.appendChild(authSheet);
const authUI=id=>document.getElementById(id);
const authFingerprint=authUI('auth-mark').innerHTML;
const sheetPasswordDrawer=createDemoPasswordDrawer({prefix:'sheet',onVerified:()=>finishAuthChange()});
authSheet.appendChild(sheetPasswordDrawer.element);
new ResizeObserver(()=>{if(authSheet.open)positionAuthSheet();}).observe(authSheet);
let pendingKeyChange=null,authPhase='idle',authCompleted=false,lastAuthField='ssh';
const authOriginalRender=render;
render=function(){authOriginalRender();const control=document.querySelector('#confirmation');if(control){control.disabled=true;control.title='Read-only policy in the current native key inspector';}};
function positionAuthSheet(){const r=document.querySelector('.app-window').getBoundingClientRect();authSheet.style.left=`${r.left+r.width/2}px`;const visibleHeight=authSheet.offsetHeight||416;const ideal=r.top+Math.min(72,Math.max(30,(r.height-visibleHeight)/2));authSheet.style.top=`${Math.max(15,Math.min(ideal,innerHeight-visibleHeight-20))}px`;}
function authSetPhase(phase){
 const passwordWasOpen=sheetPasswordDrawer.isOpen;
 authPhase=phase;authSheet.dataset.phase=phase;
 if(phase==='password'&&!passwordWasOpen)sheetPasswordDrawer.setOpen(true);
 else if(phase!=='password'&&passwordWasOpen)sheetPasswordDrawer.setOpen(false);
 const text={waiting:['Touch ID to apply change','Place your finger on Touch ID.'],failed:['Fingerprint not recognized','Try again. Your settings haven’t changed.'],unavailable:['Touch ID is unavailable','Use your Mac password to continue.'],password:['Verify with a password','Enter the demo password below.'],success:['Change applied','The key settings have been updated.'],'save-error':['Couldn’t apply change','Authentication succeeded, but the change wasn’t saved.']};
 const [title,description]=text[phase]||text.waiting;
 authUI('auth-sim-success').textContent=phase==='password'?'Password accepted':'Touch ID match';
 authUI('auth-status-title').textContent=title;authUI('auth-status-description').textContent=description;
 authUI('auth-mark').innerHTML=phase==='success'?'<svg class="auth-result-icon"><use href="#icon-check"/></svg>':phase==='password'?'<svg class="auth-result-icon"><use href="#icon-lock"/></svg>':authFingerprint;
 authUI('auth-fallback').textContent=phase==='password'?'Use Touch ID':phase==='save-error'?'Try Again': 'Use Password…';
 authUI('auth-fallback').hidden=phase==='success';authUI('auth-cancel').textContent=phase==='success'?'Done':phase==='save-error'?'Close':'Cancel';
 for(const id of ['auth-sim-success','auth-sim-failure','auth-sim-unavailable','auth-sim-save-error'])authUI(id).disabled=!pendingKeyChange||phase==='success'||phase==='save-error';
 const label=phase==='success'?'Applied in this preview only':phase==='save-error'?'Save failed · Original settings preserved':phase==='password'?'Password preview · Enter clavis, then Verify':'Waiting for authentication · Changes are not applied';
 authUI('auth-study-status').textContent=label;
 positionAuthSheet();
}
function beginKeyChange(field,target){
 const key=current();if(key[field]===target)return;
 sheetPasswordDrawer.setOpen(false);lastAuthField=field;pendingKeyChange={id:key.id,field,before:key[field],after:target};authCompleted=false;
 const names={ssh:'SSH authentication',git:'Git signing',profile:'Key profile'};
 authUI('auth-key-tile').innerHTML=tile(key);authUI('auth-key-name').textContent=key.name;authUI('auth-key-kind').textContent=`${key.profile} key`;
 authUI('key-auth-reason').textContent=`Use Touch ID to change settings for “${key.name}”.`;
 authUI('auth-change-label').textContent=names[field];authUI('auth-before').textContent=typeof key[field]==='boolean'?(key[field]?'Enabled':'Disabled'):key[field];authUI('auth-after').textContent=typeof target==='boolean'?(target?'Enabled':'Disabled'):target;
 authUI('auth-impact').textContent=field==='profile'?'Changing the key profile revokes existing approvals.':target?`${field==='ssh'?'SSH authentication':'Git signing'} becomes available under this key’s existing access rules.`:`New ${field==='ssh'?'SSH authentication':'Git signing'} requests for this key will be refused.`;
 document.querySelector('.sidebar').inert=true;document.querySelector('.main-pane').inert=true;document.querySelector('.app-window').classList.add('auth-open');authSheet.show();authSetPhase('waiting');authUI('auth-cancel').focus({preventScroll:true});
}
function replayAuthScenario(){
 if(authSheet.open)authSheet.close();
 const scenario=authUI('auth-scenario').value;const key=current();
 beginKeyChange(scenario,scenario==='profile'?(key.profile==='Personal'?'Bot':'Personal'):!key[scenario]);
}
function finishAuthChange(saveFailure=false){
 if(!pendingKeyChange||authPhase==='success'||authPhase==='save-error')return;
 const pending=pendingKeyChange,key=keys.find(k=>k.id===pending.id);
 if(!key||key[pending.field]!==pending.before){authUI('auth-study-status').textContent='The setting changed while approval was open. Review it again.';authSheet.close();pendingKeyChange=null;return;}
 if(saveFailure){authSetPhase('save-error');return;}
 key[pending.field]=pending.after;if(pending.field==='profile')key.confirmation=key.profile==='Bot'?'Approved sessions':'Strict biometrics';
 authCompleted=true;render();authSetPhase('success');
}
// Capture before the shared fixture mutates settings: the pending value is staged, not saved.
document.addEventListener('change',event=>{
 if(!event.target.matches('#profile,[data-field="ssh"],[data-field="git"]'))return;
 event.stopImmediatePropagation();const field=event.target.id==='profile'?'profile':event.target.dataset.field;const target=field==='profile'?event.target.value:event.target.checked;
 if(field==='profile')event.target.value=current().profile;else event.target.checked=current()[field];
 beginKeyChange(field,target);
},true);
authUI('auth-cancel').onclick=()=>{const changed=authCompleted;sheetPasswordDrawer.setOpen(false);authSheet.close();pendingKeyChange=null;authPhase='idle';authUI('auth-study-status').textContent=changed?'Change applied in the preview · Replay or change another setting':'Cancelled · Original settings preserved';for(const id of ['auth-sim-success','auth-sim-failure','auth-sim-unavailable','auth-sim-save-error'])authUI(id).disabled=true;};
authSheet.addEventListener('close',()=>{if(!authSheet.open){document.querySelector('.sidebar').inert=false;document.querySelector('.main-pane').inert=false;document.querySelector('.app-window').classList.remove('auth-open');requestAnimationFrame(()=>document.querySelector(lastAuthField==='profile'?'#profile':`[data-field="${lastAuthField}"]`)?.focus({preventScroll:true}));}});
document.addEventListener('keydown',event=>{if(event.key==='Escape'&&authSheet.open){event.preventDefault();authUI('auth-cancel').click();}});
authSheet.addEventListener('cancel',event=>{event.preventDefault();authUI('auth-cancel').click();});
authUI('auth-fallback').onclick=()=>{if(authPhase==='save-error'){authCompleted=false;authSetPhase('waiting');}else authSetPhase(authPhase==='password'?'waiting':'password');};
authUI('auth-sim-success').onclick=()=>finishAuthChange();authUI('auth-sim-save-error').onclick=()=>finishAuthChange(true);authUI('auth-sim-failure').onclick=()=>{if(pendingKeyChange)authSetPhase('failed');};authUI('auth-sim-unavailable').onclick=()=>{if(pendingKeyChange)authSetPhase('unavailable');};
authUI('auth-replay').onclick=replayAuthScenario;authUI('auth-scenario').onchange=replayAuthScenario;
authUI('auth-reset').onclick=()=>location.reload();
authUI('auth-appearance').onclick=()=>{const light=document.body.dataset.theme!=='light';document.body.dataset.theme=light?'light':'dark';authUI('auth-appearance').textContent=light?'Dark appearance':'Light appearance';};
window.addEventListener('resize',positionAuthSheet);new ResizeObserver(positionAuthSheet).observe(document.querySelector('.app-window'));
selectHeaderVariant('prominent');selectHeaderLayout('light');render();
// Leave the chosen header/layout in the URL for reproducible review.
replayAuthScenario();
