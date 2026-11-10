'use strict';
// Local prototype validation only. Never send or persist password input.
function createDemoPasswordDrawer({prefix,onVerified}){
 const drawer=document.createElement('div');drawer.className='demo-password-drawer';drawer.hidden=true;
 drawer.innerHTML=`<div class="demo-password-inner"><form class="demo-password-form" novalidate><div class="demo-password-entry"><input id="${prefix}-demo-password" type="password" aria-label="Demo password" aria-describedby="${prefix}-password-hint ${prefix}-password-error" placeholder="Demo password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="64" disabled><button type="submit">Verify</button></div><p class="demo-password-hint" id="${prefix}-password-hint">Preview password: <code>clavis</code></p><p class="demo-password-error" id="${prefix}-password-error" role="alert" hidden></p></form></div>`;
 const input=drawer.querySelector('input'),form=drawer.querySelector('form'),error=drawer.querySelector('.demo-password-error');
 let open=false,hideTimer;
 function reset(){input.value='';input.removeAttribute('aria-invalid');error.hidden=true;error.textContent='';}
 function setOpen(value,{focus=true}={}){
  clearTimeout(hideTimer);open=value;
  if(value){drawer.hidden=false;input.disabled=false;reset();requestAnimationFrame(()=>{if(open){drawer.classList.add('is-open');if(focus)input.focus({preventScroll:true});}});}
  else{drawer.classList.remove('is-open');input.disabled=true;reset();hideTimer=setTimeout(()=>{if(!open)drawer.hidden=true;},180);}
 }
 form.addEventListener('submit',event=>{
  event.preventDefault();if(!open)return;
  if(input.value!=='clavis'){
   error.textContent=input.value?'Password didn’t match. Use clavis for this preview.':'Enter the demo password: clavis.';error.hidden=false;input.setAttribute('aria-invalid','true');input.focus({preventScroll:true});input.select();return;
  }
  reset();onVerified();
 });
 input.addEventListener('input',()=>{input.removeAttribute('aria-invalid');error.hidden=true;error.textContent='';});
 return {element:drawer,setOpen,reset,get isOpen(){return open;}};
}
