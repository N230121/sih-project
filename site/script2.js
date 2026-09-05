
function unlockTraceMail(source){
  sessionStorage.setItem('tmAuthenticated','1');
  if(source) localStorage.setItem('tmIntakeSource',source);
  const gate=document.getElementById('authGate'); if(gate){gate.classList.add('hidden');gate.setAttribute('aria-hidden','true')}
  document.body.classList.remove('authLocked');
  go('dashboard');
  toast(source==='eml'?'EML evidence loaded — welcome to your workspace':'Welcome to TraceMail AI');
}
function authEmailLogin(){
  const el=document.getElementById('authEmail'),email=(el?.value||'').trim();
  if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){toast('Enter a valid work email');el?.focus();return}
  localStorage.setItem('tmPendingEmail',email);
  unlockTraceMail('email');
}
function authGoogleLogin(){
  const cfg = window.TRACEMAIL_CONFIG || {};
  window.location.href = cfg.OAUTH_START;
}
document.addEventListener('DOMContentLoaded',()=>{
  const gate=document.getElementById('authGate');
  const already=sessionStorage.getItem('tmAuthenticated')==='1';
  if(already){gate?.classList.add('hidden');document.body.classList.remove('authLocked');setTimeout(()=>go('dashboard'),0)}
  const af=document.getElementById('authEml');
  af?.addEventListener('change',async e=>{const f=e.target.files?.[0];if(!f)return;try{const raw=await f.text();const rawEl=document.getElementById('raw');if(rawEl)rawEl.value=raw;localStorage.setItem('tmPendingEml',raw);unlockTraceMail('eml')}catch(err){toast('Unable to read the EML file')}});
});
