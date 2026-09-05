
(function(){
  const q=s=>document.querySelector(s), qa=s=>document.querySelectorAll(s);
  function addReveal(){
    qa('.section,.hero,.intakeGrid,.judge-strip,.conf-grid,.tableWrap,.map,.graph').forEach((el,i)=>{el.style.animationDelay=Math.min(i*35,280)+'ms';el.classList.add('tm-reveal')});
  }
  const st=document.createElement('style');st.textContent='.tm-reveal{animation:tmReveal .45s cubic-bezier(.2,.8,.2,1) both}@keyframes tmReveal{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}';document.head.appendChild(st);
  document.addEventListener('DOMContentLoaded',()=>{
    addReveal();
    qa('.nav button').forEach(b=>b.addEventListener('click',()=>setTimeout(addReveal,30)));
    qa('.stat').forEach(el=>{el.addEventListener('mouseenter',()=>el.style.transform='translateY(-4px)');el.addEventListener('mouseleave',()=>el.style.transform='')});
    const badge=q('#modeBadge'); if(badge) badge.title='Demo mode: no external security systems are modified';
  });
})();
