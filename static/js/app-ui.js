window.AppUI = (() => {
  const toastEl = () => document.getElementById('app-toast');
  const toast = (msg) => { const el = toastEl(); if(!el) return; el.textContent = msg; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'), 2200); };

  async function initAnnouncements(url) {
    const target = document.getElementById('announcement-content');
    if (!target) return;
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error();
      const data = await res.json();
      if (!Array.isArray(data) || !data.length) { target.textContent = 'Keine Ankündigungen vorhanden.'; return; }
      let i = 0;
      const render = () => { const a = data[i]; target.innerHTML = `<strong>${a.title}</strong><br>${a.content}<br><small>Quelle: ${a.source}</small>`; i = (i + 1) % data.length; };
      render(); setInterval(render, 7000);
    } catch { target.textContent = 'Fehler beim Laden der Ankündigungen.'; }
  }

  function initTrainings(){
    const upcoming = document.getElementById('upcoming-list'); const filter = document.getElementById('training-filter'); const cal = document.getElementById('calendar');
    if(!upcoming || !cal) return;
    const calendar = new FullCalendar.Calendar(cal,{initialView:'dayGridMonth',locale:'de',events:'/api/trainings',eventClick:(info)=>toast(info.event.title||'Schulung')});
    calendar.render();
    const load = async ()=>{ try{ const r=await fetch('/api/trainings/upcoming'); const items=await r.json();
      const q=(filter?.value||'').toLowerCase(); upcoming.innerHTML='';
      (items||[]).filter(x=>`${x.title||''} ${(x.participants||[]).join(' ')}`.toLowerCase().includes(q)).forEach(it=>{const li=document.createElement('li');li.className='list-group-item';li.textContent=`${it.date||''} – ${it.title||''}${it.time?`, ${it.time}`:''}`;upcoming.appendChild(li);});
      if(!upcoming.children.length){upcoming.innerHTML='<li class="list-group-item">Keine Treffer.</li>'}
    }catch{upcoming.innerHTML='<li class="list-group-item">Fehler beim Laden.</li>';}};
    filter?.addEventListener('input', load); load(); setInterval(()=>{calendar.refetchEvents(); load();},30000);
  }

  function initQualiMatrix(images){
    const slider = document.getElementById('qm-slider-wrap'); const grid = document.getElementById('qm-grid-wrap');
    const hero = document.getElementById('qm-hero-img'); const caption = document.getElementById('qm-hero-caption');
    if(!slider || !grid) return;
    let i=0; const render=()=>{ if(!images?.length) return; const it=images[i]; hero.src=it.src; caption.textContent=`${it.label} – ${it.name}`; i=(i+1)%images.length;};
    if(images?.length>1) setInterval(render,9000);
    document.querySelectorAll('.view-toggle').forEach(btn=>btn.addEventListener('click',()=>{const isGrid=btn.dataset.view==='grid';grid.classList.toggle('d-none',!isGrid);slider.classList.toggle('d-none',isGrid);toast(`Ansicht: ${isGrid?'Raster':'Slider'}`);}));
  }

  return { initAnnouncements, initTrainings, initQualiMatrix, toast };
})();
