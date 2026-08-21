async function load(){
  document.getElementById('k').textContent=JSON.stringify(await (await fetch('/api/keys')).json(),null,2);
  document.getElementById('s').textContent=JSON.stringify(await (await fetch('/api/stats')).json(),null,2);
}
document.getElementById('r').onclick=load;
let last=null;
document.getElementById('seal').onclick=async()=>{
  const r=await fetch('/api/seal',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({aad:aad.value,plain:plain.value})});
  last=await r.json();
  blob.textContent=JSON.stringify(last,null,2);
};
document.getElementById('open').onclick=async()=>{
  if(!last) return;
  const r=await fetch('/api/open',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(last)});
  out.textContent=JSON.stringify(await r.json(),null,2);
};
load(); setInterval(load,3000);
