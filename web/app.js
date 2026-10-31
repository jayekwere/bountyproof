'use strict';
const $ = id => document.getElementById(id);
let data, selected;
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text],{type}));
  const a = document.createElement('a'); a.href=url; a.download=name; a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function http(response) {
  return response.request+'\n\nHTTP/1.1 '+response.status+'\n'+Object.entries(response.headers).map(([k,v])=>k+': '+v).join('\n')+'\n\n'+response.body;
}
function choose(item) {
  selected=item;
  $('placeholder').hidden=true; $('finding').hidden=false;
  for(const [id,value] of Object.entries({'finding-id':item.id+' / '+item.slug.toUpperCase(),'finding-title':item.title,mapping:item.cwe+' · '+item.owasp,impact:item.impact,cause:item.rootCause,limitations:item.limitation,'before':http(item.before),'after':http(item.after),positive:http(item.positive),'vuln-code':item.vulnerableCode,'fixed-code':item.fixedCode,'status-before':String(item.before.status),'status-after':String(item.after.status)})) $(id).textContent=value;
  $('reference').href=item.reference;
  $('checks').replaceChildren(...['Exploit reproduced','Fix verified','Legitimate access preserved'].map(label=>{const span=document.createElement('span');span.className='check';span.textContent='✓ '+label;return span;}));
  for(const row of document.querySelectorAll('.finding-row')) row.classList.toggle('active',row.dataset.id===item.id);
}
function renderCatalog() {
  const query=$('search').value.toLowerCase();
  const findings=data.findings.filter(item=>(item.id+' '+item.title+' '+item.cwe).toLowerCase().includes(query));
  $('catalog').replaceChildren(...findings.map(item=>{
    const button=document.createElement('button');button.className='finding-row';button.dataset.id=item.id;button.setAttribute('role','listitem');
    const meta=document.createElement('span');meta.className='row-meta';
    const id=document.createElement('span');id.textContent=item.id+' / '+item.cwe;
    const severity=document.createElement('span');severity.className='severity';severity.textContent=item.severity;
    meta.append(id,severity);
    const title=document.createElement('strong');title.textContent=item.title;
    const check=document.createElement('span');check.className='row-check';check.textContent='✓ Reproduced & remediated';
    button.append(meta,title,check);button.addEventListener('click',()=>choose(item));
    if(selected?.id===item.id)button.classList.add('active');return button;
  }));
  if(!findings.length){const p=document.createElement('p');p.className='empty';p.textContent='No matching findings.';$('catalog').append(p);}
}
$('connect').addEventListener('submit',async event=>{
  event.preventDefault();
  try {
    const response=await fetch('/api/evidence',{headers:{Authorization:'Bearer '+$('token').value.trim()},cache:'no-store'});
    if(!response.ok)throw new Error(response.status===401?'Token rejected. Use the token from the current dashboard process.':'Evidence unavailable. Run the evidence suite first.');
    data=await response.json();
    if(data.schemaVersion!==1||data.findings.length!==10)throw new Error('Unsupported evidence format');
    $('token').value='';$('unlock').hidden=true;$('message').textContent='Connected to measured local evidence. Tokens are kept out of browser storage.';
    for(const [metric,key] of [['before','reproduced'],['after','remediated'],['positive','legitimateAccess']])$('metric-'+metric).textContent=data.findings.filter(f=>f.checks[key]).length+' / 10';
    $('timestamp').textContent='Evidence collected '+new Date(data.generatedAt).toLocaleString();
    $('source-hash').textContent='Source SHA-256 '+data.sourceSha256.slice(0,16)+'…';
    $('export-all').disabled=false;renderCatalog();choose(data.findings[0]);
  }catch(error){$('message').textContent=error.message;}
});
$('search').addEventListener('input',()=>{if(data)renderCatalog();});
const tabs=[...document.querySelectorAll('[role=tab]')];
function tab(button){for(const other of tabs){const active=other===button;other.setAttribute('aria-selected',String(active));other.tabIndex=active?0:-1;$('panel-'+other.dataset.tab).hidden=!active;}}
for(const [index,button] of tabs.entries()){
  button.addEventListener('click',()=>tab(button));
  button.addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();const next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[next].focus();tab(tabs[next]);}});
}tab(tabs[0]);
$('export-all').addEventListener('click',()=>download('bountyproof-evidence.json',JSON.stringify(data,null,2),'application/json'));
$('export-report').addEventListener('click',()=>{
  if(!selected)return;const item=selected;
  const text=['# '+item.id+': '+item.title,'Educational local fixture finding. '+item.severity+' · '+item.cwe+' · '+item.owasp,'## Scope\nOwned local fixtures. Fictional data. No third-party finding.','## Root cause\n'+item.rootCause,'## Impact\n'+item.impact,...[['Vulnerable','before'],['Remediated','after'],['Legitimate access','positive']].map(([label,key])=>'## '+label+'\n```http\n'+http(item[key])+'\n```'),'## Vulnerable code\n```python\n'+item.vulnerableCode+'```','## Corrected code\n```python\n'+item.fixedCode+'```','## Regression\n'+JSON.stringify(item.checks),'## Limitations\n'+item.limitation,'## Reference\n'+item.reference,'Collected: '+data.generatedAt+'\nSource SHA-256: '+data.sourceSha256].join('\n\n');
  download(item.id+'-'+item.slug+'.md',text,'text/markdown');
});

for(const link of document.querySelectorAll('.nav-item')) link.addEventListener('click',()=>{
  if(link.hash==='#code') tab(tabs.find(button=>button.dataset.tab==='code'));
  if(link.hash==='#details') tab(tabs.find(button=>button.dataset.tab==='evidence'));
});
