import { test, expect } from '@playwright/test';
import { replay } from '../../src/replay.js';
import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
let dashboard: ChildProcess, labs: ChildProcess, token: string;
test.beforeAll(async()=>{
  dashboard=spawn(process.execPath,['dist/src/server.js'],{cwd:process.cwd(),stdio:['ignore','pipe','pipe']});
  token=await new Promise<string>((resolve,reject)=>{
    let output='';const timer=setTimeout(()=>reject(new Error('Dashboard startup timeout')),5000);
    dashboard.stdout!.on('data',chunk=>{output+=chunk;const match=output.match(/Management token .*: ([a-f0-9]{64})/);if(match){clearTimeout(timer);resolve(match[1]!);}});
    dashboard.on('error',reject);
  });
  labs=spawn('python3',['-m','tools.lab'],{stdio:['ignore','pipe','pipe']});
  await new Promise<void>((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('Lab startup timeout')),5000);
    labs.stdout!.on('data',()=>{clearTimeout(timer);resolve();});labs.on('error',reject);
  });
});
test.afterAll(async()=>{
  for(const child of [dashboard,labs])if(child && child.exitCode===null){child.kill('SIGTERM');await new Promise(resolve=>child.once('exit',resolve));}
});
test('management API rejects unauthorized, cross-origin and write requests',async({request})=>{
  expect((await request.get('http://127.0.0.1:8090/api/evidence')).status()).toBe(401);
  expect((await request.get('http://127.0.0.1:8090/api/evidence',{headers:{Authorization:'Bearer '+token,Origin:'http://evil.example'}})).status()).toBe(403);
  expect((await request.post('http://127.0.0.1:8090/api/evidence',{headers:{Authorization:'Bearer '+token}})).status()).toBe(405);
  expect((await request.get('http://127.0.0.1:8090/api/evidence',{headers:{Authorization:'Bearer '+token,Host:'evil.example'}})).status()).toBe(403);
  expect((await request.get('http://127.0.0.1:8090/../../lab/scenarios.py',{headers:{Authorization:'Bearer '+token}})).status()).toBe(404);
});
test('XSS executes only in vulnerable origin',async({page})=>{
  const payload=encodeURIComponent('<script>window.__bp=1</script>');
  for(const port of [8091,8092]){
    await page.setExtraHTTPHeaders({Authorization:'Bearer fixture-alice'});
    await page.goto(`http://127.0.0.1:${port}/xss?q=${payload}`);
    expect(await page.evaluate(()=> (window as unknown as {__bp?:number}).__bp)).toBe(port===8091?1:undefined);
  }
});
test('dashboard inspects every finding, filters, exports reports and responds to mobile layout',async({page})=>{
  const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:1512,height:1050});
  await page.goto('http://127.0.0.1:8090');
  await page.getByLabel('Management token').fill('incorrect');await page.getByRole('button',{name:'Connect',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('Token rejected');
  await page.getByLabel('Management token').fill(token);await page.getByRole('button',{name:'Connect',exact:true}).click();
  await expect(page.locator('#metric-after')).toHaveText('10 / 10');
  await expect(page.locator('.finding-row')).toHaveCount(10);
  const catalog=JSON.parse(readFileSync('evidence/results.json','utf8')).findings;
  for(const finding of catalog){
    await page.locator(`[data-id="${finding.id}"]`).click();
    await expect(page.locator('#finding-title')).toHaveText(finding.title);
  }
  await page.locator('[data-id="BP-010"]').click();
  await page.locator('#supporting summary').click();
  await expect(page.locator('#additional')).toContainText('FICTIONAL_ADMIN_AUDIT_MARKER');
  await expect(page.locator('#additional')).toContainText('HTTP/1.1 403');
  await page.locator('[data-id="BP-001"]').click();
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:'docs/dashboard.png',fullPage:true});
  await page.getByRole('tab',{name:'Code comparison'}).click();
  await expect(page.locator('#fixed-code')).toContainText("record['owner'] != actor");
  await page.getByRole('tab',{name:'Root cause'}).click();
  await expect(page.locator('#cause')).toContainText('ownership');
  await page.getByLabel('Filter findings').fill('JWT');
  await expect(page.locator('.finding-row')).toHaveCount(1);
  await page.getByLabel('Filter findings').fill('');
  const download=page.waitForEvent('download');await page.getByRole('button',{name:'Export report',exact:false}).click();
  expect((await download).suggestedFilename()).toBe('BP-001-idor.md');
  const evidenceDownload=page.waitForEvent('download');await page.getByRole('button',{name:'Export all evidence',exact:false}).click();
  expect((await evidenceDownload).suggestedFilename()).toBe('bountyproof-evidence.json');
  expect(await page.evaluate(()=>Object.keys(localStorage))).toEqual([]);
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:'docs/dashboard-mobile.png',fullPage:true});
  expect(errors).toEqual([]);
});

test('TypeScript replay proves authorization and SQL remediation over real HTTP', async()=>{
  const before = await replay('vulnerable','/api/invoices',{id:'2'});
  const after = await replay('fixed','/api/invoices',{id:'2'});
  expect(before.status).toBe(200);expect(JSON.parse(before.body).owner).toBe('bob');
  expect(after.status).toBe(403);
  const attack = {q: "' OR 1=1 --"};
  expect(JSON.parse((await replay('vulnerable','/sql',attack)).body).rows).toContainEqual(['Bob private note']);
  expect(JSON.parse((await replay('fixed','/sql',attack)).body).rows).toEqual([]);
});
