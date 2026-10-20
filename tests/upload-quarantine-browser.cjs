'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const crypto=require('node:crypto');const {execFileSync}=require('node:child_process');
(async()=>{
    const [origin,runtime,configuration,packageRoot]=process.argv.slice(2);const payload=Buffer.from('Private native upload bytes.\n');
    const work=fs.mkdtempSync(path.join(os.tmpdir(),'sosecurity-quarantine-browser-'));
    const browser=await chromium.launch({headless:true});const options={viewport:{width:390,height:844},acceptDownloads:true,ignoreHTTPSErrors:true};
    const owner=await browser.newContext(options);const admin=await browser.newContext(options);const page=await owner.newPage();const manager=await admin.newPage();const errors=[];const origins=[];
    for(const view of [page,manager]){view.on('pageerror',e=>errors.push(e.message));view.on('dialog',d=>{errors.push('unexpected dialog');d.dismiss();});view.on('request',r=>{if(r.method()==='POST'){origins.push(r.headers().origin);}});}
    const state=async view=>JSON.parse(await view.locator('[data-quarantine-state]').textContent());
    const submit=async(view,action,form=null)=>Promise.all([view.waitForNavigation(),(form || view).locator(`button[value="${action}"]`).click()]);
    const login=async(view,name)=>{await view.goto(origin);await view.locator('[name="username"]').fill(name);await view.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_QUARANTINE_PASSWORD);await submit(view,'login');assert.equal((await state(view)).stage,'authenticated');};
    const worker=()=>JSON.parse(execFileSync(runtime,['-d','memory_limit=32M',path.join(packageRoot,'examples/upload-quarantine-worker.php'),configuration,'64'],{encoding:'utf8',env:process.env}));
    try{
        await page.goto(origin);const previous=(await owner.cookies()).find(c=>c.name==='QUARANTINE_SESSION').value;
        await page.locator('[name="username"]').fill('alice');await page.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_QUARANTINE_PASSWORD);await submit(page,'login');
        assert.equal((await state(page)).stage,'authenticated',JSON.stringify(await state(page)));const cookie=(await owner.cookies()).find(c=>c.name==='QUARANTINE_SESSION');
        assert.notEqual(cookie.value,previous);assert.equal(cookie.httpOnly,true);assert.equal(cookie.secure,true);assert.equal(cookie.sameSite,'Lax');
        await page.locator('[name="file"]').setInputFiles({name:'browser.txt',mimeType:'text/plain',buffer:payload});await submit(page,'upload');
        const id=(await state(page)).files[0].id;assert.equal((await state(page)).files[0].state,'pending');assert.equal(await page.locator('[data-download]').count(),0);
        assert.equal((await page.request.get(origin+'/?download='+id,{headers:{Accept:'application/json'}})).status(),409);
        assert.equal(worker().processed[0].state,'available');const refreshed=await page.reload();assert.equal(refreshed.request().method(),'GET');assert.equal(refreshed.status(),200);
        const [saved]=await Promise.all([page.waitForEvent('download',{timeout:10000}),page.locator('[data-download]').click({timeout:4000})]);assert.equal(saved.suggestedFilename(),'upload.txt');
        const target=path.join(work,'download.txt');await saved.saveAs(target);assert.equal(await saved.failure(),null);
        assert.equal(crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex'),crypto.createHash('sha256').update(payload).digest('hex'));
        assert.equal(await page.locator('button[value="reject"]').count(),0);
        const csrf=await page.locator('[name="_csrf"]').first().inputValue();
        assert.equal((await page.request.post(origin,{form:{action:'reject',id,_csrf:csrf},headers:{Origin:origin,Accept:'application/json'}})).status(),403);
        await login(manager,'admin');const section=()=>manager.locator(`section[data-file-id="${id}"]`);
        assert.equal(await manager.locator('[data-download]').count(),0);
        assert.equal(await section().locator('button[value="remove"]').count(),0);
        assert.equal((await manager.request.get(origin+'/?download='+id,{headers:{Accept:'application/json'}})).status(),403);
        await submit(manager,'rescan',section());assert.equal((await state(manager)).files[0].state,'pending');
        assert.equal((await page.request.get(origin+'/?download='+id,{headers:{Accept:'application/json'}})).status(),409);
        assert.equal(worker().processed[0].state,'available');
        const form=manager.locator('form').filter({has:manager.locator('button[value="reauthenticate"]')});
        await form.locator('[name="username"]').fill('admin');await form.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_QUARANTINE_PASSWORD);await submit(manager,'reauthenticate',form);
        const used=await manager.locator('[name="_csrf"]').first().inputValue();await submit(manager,'reject',section());assert.equal((await state(manager)).files[0].state,'rejected');
        assert.equal((await page.request.get(origin+'/?download='+id,{headers:{Accept:'application/json'}})).status(),409);
        assert.equal((await manager.request.post(origin,{form:{action:'remove',id,_csrf:used},headers:{Origin:origin,Accept:'application/json'}})).status(),403);
        await submit(manager,'remove',section());assert.deepEqual((await state(manager)).files,[]);
        assert.equal((await page.request.get(origin+'/?download='+id,{headers:{Accept:'application/json'}})).status(),403);
        await page.goto(origin);assert.deepEqual((await state(page)).files,[]);
        for(const view of [page,manager]){assert.equal(await view.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
        await submit(page,'logout');assert.equal((await state(page)).stage,'anonymous');assert.deepEqual(errors,[]);assert.equal(origins.length>=6,true);assert.deepEqual([...new Set(origins)],[origin]);
        console.log('PASS native quarantine TLS Chromium: real password/session rotation, multipart pending/scan/download SHA-256, admin privacy, rescan/reauthentication/rejection/removal, single-use CSRF, logout and 390px layout');
    }finally{await browser.close();fs.rmSync(work,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
