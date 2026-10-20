'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const crypto=require('node:crypto');
(async()=>{
    const work=fs.mkdtempSync(path.join(os.tmpdir(),'sosecurity-download-browser-'));const browser=await chromium.launch({headless:true});
    const options={viewport:{width:390,height:844},acceptDownloads:true,ignoreHTTPSErrors:process.argv[2].startsWith('https:')};
    const issuer=await browser.newContext(options);const reader=await browser.newContext(options);const page=await issuer.newPage();const shared=await reader.newPage();const errors=[];let saved=0;
    for(const view of [page,shared]){view.on('pageerror',e=>errors.push(e.message));view.on('dialog',d=>{errors.push('unexpected dialog');d.dismiss();});}
    const state=async view=>JSON.parse(await view.locator('[data-download-state]').textContent());
    const submit=async(action,form=null)=>{await Promise.all([page.waitForNavigation(),(form || page).locator(`button[value="${action}"]`).click()]);};
    const verify=async download=>{
        const filename=download.suggestedFilename();assert.equal(filename.startsWith('报告 '),true);assert.equal(filename.endsWith('.bin'),true);assert.equal(/[\r\n/\\]/.test(filename),false);
        const target=path.join(work,`${++saved}.bin`);await download.saveAs(target);assert.equal(await download.failure(),null);assert.equal(crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex'),process.env.SOSECURITY_TEST_DOWNLOAD_SHA256);
    };
    const issue=async delivery=>{
        const form=page.locator('form').filter({has:page.locator('button[value="issue"]')});await form.locator('[name="delivery"]').selectOption(delivery);await submit('issue',form);return [await page.locator('[data-issued-link]').getAttribute('href'),(await state(page)).issued.id];
    };
    const openDownload=async url=>{const event=shared.waitForEvent('download');await shared.goto(url).catch(error=>assert.match(error.message,/Download is starting/));await verify(await event);};
    try{
        await page.goto(process.argv[2]);await page.locator('[name="username"]').fill('demo');await page.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_DOWNLOAD_PASSWORD);await submit('login');assert.equal((await state(page)).stage,'authenticated');
        const event=page.waitForEvent('download');await page.locator('[data-private-download]').click();await verify(await event);assert.equal((await state(page)).stage,'authenticated');
        let [url,id]=await issue('read');await page.screenshot({path:'/tmp/sosecurity-download-mobile.png',fullPage:true});await shared.goto(process.argv[2]);
        // Public download itself does not create a Cookie; discard the anonymous management-page Cookie first.
        await reader.clearCookies();await openDownload(url);assert.equal((await reader.cookies()).length,0);
        const revoke=page.locator('form').filter({has:page.locator('button[value="revoke"]')});await revoke.locator('[name="link_id"]').fill(id);await submit('revoke',revoke);assert.equal((await state(page)).revoked,true);
        const denied=await shared.goto(url);assert.equal(denied.status(),403);assert.equal((await state(shared)).error,'download.denied');
        [url,id]=await issue('redeem');await shared.goto(url);assert.equal((await state(shared)).redemption,true);const csrf=await shared.locator('[name="_csrf"]').inputValue();
        const redemption=shared.waitForEvent('download');await shared.locator('button').click();await verify(await redemption);
        const replay=await shared.request.post(url,{form:{_csrf:csrf},headers:{Accept:'application/json'}});assert.equal(replay.status(),403);assert.deepEqual(await replay.json(),{error:'download.denied'});
        for(const view of [page,shared]){assert.equal(await view.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
        await submit('logout');assert.equal((await state(page)).stage,'anonymous');const response=await page.request.get(process.argv[2]+'?delivery=private&file_id=a',{headers:{Accept:'application/json'}});assert.equal(response.status(),403);assert.deepEqual(errors,[]);
        console.log('PASS authorized download Chromium: real password login, private and public saved binary SHA-256/name, revoked link, explicit POST download/replay, logout and 390px layout');
    }finally{await browser.close();fs.rmSync(work,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
