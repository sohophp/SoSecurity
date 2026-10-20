'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
    const browser=await chromium.launch({headless:true});const issuer=await browser.newContext({viewport:{width:390,height:844}});const reader=await browser.newContext({viewport:{width:390,height:844}});
    const page=await issuer.newPage();const shared=await reader.newPage();const errors=[];
    for(const view of [page,shared]){view.on('pageerror',e=>errors.push(e.message));view.on('dialog',dialog=>{errors.push('unexpected dialog');dialog.dismiss();});}
    const state=async view=>JSON.parse(await view.locator('[data-link-state]').textContent());
    const submit=async(action,form=null)=>{const button=(form || page).locator(`button[value="${action}"]`);await Promise.all([page.waitForNavigation(),button.click()]);};
    const issue=async delivery=>{
        const form=page.locator('form').filter({has:page.locator('button[value="issue"]')});await form.locator('[name="delivery"]').selectOption(delivery);await submit('issue',form);
        return [await page.locator('[data-issued-link]').getAttribute('href'),(await state(page)).issued.id];
    };
    try{
        await page.goto(process.argv[2]);await page.locator('[name="username"]').fill('demo');await page.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_LINK_PASSWORD);await submit('login');assert.equal((await state(page)).stage,'authenticated');
        let [url,id]=await issue('read');await page.screenshot({path:'/tmp/sosecurity-link-mobile.png',fullPage:true});await shared.goto(url);
        assert.equal(await shared.locator('[data-content] h2').textContent(),'Link document <script>alert(1)</script>');assert.equal(await shared.locator('[data-content] script').count(),0);assert.equal((await state(shared)).content.body,'PRIVATE-LINK-DOCUMENT-BODY');assert.equal((await reader.cookies()).length,0);
        const form=page.locator('form').filter({has:page.locator('button[value="revoke"]')});await form.locator('[name="link_id"]').fill(id);await submit('revoke',form);assert.equal((await state(page)).revoked,true);
        const denied=await shared.goto(url);assert.equal(denied.status(),403);assert.equal((await shared.locator('body').textContent()).includes('PRIVATE-LINK-DOCUMENT-BODY'),false);
        [url,id]=await issue('redeem');await shared.goto(url);assert.equal((await state(shared)).redemption,true);assert.equal(await shared.locator('[data-content]').count(),0);await shared.goto(url);
        const csrf=await shared.locator('[name="_csrf"]').inputValue();await Promise.all([shared.waitForNavigation(),shared.locator('button').click()]);assert.equal((await state(shared)).content.body,'PRIVATE-LINK-DOCUMENT-BODY');
        const replay=await shared.request.post(url,{form:{_csrf:csrf},headers:{Accept:'application/json'}});assert.equal(replay.status(),403);assert.equal((await replay.text()).includes('PRIVATE-LINK-DOCUMENT-BODY'),false);
        for(const view of [page,shared]){assert.equal(await view.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
        await submit('logout');assert.equal((await state(page)).stage,'anonymous');assert.deepEqual(errors,[]);
        console.log('PASS signed-link Chromium: real login/issuance, separate public reader, escaped content, revoke, non-consuming GET landing, explicit POST redemption/replay and mobile layout');
    }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
