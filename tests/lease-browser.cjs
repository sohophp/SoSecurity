'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
    const browser=await chromium.launch({headless:true});const context=await browser.newContext({viewport:{width:390,height:844}});const page=await context.newPage();const errors=[];
    page.on('pageerror',e=>errors.push(e.message));const state=async()=>JSON.parse(await page.locator('[data-demo-state]').textContent());
    const click=async action=>Promise.all([page.waitForNavigation(),page.locator(`button[name="action"][value="${action}"]`).click()]);
    try {
        await page.goto(process.argv[2]+'?module=leases');assert.equal((await state()).initialized,false);await click('prepare');await click('acquire');await click('step');assert.equal((await state()).steps,1);
        await click('acquire');assert.equal((await state()).active,1);await click('advance');await click('verify');assert.equal((await state()).current_valid,false);await click('acquire');assert.equal((await state()).sequence,2);
        const form=page.locator('[data-demo-form]').filter({has:page.locator('button[value="stale_release"]')});await form.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption('stale_release');
        const [response]=await Promise.all([page.waitForResponse(r=>r.request().method()==='POST'&&r.url().includes('module=leases')),form.locator('[data-ajax]').click()]);assert.equal(response.status(),409);
        await page.waitForFunction(()=>document.querySelector('.ajax-output').textContent.includes('HTTP 409'));assert.equal((await state()).current_valid,true);
        const other=await browser.newContext();const stranger=await other.newPage();await stranger.goto(process.argv[2]+'?module=leases');assert.equal(JSON.parse(await stranger.locator('[data-demo-state]').textContent()).initialized,false);await other.close();
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.deepEqual(errors,[]);assert.equal((await page.content()).includes('l1.'),false);
        await page.screenshot({path:'/tmp/sosecurity-lease-mobile.png',fullPage:true});await click('release');await click('remove');
        console.log('PASS lease Chromium mobile: native provisioning/acquire/step, expiry, retained sequence, AJAX stale-release refusal, visitor isolation and layout');
    } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
