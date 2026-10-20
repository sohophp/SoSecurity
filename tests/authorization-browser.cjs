'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
    const browser=await chromium.launch({headless:true});const context=await browser.newContext({viewport:{width:390,height:844}});const page=await context.newPage();const errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    const state=async()=>JSON.parse(await page.locator('main > pre').textContent());
    const submit=async action=>{await Promise.all([page.waitForNavigation(),page.locator(`button[value="${action}"]`).click()]);};
    try{
        await page.goto(process.argv[2]);await page.locator('[name="username"]').fill('demo');await page.locator('[name="password"]').fill('Correct-test-password');await submit('login');
        assert.equal((await state()).stage,'authenticated');assert.equal((await state()).documents_available,true);
        await page.locator('[name="document_id"]').fill('a');await submit('document_read');assert.deepEqual(Object.keys((await state()).document),['id','version','title']);
        await page.locator('[name="document_id"]').fill('a');await page.locator('[name="fields"]').fill('confidential_note');await submit('document_read');assert.equal((await state()).error,'authorization.denied');
        await page.locator('[name="operations"]').fill(JSON.stringify([{id:'a',version:1,changes:{title:'Browser changed'}}]));await submit('document_batch');assert.equal((await state()).updated,1);
        await page.locator('[name="operations"]').fill(JSON.stringify([{id:'b',version:1,changes:{title:'Denied'}}]));await submit('document_batch');assert.equal((await state()).error,'authorization.denied');
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.equal((await page.locator('main').textContent()).includes('PRIVATE-NOTE'),false);
        await page.screenshot({path:'/tmp/sosecurity-authorization-mobile.png',fullPage:true});assert.deepEqual(errors,[]);
        console.log('PASS native authorization Chromium: real login, field denial, version-bound update, foreign-owner refusal and mobile layout');
    }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
