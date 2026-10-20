'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
    const browser=await chromium.launch({headless:true});const context=await browser.newContext({viewport:{width:390,height:844}});const page=await context.newPage();const errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    try {
        await page.goto(process.argv[2]+'?module=password');
        await page.locator('input[name="password"]').fill('passwordpassword');
        await Promise.all([page.waitForNavigation(),page.locator('button[value="policy"]').click()]);
        assert.deepEqual(JSON.parse(await page.locator('.result pre').textContent()).errors,['password.weak']);
        assert.equal(await page.locator('input[name="password"]').inputValue(),'');
        const form=page.locator('[data-demo-form]').filter({has:page.locator('button[value="policy"]')});
        await form.locator('input[name="password"]').fill('Unique demo phrase 59!');
        await form.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption('policy');
        const [response]=await Promise.all([page.waitForResponse(r=>r.request().method()==='POST'),form.locator('[data-ajax]').click()]);
        const result=await response.json();assert.equal(response.status(),200);assert.equal(result.result.valid,true);
        await page.waitForFunction(()=>document.querySelector('.ajax-output').textContent.includes('HTTP 200'));
        assert.equal((await form.locator('.ajax-output').textContent()).includes('Unique demo phrase'),false);
        await form.locator('input[name="password"]').fill('');
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
        assert.match(await page.locator('main').textContent(),/不自动联网/);
        await page.screenshot({path:'/tmp/sosecurity-password-mobile.png',fullPage:true});assert.deepEqual(errors,[]);
        console.log('PASS password Chromium: real form weak-password rejection, AJAX acceptance, no password echo, explicit offline status and mobile layout');
    } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
