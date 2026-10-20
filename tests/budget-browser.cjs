'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
    const browser=await chromium.launch({headless:true});const context=await browser.newContext({viewport:{width:390,height:844}});const page=await context.newPage();const errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    const state=async()=>JSON.parse(await page.locator('[data-demo-state]').textContent());
    const click=async action=>Promise.all([page.waitForNavigation(),page.locator(`button[name="action"][value="${action}"]`).click()]);
    try {
        await page.goto(process.argv[2]+'?module=budgets');await page.locator('select[name="budget_algorithm"]').selectOption('fixed_window');await click('reset');await click('batch');assert.equal((await state()).executed,1);
        await click('batch');assert.equal((await state()).executed,1);assert.equal((await state()).balances.work.remaining,2);
        await page.locator('select[name="budget_mode"]').selectOption('atomic');await click('reset');await click('batch');await click('batch');assert.equal((await state()).balances.requests.remaining,1);
        await page.locator('select[name="budget_mode"]').selectOption('ordered');await click('reset');await click('batch');
        const form=page.locator('[data-demo-form]').filter({has:page.locator('button[value="batch"]')});await form.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption('batch');
        const [response]=await Promise.all([page.waitForResponse(r=>r.request().method()==='POST'&&r.url().includes('module=budgets')),form.locator('[data-ajax]').click()]);const data=await response.json();
        assert.equal(response.status(),429);assert.deepEqual(data.result.charged,['ip']);
        await page.waitForFunction(()=>JSON.parse(document.querySelector('[data-demo-state]').textContent).balances.ip.remaining===18);
        const other=await browser.newContext();const stranger=await other.newPage();await stranger.goto(process.argv[2]+'?module=budgets');assert.equal(JSON.parse(await stranger.locator('[data-demo-state]').textContent()).executed,0);await other.close();
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.deepEqual(errors,[]);
        await page.screenshot({path:'/tmp/sosecurity-budget-mobile.png',fullPage:true});await click('reset');
        console.log('PASS budget Chromium mobile: native form, weighted denial, atomic group, ordered AJAX charges, visitor isolation and layout');
    } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
