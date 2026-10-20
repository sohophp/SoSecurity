'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
function otp(uri){
    const seed=new URL(uri).searchParams.get('secret');const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';
    for(const character of seed){bits+=alphabet.indexOf(character).toString(2).padStart(5,'0');}
    const bytes=[];for(let i=0;i+8<=bits.length;i+=8){bytes.push(parseInt(bits.slice(i,i+8),2));}
    const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
    const mac=crypto.createHmac('sha1',Buffer.from(bytes)).update(counter).digest();const start=mac[mac.length-1]&15;
    return String((mac.readUInt32BE(start)&0x7fffffff)%1000000).padStart(6,'0');
}
(async()=>{
    const browser=await chromium.launch({headless:true});const url=process.argv[2];
    const context=await browser.newContext({viewport:{width:390,height:844},ignoreHTTPSErrors:true});const page=await context.newPage();const errors=[];
    page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>{errors.push('unexpected dialog');dialog.dismiss();});
    const state=async()=>JSON.parse(await page.locator('[data-webhook-state]').textContent());
    const submit=async action=>Promise.all([page.waitForNavigation(),page.locator(`button[value="${action}"]`).click()]);
    try{
        await page.goto(url);assert.equal((await state()).stage,'anonymous');assert.equal(await page.locator('button[value="retry"]').count(),0);
        await page.locator('[name="username"]').fill('admin');await page.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_WEBHOOK_PASSWORD);await submit('login');
        assert.equal((await state()).stage,'mfa_required');assert.equal(await page.locator('button[value="retry"]').count(),0);
        await page.locator('[name="code"]').fill(otp(process.env.SOSECURITY_TEST_WEBHOOK_OTP_URI));await submit('second_factor');
        let data=await state();assert.equal(data.stage,'authenticated');assert.equal(data.receipts.length,2);assert.equal(data.receipts.filter(row=>row.processing?.status==='dead').length,1);
        assert.equal(data.receipts.some(row=>row.event_id==='<script>alert(1)</script>'),true);assert.equal(await page.locator('script').count(),0);
        assert.equal(await page.locator('button[value="retry"]').count(),1);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
        for(const secret of ['DOCUMENT-PRIVATE','body_digest','claim_digest','worker_digest','payload','seal_key']){assert.equal((await page.locator('main').textContent()).includes(secret),false);}
        await page.screenshot({path:process.env.SOSECURITY_TEST_WEBHOOK_SCREENSHOT || '/tmp/sosecurity-webhook-processing-mobile.png',fullPage:true});
        await submit('retry');data=await state();assert.equal(data.retry_scheduled,true);assert.equal(data.receipts.filter(row=>row.processing?.status==='retry').length,1);
        assert.equal(await page.locator('button[value="retry"]').count(),0);assert.equal(page.url(),url);
        await submit('logout');assert.equal((await state()).stage,'anonymous');assert.equal('receipts' in await state(),false);assert.deepEqual(errors,[]);
        console.log('PASS webhook processing mobile Chromium: real password/TOTP, CSRF form retry, terminal-state-only action, inert signed HTML-like ID, bounded metadata and logout; isolated TLS');
    }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
