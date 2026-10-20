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
    // Certificate trust is bypassed only for this isolated TLS test server; Python verifies its private CA.
    const options={viewport:{width:390,height:844},ignoreHTTPSErrors:url.startsWith('https:')};
    const context=await browser.newContext(options);const anonymous=await browser.newContext(options);const weak=await browser.newContext(options);
    const page=await context.newPage();const denied=await weak.newPage();const errors=[];
    for(const view of [page,denied]){view.on('pageerror',error=>errors.push(error.message));view.on('dialog',dialog=>{errors.push('unexpected dialog');dialog.dismiss();});}
    const state=async view=>JSON.parse(await view.locator('[data-webhook-state]').textContent());
    const submit=async(view,action)=>Promise.all([view.waitForNavigation(),view.locator(`button[value="${action}"]`).click()]);
    const login=async(view,user)=>{await view.goto(url);await view.locator('[name="username"]').fill(user);await view.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_WEBHOOK_PASSWORD);await submit(view,'login');};
    try{
        await login(page,'admin');assert.equal((await state(page)).stage,'mfa_required');assert.equal('receipts' in await state(page),false);
        await page.locator('[name="code"]').fill(otp(process.env.SOSECURITY_TEST_WEBHOOK_OTP_URI));await submit(page,'second_factor');
        let data=await state(page);assert.equal(data.stage,'authenticated');assert.equal(data.receipts.length,2);
        assert.equal(data.receipts.some(row=>row.event_id==='<script>alert(1)</script>'),true);
        const text=await page.locator('main').textContent();
        for(const secret of ['PAYLOAD-PRIVATE','DOCUMENT-PRIVATE','seal_key','body_digest','descriptor']){assert.equal(text.includes(secret),false);}
        assert.equal(await page.locator('script').count(),0);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
        assert.equal(await page.evaluate(()=>localStorage.length),0);assert.equal(page.url(),url);
        await page.screenshot({path:'/tmp/sosecurity-webhook-mobile.png',fullPage:true});
        // A current admin Cookie does not authenticate a public webhook POST.
        let response=await context.request.post(url+'?receive=1',{data:{id:'forged'}});assert.equal(response.status(),403);
        response=await anonymous.request.get(url,{headers:{Accept:'application/json'}});data=await response.json();assert.equal(data.stage,'anonymous');assert.equal('receipts' in data,false);
        await login(denied,'weakadmin');assert.equal(await denied.locator('[data-webhook-state]').count(),1);assert.equal((await state(denied)).error,'webhook_example.denied');
        await submit(page,'logout');assert.equal((await state(page)).stage,'anonymous');assert.equal('receipts' in await state(page),false);
        response=await context.request.get(url,{headers:{Accept:'application/json'}});assert.equal((await response.json()).stage,'anonymous');assert.deepEqual(errors,[]);
        console.log('PASS webhook Chromium: real password/TOTP, 390px metadata view, inert signed HTML-like IDs, independent Cookie/signature boundaries, weak-admin denial and logout; isolated TLS only');
    }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
