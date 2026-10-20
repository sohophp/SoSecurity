'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
function proof(offset=0){
    const seed=new URL(process.env.SOSECURITY_TEST_OPERATION_OTP_URI).searchParams.get('secret');
    const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let buffer=0,bits=0;const bytes=[];
    for(const character of seed){buffer=(buffer<<5)|alphabet.indexOf(character);bits+=5;if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}buffer&=(1<<bits)-1;}
    const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)+offset));
    const mac=crypto.createHmac('sha1',Buffer.from(bytes)).update(counter).digest();
    return String((mac.readUInt32BE(mac[mac.length-1]&15)&0x7fffffff)%1000000).padStart(6,'0');
}
(async()=>{
    const browser=await chromium.launch({headless:true});const context=await browser.newContext({viewport:{width:390,height:844}});const page=await context.newPage();
    const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('dialog',dialog=>{errors.push('unexpected dialog');dialog.dismiss();});
    const state=async()=>JSON.parse(await page.locator('[data-operation-state]').textContent());
    const submit=async(action,target=page)=>{await Promise.all([target.waitForNavigation(),target.locator(`button[value="${action}"]`).click()]);};
    const credentials=async()=>{await page.locator('[name="username"]').fill('demo');await page.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_OPERATION_PASSWORD);};
    try{
        await page.goto(process.argv[2]);assert.equal((await state()).stage,'anonymous');
        await credentials();await submit('login');
        if(process.argv[3]==='totp'){assert.equal((await state()).stage,'mfa_required');await page.locator('[name="proof"]').fill(proof());await submit('mfa');}
        assert.equal((await state()).stage,'authenticated');const session=(await state()).session.id;
        await page.locator('[name="title"]').fill('Old tab proposal');await submit('prepare');
        const stale=await context.newPage();await stale.goto(process.argv[2]);
        const proposed='Browser reviewed <script>alert(1)</script>';
        await page.locator('[name="title"]').fill(proposed);await submit('prepare');const review=(await state()).review.id;
        await submit('confirm',stale);assert.equal(JSON.parse(await stale.locator('[data-operation-state]').textContent()).error,'operation.review_changed');await stale.close();
        await page.goto(process.argv[2]);assert.equal((await state()).review.id,review);assert.equal(await page.locator('[data-review] bdi').textContent(),proposed);
        assert.equal(await page.locator('[data-review] script').count(),0);assert.equal((await state()).review.phase,'pending');
        await page.screenshot({path:'/tmp/sosecurity-operation-'+process.argv[3]+'-mobile.png',fullPage:true});
        await credentials();await submit('reauthenticate');
        if(process.argv[3]==='totp'){assert.equal((await state()).stage,'mfa_required');assert.equal((await state()).review.id,review);await page.locator('[name="proof"]').fill(proof(1));await submit('mfa');}
        assert.equal((await state()).session.id,session);await submit('confirm');assert.equal((await state()).review.phase,'granted');
        await submit('execute');assert.equal((await state()).applied,true);assert.equal((await state()).review,null);
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
        const body=await page.locator('body').textContent();for(const prefix of ['oc1.','og1.','soss_','$2y$']){assert.equal(body.includes(prefix),false);}
        await submit('logout');assert.equal((await state()).stage,'anonymous');assert.deepEqual(errors,[]);
        console.log('PASS operation Chromium ('+process.argv[3]+'): native login, visible escaped review, stale tab denial, renewed proof, explicit confirmation and one-use SQL execution on mobile');
    }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
