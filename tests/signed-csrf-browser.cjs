'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true});
  // Browser uses only an ephemeral self-signed test certificate; urllib separately verifies its test CA.
  const context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();
  const origin=process.argv[2],attacker=process.argv[3];
  try {
    await page.goto(origin+'/form');
    await page.evaluate(async()=>{ await fetch('/test-login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'user=alice'}); });
    const token=await page.evaluate(async()=>(await (await fetch('/form')).json()).token);
    const again=await page.evaluate(async()=>(await (await fetch('/form')).json()).token);assert.equal(again,token);
    assert.equal(await page.evaluate(()=>document.cookie),'');
    const cookies=await context.cookies(origin);assert.equal(cookies.length,2);
    for(const cookie of cookies){assert.equal(cookie.secure,true);assert.equal(cookie.httpOnly,true);assert.equal(cookie.path,'/');assert.equal(cookie.name.startsWith('__Host-'),true);}
    assert.equal(await page.evaluate(async t=>(await fetch('/update',{method:'POST',headers:{'X-CSRF-Token':t},body:''})).status,token),200);
    assert.equal(await page.evaluate(async()=>(await fetch('/update',{method:'POST',body:''})).status),403);
    // Different port is another Origin while still same-site: auth cookies are present, CSRF must reject the forged form.
    await page.goto(attacker+'/');
    const pending=page.waitForResponse(r=>r.url()===origin+'/update');await page.locator('button').click();assert.equal((await pending).status(),403);
    const blocked=await context.newPage();await blocked.goto(attacker+'/');
    const read=await blocked.evaluate(async target=>{try{await fetch(target+'/form',{credentials:'include'});return true;}catch{return false;}},origin);assert.equal(read,false);
    console.log('PASS Chromium HTTPS: __Host/Secure/HttpOnly cookies, stable multi-tab pair, same-origin AJAX; authenticated same-site hostile-Origin form rejected, CORS cannot read token');
  } finally {await context.close();await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
