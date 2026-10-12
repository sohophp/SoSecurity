'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
  const [backend,allowed,denied]=process.argv.slice(2);
  const browser=await chromium.launch({headless:true});const context=await browser.newContext();const page=await context.newPage();
  try {
    await page.goto(allowed);
    const success=await page.evaluate(async url=>(await fetch(url,{headers:{'X-Demo-Token':'sample'}})).json(),backend);
    assert.equal(success.demo,true);
    const credentials=await page.evaluate(async url=>{try{await fetch(url,{credentials:'include'});return false;}catch{return true;}},backend);
    assert.equal(credentials,true);
    const method=await page.evaluate(async url=>{try{await fetch(url,{method:'DELETE',headers:{'X-Demo-Token':'sample'}});return false;}catch{return true;}},backend);
    assert.equal(method,true);
    await page.goto(denied);
    const blocked=await page.evaluate(async url=>{try{await fetch(url,{headers:{'X-Demo-Token':'sample'}});return false;}catch{return true;}},backend);
    assert.equal(blocked,true);
    console.log('PASS Chromium CORS: real preflight/read, denied origin/method and credential mode');
  } finally {await context.close();await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
