'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');const crypto=require('node:crypto');
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
    // A self-signed certificate belongs only to this isolated local TLS fixture.
    const options={viewport:{width:390,height:844},ignoreHTTPSErrors:url.startsWith('https:')};
    const self=await browser.newContext(options);const administrator=await browser.newContext(options);const bearer=await browser.newContext(options);
    const page=await self.newPage();const admin=await administrator.newPage();const errors=[];
    for(const view of [page,admin]){view.on('pageerror',error=>errors.push(error.message));view.on('dialog',dialog=>{errors.push('unexpected dialog');dialog.dismiss();});}
    const state=async view=>JSON.parse(await view.locator('[data-credential-state]').textContent());
    const submit=async(view,action,container=view)=>{await Promise.all([view.waitForNavigation(),container.locator(`button[value="${action}"]`).click()]);};
    const login=async(view,username)=>{await view.goto(url);await view.locator('[name="username"]').fill(username);await view.locator('[name="password"]').fill(process.env.SOSECURITY_TEST_CREDENTIAL_PASSWORD);await submit(view,'login');};
    const issue=async(view,name,both=false)=>{
        const form=view.locator('form').filter({has:view.locator('button[value="issue"]')});await form.locator('[name="name"]').fill(name);
        if(both){await form.locator('[name="scopes[]"]').selectOption(['documents:read','documents:write']);}
        await submit(view,'issue',form);return [await view.locator('[data-issued-token]').inputValue(),(await state(view)).issued];
    };
    const api=async(token,document='a',write=null)=>{
        const target=url+'?api=document&document_id='+document;const headers={Authorization:'Bearer '+token,Accept:'application/json'};
        return write===null?bearer.request.get(target,{headers}):bearer.request.post(target,{headers,data:write});
    };
    try{
        await login(page,'demo');assert.equal((await state(page)).stage,'authenticated');
        let [secret,metadata]=await issue(page,'Browser <script>alert(1)</script>',true);
        assert.equal(secret.startsWith('ac1.'),true);assert.equal(await page.locator('script').count(),0);
        assert.equal(page.url().includes(secret),false);assert.equal(await page.evaluate(()=>localStorage.length),0);
        await page.screenshot({path:'/tmp/sosecurity-credential-mobile.png',fullPage:true});
        assert.equal((await api(secret)).status(),200);assert.equal((await bearer.cookies()).length,0);
        await page.goto(url);assert.equal(await page.locator('[data-issued-token]').count(),0);
        let article=page.locator('article').filter({has:page.locator(`input[name="id"][value="${metadata.id}"]`)});
        const previous=secret;await submit(page,'rotate',article);secret=await page.locator('[data-issued-token]').inputValue();
        assert.equal((await state(page)).issued.generation,2);assert.equal((await api(previous)).status(),403);assert.equal((await api(secret)).status(),200);
        article=page.locator('article').filter({has:page.locator(`input[name="id"][value="${metadata.id}"]`)});
        await submit(page,'revoke',article);assert.equal((await state(page)).revoked,true);assert.equal((await api(secret)).status(),403);
        await login(admin,'admin');assert.equal((await state(admin)).stage,'mfa_required');
        await admin.locator('[name="code"]').fill(otp(process.env.SOSECURITY_TEST_CREDENTIAL_OTP_URI));await submit(admin,'second_factor');assert.equal((await state(admin)).stage,'authenticated');
        const target=admin.locator('form').filter({has:admin.locator('[name="owner"]')});await target.locator('[name="owner"]').fill('service');await Promise.all([admin.waitForNavigation(),target.locator('button').click()]);assert.equal((await state(admin)).owner,'service');
        const [serviceSecret,serviceInfo]=await issue(admin,'Service read only');const serviceResponse=await api(serviceSecret,'s');assert.equal(serviceResponse.status(),200);assert.equal((await serviceResponse.json()).document.body,'SERVICE-PRIVATE-BODY');assert.equal((await api(serviceSecret,'a')).status(),403);
        assert.equal((await api(serviceSecret,'s',{title:'Forbidden write',version:'1'})).status(),403);
        assert.equal(serviceInfo.creator_reference,serviceInfo.issuer_reference);
        await submit(admin,'revoke_all');assert.equal((await state(admin)).revoked_count,1);assert.equal((await api(serviceSecret,'s')).status(),403);
        for(const view of [page,admin]){assert.equal(await view.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.equal(await view.locator('script').count(),0);}
        await submit(page,'logout');assert.equal((await state(page)).stage,'anonymous');assert.deepEqual(errors,[]);
        console.log('PASS API credential Chromium: real password/TOTP, 390px management, once-only secret display, isolated Bearer reads, generation rotation/revocation, service delegation and scope denial; test TLS certificate only');
    }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
