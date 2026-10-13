'use strict';
const {chromium}=require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({viewport:{width:390,height:844}});const page=await context.newPage();
  const base=process.argv[2] || 'http://72.rocky.wsl/SoSecurity/';const origin=new URL(base).origin;const external=[];const errors=[];
  page.on('request',request=>{if(!request.url().startsWith(origin+'/')&&!request.url().startsWith('data:'))external.push(request.url());});
  page.on('pageerror',error=>errors.push(error.message));
  try {
    await page.goto(base+'?module=html');
    const corpus=[
      '<p onclick="window.pwn=1">text<script>window.pwn=1</script><img src="https://evil.invalid/x" onerror="window.pwn=1"></p>',
      '<svg><style><a title="</style><img src=https://evil.invalid/x onerror=window.pwn=1>">x</a></style></svg>',
      '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=https://evil.invalid/x onerror=window.pwn=1>">',
      '<noscript><p title="</noscript><img src=https://evil.invalid/x onerror=window.pwn=1>">x',
      '<a href="jav&#x61;script:window.pwn=1" target="_blank">link</a><iframe srcdoc="<script>parent.pwn=1</script>"></iframe>',
      '<form id="location"><input name="cookie" autofocus onfocus="window.pwn=1"></form><p style="background:url(https://evil.invalid/x)">x</p>'
    ];
    for(const input of corpus){
      const result=await page.evaluate(async html=>{
        const csrf=document.querySelector('input[name="_csrf"]').value;
        const response=await fetch(location.href,{method:'POST',credentials:'same-origin',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({_csrf:csrf,action:'links',html})});
        const result=await response.json();document.querySelectorAll('input[name="_csrf"]').forEach(node=>node.value=result.controls_token);return {status:response.status,...result.result};
      },input);
      assert.equal(result.status,200);
      const unsafe=await page.evaluate(html=>{
        window.pwn=undefined;document.querySelector('[data-html-probe]')?.remove();
        const probe=document.createElement('section');probe.dataset.htmlProbe='';document.body.append(probe);probe.innerHTML=html;
        return probe.querySelectorAll('script,style,svg,math,iframe,object,embed,img,input,form,[onload],[onerror],[onfocus],[id],[name],[style]').length;
      },result.output);
      assert.equal(unsafe,0);await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>typeof window.pwn),'undefined');
    }
    const form=page.locator('form[data-demo-form]');await form.locator('select').selectOption('normal');await form.locator('[data-ajax]').click();await form.locator('.ajax-output').filter({hasText:/^HTTP 200/}).waitFor();
    await page.reload();const preview=page.frameLocator('iframe[title="清理后的基础HTML预览"]');assert.equal(await preview.locator('strong').textContent(),'粗体');
    assert.equal(await page.locator('iframe').getAttribute('sandbox'),'');assert.equal(await preview.locator('a,img,script,svg,form,style').count(),0);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.screenshot({path:'/tmp/sosecurity-html-mobile.png',fullPage:true});assert.deepEqual(external,[]);assert.deepEqual(errors,[]);
    console.log('PASS Chromium HTML: 6 real browser DOM/mutation-XSS cases, no external requests or script execution, sandbox preview and mobile width');
  } finally{await context.close();await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
