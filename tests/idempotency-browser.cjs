const { chromium } = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({ignoreHTTPSErrors:true, viewport:{width:390,height:844}});
  const page = await context.newPage();
  const errors=[];
  page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto(process.argv[2]);
    await page.locator('#credential').fill(process.env.SOSECURITY_IDEMPOTENCY_BROWSER_TOKEN);
    await page.locator('#reference').fill('browser-order');
    const key=await page.locator('#request-key').inputValue();
    await page.locator('#submit-order').click();
    await page.waitForFunction(() => document.getElementById('status').textContent==='订单已提交。');
    const first=await page.locator('#result').textContent();
    await page.locator('#submit-order').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.includes('未再次创建订单'));
    if (await page.locator('#result').textContent()!==first || await page.locator('#request-key').inputValue()!==key) throw Error('Replay changed the result or key');
    await page.locator('#new-key').click();
    if (await page.locator('#request-key').inputValue()===key) throw Error('New key did not change');
    await page.locator('#submit-order').click();
    await page.waitForFunction(() => document.getElementById('status').textContent==='订单已提交。');
    if (await page.locator('#result').textContent()!==first) throw Error('Business uniqueness changed the original receipt');
    const privacy=await page.evaluate(() => ({cookies:document.cookie,local:localStorage.length,session:sessionStorage.length,overflow:document.documentElement.scrollWidth>innerWidth,body:document.body.innerText}));
    if (privacy.cookies || privacy.local || privacy.session || privacy.overflow || privacy.body.includes(process.env.SOSECURITY_IDEMPOTENCY_BROWSER_TOKEN) || errors.length) throw Error('Unexpected browser state or script error');
    await page.screenshot({path:process.env.SOSECURITY_IDEMPOTENCY_BROWSER_SCREENSHOT || '/tmp/sosecurity-idempotency-mobile.png',fullPage:true});
    console.log('PASS real mobile Chromium idempotency submit, replay, business uniqueness, safe text output and no credential persistence');
  } finally {await context.close();await browser.close();}
})().catch(error => {console.error(error.message);process.exit(1);});
