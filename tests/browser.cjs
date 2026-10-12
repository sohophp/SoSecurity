'use strict';
// Optional browser test only. No Node or browser dependency is introduced into the PHP package.
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({headless: true});
  const context = await browser.newContext({viewport: {width: 390, height: 844}});
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const base = process.argv[2] || 'http://72.rocky.wsl/SoSecurity/';
  async function ajax(action) {
    await page.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption(action);
    await page.locator('[data-ajax]').click();
    await page.waitForFunction(() => document.querySelector('.ajax-output').textContent.startsWith('HTTP '));
    return page.locator('.ajax-output').textContent();
  }
  try {
    await page.goto(base + '?module=validation');
    assert.match(await ajax('valid_sample'), /HTTP 200/);
    const invalid = await ajax('invalid_sample');
    assert.match(invalid, /HTTP 422/); assert.match(invalid, /\/profile\/age/);
    assert.match(await ajax('unknown_sample'), /validation.unknown/);
    await page.locator('textarea[name="json"]').fill(JSON.stringify({profile: {name: '<svg/onload=pwn=1>', age: 20, email: 'a@example.test', kind: 'member'}}));
    assert.match(await ajax('validate'), /HTTP 200/);
    assert.equal(await page.evaluate(() => typeof window.pwn), 'undefined');
    assert.equal(await page.locator('.ajax-output svg').count(), 0);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({path: '/tmp/sosecurity-validation-mobile.png', fullPage: true});
    await page.goto(base + '?module=storage');
    const mysql = await page.locator('select[name="backend"] option[value="mysql"]').count();
    if (mysql) {
      await page.locator('select[name="backend"]').selectOption('mysql');
      assert.match(await ajax('read'), /"count": 0/);
      assert.match(await ajax('increment'), /"count": 1/);
      assert.match(await ajax('isolation'), /"other_namespace_count": 0/);
      const stranger = await browser.newContext();
      const response = await stranger.request.get(base + '?module=storage', {headers: {Accept: 'application/json'}});
      const token = (await response.json()).controls_token;
      const read = await stranger.request.post(base + '?module=storage', {form: {action: 'read', backend: 'mysql', _csrf: token}, headers: {Accept: 'application/json'}});
      assert.equal((await read.json()).result.count, 0);
      await stranger.close();
    } else { console.log('NOT RUN browser MySQL: private demo backend not configured'); }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({path: '/tmp/sosecurity-storage-mobile.png', fullPage: true});
    assert.deepEqual(errors, []);
    console.log('PASS Chromium: validation AJAX/422/localization, inert HTML input, mobile width, configured MySQL count/namespace/visitor isolation');
  } finally { await context.close(); await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
