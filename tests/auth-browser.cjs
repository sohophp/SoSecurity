'use strict';
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
(async () => {
    const browser = await chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 390, height: 844}});
    const page = await context.newPage(); const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const base = process.argv[2];
    const state = async () => JSON.parse(await page.locator('[data-demo-state]').textContent());
    async function ajax(action) {
        const form = page.locator('[data-demo-form]').filter({has: page.locator(`button[name="action"][value="${action}"]`)});
        await form.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption(action);
        const [response] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST' && r.url().includes('module=auth')), form.locator('[data-ajax]').click()]);
        const result = await response.json();
        const expected = `HTTP ${response.status()}\n${JSON.stringify(result.result ?? result, null, 2)}`;
        await page.waitForFunction(({action, expected}) => document.querySelector(`button[name="action"][value="${action}"]`).closest('form').querySelector('.ajax-output').textContent === expected, {action, expected});
        return [response.status(), result];
    }
    try {
        await page.goto(base + '?module=auth'); assert.equal((await state()).authenticated, false);
        const before = (await context.cookies()).find(cookie => cookie.name === 'SoSecurityDemo').value;
        await page.locator('input[name="auth_password"]').fill('Demo-only-7.2!');
        await Promise.all([page.waitForNavigation(), page.locator('button[name="action"][value="login"]').click()]);
        assert.equal((await state()).authenticated, true);
        const after = (await context.cookies()).find(cookie => cookie.name === 'SoSecurityDemo').value; assert.notEqual(before, after);
        const id = (await state()).current_id;
        assert.equal((await ajax('recent'))[0], 403); assert.equal((await state()).recent_authentication, false);
        await page.locator('input[name="auth_password"]').fill('Demo-only-7.2!');
        assert.equal((await ajax('reauthenticate'))[0], 200); assert.equal((await state()).current_id, id);
        assert.equal((await state()).recent_authentication, true);
        assert.equal((await ajax('roles_change'))[0], 200); assert.equal((await state()).authenticated, false);
        await page.locator('input[name="auth_password"]').fill('Demo-only-7.2!'); assert.equal((await ajax('login'))[0], 200);
        assert.deepEqual((await state()).roles, ['reader']);
        const other = await browser.newContext(); const stranger = await other.newPage();
        await stranger.goto(base + '?module=auth'); assert.equal(JSON.parse(await stranger.locator('[data-demo-state]').textContent()).authenticated, false);
        await other.close();
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        await page.screenshot({path: '/tmp/sosecurity-auth-mobile.png', fullPage: true});
        assert.equal((await ajax('source_failure'))[0], 503);
        assert.equal((await ajax('clear'))[0], 200); assert.equal((await state()).authenticated, false);
        assert.deepEqual(errors, []);
        console.log('PASS authentication Chromium mobile: native login/Cookie rotation, AJAX reauthentication, permission-version revocation, visitor isolation and layout');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
