'use strict';
const assert = require('node:assert/strict');
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');

(async () => {
    const browser = await chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 390, height: 844}});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        const url = process.env.SOSECURITY_MANAGED_AUTH_URL;
        const first = await page.goto(url);
        assert.equal(first.status(), 200);
        assert.equal(first.headers()['cache-control'], 'no-store');
        assert.equal(await page.locator('button[value="login"]').count(), 1);
        const before = (await context.cookies()).find(cookie => cookie.name === 'SoSecurityManagedExample');
        assert.equal(before.httpOnly, true);
        await page.locator('input[name="username"]').fill('owned@example.test');
        await page.locator('input[name="password"]').fill(process.env.SOSECURITY_MANAGED_AUTH_PASSWORD);
        const [passwordResponse] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'),
            page.locator('button[value="login"]').click()]);
        assert.equal(passwordResponse.status(), 200);
        assert.equal(await page.locator('button[value="mfa"]').count(), 1);
        assert.equal((await context.cookies()).find(cookie => cookie.name === 'SoSecurityManagedExample').value, before.value);
        await page.locator('select[name="type"]').selectOption('recovery');
        await page.locator('input[name="proof"]').fill(process.env.SOSECURITY_MANAGED_AUTH_RECOVERY);
        const [factorResponse] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'),
            page.locator('button[value="mfa"]').click()]);
        assert.equal(factorResponse.status(), 200);
        assert.equal(await page.locator('button[value="logout"]').count(), 1);
        assert.notEqual((await context.cookies()).find(cookie => cookie.name === 'SoSecurityManagedExample').value, before.value);
        assert.equal(await page.evaluate(() => document.cookie.includes('SoSecurityManagedExample=')), false);
        assert.equal((await page.locator('body').innerText()).includes(process.env.SOSECURITY_MANAGED_AUTH_RECOVERY), false);
        const [logoutResponse] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'),
            page.locator('button[value="logout"]').click()]);
        assert.equal(logoutResponse.status(), 200);
        assert.equal(await page.locator('button[value="login"]').count(), 1);
        assert.deepEqual(errors, []);
        console.log('PASS managed MFA Chromium: form login, recovery proof, HttpOnly rotation, no-store and logout');
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
