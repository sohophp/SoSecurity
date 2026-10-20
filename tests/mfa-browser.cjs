'use strict';
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

function otp(uri) {
    const config = new URL(uri).searchParams;
    let buffer = 0, bits = 0; const bytes = [];
    for (const character of config.get('secret')) {
        buffer = (buffer << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(character); bits += 5;
        if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 255); }
        buffer &= (1 << bits) - 1;
    }
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / Number(config.get('period')))));
    const mac = crypto.createHmac(config.get('algorithm').toLowerCase(), Buffer.from(bytes)).update(counter).digest();
    const offset = mac[mac.length - 1] & 15;
    return String((mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** Number(config.get('digits'))).padStart(Number(config.get('digits')), '0');
}

(async () => {
    const browser = await chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 390, height: 844}});
    const page = await context.newPage(); const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const base = process.argv[2];
    async function ajax(action) {
        const form = page.locator('form[data-demo-form]').filter({has: page.locator(`button[name="action"][value="${action}"]`)});
        await form.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption(action);
        const [response] = await Promise.all([
            page.waitForResponse(result => result.request().method() === 'POST' && result.url().includes('module=mfa')),
            form.locator('[data-ajax]').click(),
        ]);
        const result = await response.json();
        const expected = `HTTP ${response.status()}\n${JSON.stringify(result.result ?? result, null, 2)}`;
        await page.waitForFunction(({expected, action}) => {
            const button = document.querySelector(`button[name="action"][value="${action}"]`);
            return button.closest('form').querySelector('.ajax-output').textContent === expected;
        }, {expected, action});
        return [response.status(), result];
    }
    try {
        await page.goto(base + '?module=mfa');
        assert.match(await page.title(), /SoSecurity/);
        let [status, result] = await ajax('begin'); assert.equal(status, 200);
        const uri = result.result.provisioning_uri; const proof = otp(uri);
        const field = page.locator('input[name="mfa_code"]');
        await field.fill(proof);
        [status, result] = await ajax('confirm'); assert.equal(status, 200);
        const codes = result.result.recovery_codes; assert.equal(codes.length, 10);
        assert.equal(result.state.factor.enabled, true);
        [status] = await ajax('verify'); assert.equal(status, 403);
        await field.fill(codes[0]); [status] = await ajax('recovery'); assert.equal(status, 200);
        [status] = await ajax('recovery'); assert.equal(status, 403);
        [status] = await ajax('rotate'); assert.equal(status, 200);
        await field.fill(codes[1]); [status] = await ajax('recovery'); assert.equal(status, 200);
        const state = await page.locator('[data-demo-state]').textContent();
        assert.equal(state.includes('provisioning_uri'), false); assert.equal(state.includes(codes[0]), false);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        // Capture after clearing one-time secret outputs from the page.
        await page.reload();
        await page.screenshot({path: '/tmp/sosecurity-mfa-mobile.png', fullPage: true});
        const other = await browser.newContext(); const stranger = await other.newPage();
        await stranger.goto(base + '?module=mfa');
        assert.equal(JSON.parse(await stranger.locator('[data-demo-state]').textContent()).factor.enabled, false);
        await other.close();
        // Exercise normal browser form submission in addition to AJAX.
        await page.locator('button[name="action"][value="clear"]').click();
        await page.waitForLoadState();
        assert.equal(JSON.parse(await page.locator('[data-demo-state]').textContent()).factor.enabled, false);
        assert.deepEqual(errors, []);
        console.log('PASS MFA Chromium mobile: actual forms/AJAX, independent Node TOTP, replay/recovery, key rotation, visitor isolation, private state and responsive layout');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
