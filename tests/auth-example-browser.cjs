'use strict';
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const fixture = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
function proof(uri) {
    const seed = new URL(uri).searchParams.get('secret'); const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let buffer = 0, bits = 0; const bytes = [];
    for (const character of seed) { buffer = (buffer << 5) | alphabet.indexOf(character); bits += 5; if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 255); } buffer &= (1 << bits) - 1; }
    const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + 1));
    const mac = crypto.createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
    return String((mac.readUInt32BE(mac[mac.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}
(async () => {
    const browser = await chromium.launch({headless: true}); const context = await browser.newContext({viewport: {width: 390, height: 844}});
    const page = await context.newPage(); const errors = []; page.on('pageerror', error => errors.push(error.message));
    const state = async () => JSON.parse(await page.locator('main > pre').textContent());
    const submit = async action => { await Promise.all([page.waitForNavigation(), page.locator(`button[name="action"][value="${action}"]`).click()]); };
    try {
        await page.goto(process.argv[2]); assert.equal((await state()).stage, 'anonymous');
        const before = (await context.cookies()).find(cookie => cookie.name === 'SoSecurityAuthExample').value;
        await page.locator('[name="username"]').fill('demo'); await page.locator('[name="password"]').fill('Correct-test-password');
        await submit('login'); assert.equal((await state()).stage, 'mfa_required'); assert.equal((await state()).session, null);
        await page.locator('[name="proof"]').fill(proof(fixture.uri)); await submit('mfa');
        const current = (await state()).session; assert.equal(current.strength, 2); assert.equal(current.method, 'totp');
        assert.notEqual((await context.cookies()).find(cookie => cookie.name === 'SoSecurityAuthExample').value, before);
        await submit('list'); assert.equal((await state()).sessions.length, 1);
        await new Promise(resolve => setTimeout(resolve, 5100)); await submit('sensitive'); assert.equal((await state()).error, 'auth.reauthentication_required');
        await page.locator('[name="username"]').fill('demo'); await page.locator('[name="password"]').fill('Correct-test-password'); await submit('reauthenticate');
        await page.locator('[name="type"]').selectOption('recovery'); await page.locator('[name="proof"]').fill(fixture.recovery[0]); await submit('mfa');
        const renewed = (await state()).session; assert.equal(renewed.method, 'recovery'); assert.equal(renewed.id, current.id); assert.equal(renewed.expires_at, current.expires_at);
        await submit('sensitive'); assert.equal((await state()).allowed, true);
        // A second real session makes the revocation check observable without logging out this browser.
        const peerContext = await browser.newContext(); const peer = await peerContext.newPage();
        await peer.goto(process.argv[2]);
        await peer.locator('[name="username"]').fill('demo'); await peer.locator('[name="password"]').fill('Correct-test-password');
        await Promise.all([peer.waitForNavigation(), peer.locator('button[value="login"]').click()]);
        await peer.locator('[name="type"]').selectOption('recovery'); await peer.locator('[name="proof"]').fill(fixture.recovery[2]);
        await Promise.all([peer.waitForNavigation(), peer.locator('button[value="mfa"]').click()]);
        const peerSession = JSON.parse(await peer.locator('main > pre').textContent()).session;
        assert.notEqual(peerSession.id, renewed.id); await peerContext.close();
        await submit('remember'); assert.equal((await state()).remembered, true);
        const persistent = (await context.cookies()).find(cookie => cookie.name === 'SoSecurityRememberLocal');
        assert.equal(persistent.httpOnly, true); assert.equal(persistent.sameSite, 'Lax'); assert.equal(persistent.path, '/');
        assert.equal(await page.evaluate(() => document.cookie.includes('sorp1.')), false);
        await context.clearCookies(); await context.addCookies([persistent]); await page.goto(process.argv[2]);
        assert.equal((await state()).stage, 'anonymous'); await submit('restore');
        assert.equal((await state()).stage, 'authenticated'); assert.equal((await state()).session.resumed, true);
        assert.equal((await state()).session.method, 'recovery');
        assert.notEqual((await context.cookies()).find(cookie => cookie.name === 'SoSecurityRememberLocal').value, persistent.value);
        await submit('sensitive'); assert.equal((await state()).error, 'auth.reauthentication_required');
        await submit('remember'); assert.equal((await state()).error, 'auth.reauthentication_required');
        await page.locator('[name="session_id"]').fill(peerSession.id); await submit('revoke');
        if ((await state()).revoked === true) {
            await submit('list'); assert.equal((await state()).sessions.some(item => item.id === peerSession.id), false);
            throw new Error('UNSAFE_SESSION_TERMINATION_WITHOUT_REAUTH');
        }
        assert.equal((await state()).error, 'auth.reauthentication_required');
        await submit('list'); assert.equal((await state()).sessions.some(item => item.id === peerSession.id), true);
        await submit('logout_all'); assert.equal((await state()).error, 'auth.reauthentication_required');
        assert.equal((await state()).stage, 'authenticated');
        await page.locator('[name="username"]').fill('demo'); await page.locator('[name="password"]').fill('Correct-test-password'); await submit('reauthenticate');
        await page.locator('[name="type"]').selectOption('recovery'); await page.locator('[name="proof"]').fill(fixture.recovery[1]); await submit('mfa');
        await submit('sensitive'); assert.equal((await state()).allowed, true); assert.equal((await state()).session.resumed, false);
        await page.locator('[name="session_id"]').fill(peerSession.id); await submit('revoke');
        assert.equal((await state()).revoked, true);
        await submit('list'); assert.equal((await state()).sessions.some(item => item.id === peerSession.id), false);
        await submit('remember_list'); assert.equal((await state()).grants.length, 1);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        assert.equal('csrf' in await state(), false); // It stays in hidden form fields, not the diagnostic display.
        await page.screenshot({path: '/tmp/sosecurity-auth-example-mobile.png', fullPage: true});
        await submit('logout_all'); assert.equal((await state()).stage, 'anonymous'); assert.deepEqual(errors, []);
        assert.equal((await context.cookies()).some(cookie => cookie.name === 'SoSecurityRememberLocal'), false);
        console.log('PASS standalone authentication Chromium: password/TOTP/recovery, persistent Cookie restore/rotation, freshness and reauthentication, logout-all and mobile layout');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
