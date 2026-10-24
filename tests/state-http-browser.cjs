'use strict';
const assert = require('node:assert/strict');
const { chromium } = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
    const browser = await chromium.launch({headless: true});
    console.log('BROWSER_ENV ' + JSON.stringify({version: browser.version(), module: require.resolve(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright')}));
    const context = await browser.newContext({ignoreHTTPSErrors: true});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        const url = process.env.SOSECURITY_STATE_HTTP_URL;
        const response = await page.goto(url);
        assert.equal(response.status(), 200);
        assert.equal(response.headers()['cache-control'], 'no-store');
        const initial = (await context.cookies()).find(c => c.name === 'SoSecurityManagedExample');
        assert.equal(initial.httpOnly, true);
        assert.equal(initial.sameSite, 'Lax');
        assert.equal(initial.secure, url.startsWith('https:'));
        await page.locator('input[name="username"]').fill('owned@example.test');
        await page.locator('input[name="password"]').fill(process.env.SOSECURITY_STATE_HTTP_PASSWORD);
        const [login] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'), page.locator('button[value="login"]').click()]);
        if (login.status() !== 200) { const h = await login.request().allHeaders(); console.error('OWNED_LOGIN_DIAGNOSTIC ' + JSON.stringify({status: login.status(), origin: h.origin, host: h.host, cookiePresent: Boolean(h.cookie), configured: new URL(url).origin})); }
        assert.equal(login.status(), 200);
        assert.equal((await login.request().allHeaders()).origin, new URL(url).origin);
        assert.equal((await context.cookies()).find(c => c.name === initial.name).value === initial.value, true);
        await page.locator('select[name="type"]').selectOption('recovery');
        await page.locator('input[name="proof"]').fill(process.env.SOSECURITY_STATE_HTTP_RECOVERY);
        const [factor] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'), page.locator('button[value="mfa"]').click()]);
        assert.equal(factor.status(), 200);
        assert.equal((await context.cookies()).find(c => c.name === initial.name).value === initial.value, false);
        assert.equal(await page.evaluate(() => document.cookie.includes('SoSecurityManagedExample=')), false);
        assert.equal((await page.locator('body').innerText()).includes(process.env.SOSECURITY_STATE_HTTP_RECOVERY), false);
        let csrf = await page.locator('input[name="_csrf"]').inputValue();
        const call = async (action, fields = {}, token = csrf) => page.evaluate(async ({url, action, fields, token}) => {
            const response = await fetch(url, {method: 'POST', headers: {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({...fields, action, _csrf: token}).toString()});
            return {status: response.status, data: await response.json(), cache: response.headers.get('cache-control')};
        }, {url, action, fields, token});
        const { execFileSync } = require('node:child_process');
        const state = () => JSON.parse(execFileSync(process.env.SOSECURITY_STATE_HTTP_RUNTIME, [process.env.SOSECURITY_STATE_HTTP_ROOT + '/tests/state-boundary/http-control.php', process.env.SOSECURITY_STATE_HTTP_FIXTURE, 'inspect'], {encoding: 'utf8'}));
        const beforeAttack = state();
        const attack = await context.newPage();
        await attack.goto(process.env.SOSECURITY_STATE_HTTP_ATTACK_ORIGIN);
        const received = attack.waitForRequest(r => r.url() === url && r.method() === 'POST');
        const corsResult = await attack.evaluate(async ({url, csrf}) => {
            try { await fetch(url, {method: 'POST', credentials: 'include', headers: {Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({action: 'api_issue', _csrf: csrf, name: 'Cross origin denied', scopes: 'records:read'}).toString()}); return 'readable'; } catch (expectedCorsDenial) { return 'blocked'; }
        }, {url, csrf});
        const deniedOrigin = await received;
        assert.equal(corsResult, 'blocked');
        const fs = require('node:fs');
        let audit;
        for (let attempt = 0; attempt < 40; attempt++) {
            audit = fs.readFileSync(process.env.SOSECURITY_STATE_HTTP_AUDIT, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)).findLast(row => row.origin === process.env.SOSECURITY_STATE_HTTP_ATTACK_ORIGIN && row.method === 'POST');
            if (audit) break;
            await new Promise(resolve => setTimeout(resolve, 50));
        }
        assert.equal(audit?.status, 403);
        assert.equal(audit.cookie, true);
        assert.deepEqual(state(), beforeAttack);
        await attack.close();
        assert.equal((await call('api_issue', {name: 'Denied browser', scopes: 'records:read'}, 'invalid')).status, 403);
        const business = process.env.SOSECURITY_STATE_HTTP_BUSINESS === '1';
        const issued = await call('api_issue', {name: 'Browser native', scopes: business ? 'records:read,records:write' : 'records:read'});
        assert.equal(issued.status, 200);
        assert.equal(issued.cache, 'no-store');
        assert.ok(issued.data.issued_token.startsWith('ac1.'));
        csrf = issued.data.csrf;
        const listed = await call('api_all');
        assert.equal(listed.status, 200);
        assert.equal(listed.data.credentials.length, 1);
        assert.equal(JSON.stringify(listed.data).includes(issued.data.issued_token), false);
        csrf = listed.data.csrf;
        const bearer = await page.evaluate(async ({url, token}) => {
            const missing = await fetch(url + '?api=identity', {headers: {Accept: 'application/json'}});
            const valid = await fetch(url + '?api=identity', {credentials: 'omit', headers: {Accept: 'application/json', Authorization: 'Bearer ' + token}});
            return {missing: missing.status, valid: valid.status, body: await valid.json()};
        }, {url, token: issued.data.issued_token});
        assert.equal(bearer.missing, 401);
        assert.equal(bearer.valid, 200);
        assert.equal(bearer.body.identity.subject, 'user');
        if (business) {
            const rename = async (version, token) => page.evaluate(async ({url, version, token}) => {
                const response = await fetch(url + '?api=document', {method: 'POST', credentials: token ? 'omit' : 'include', headers: {Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', ...(token ? {Authorization: 'Bearer ' + token} : {})}, body: new URLSearchParams({action: 'rename', id: 'browser', version, title: 'Browser document update'}).toString()});
                return {status: response.status, body: await response.json()};
            }, {url, version, token});
            const beforeCookieOnly = state();
            assert.equal((await rename('1', null)).status, 401);
            assert.deepEqual(state(), beforeCookieOnly);
            const cookiesBeforeBusiness = await context.cookies();
            const changed = await rename('1', issued.data.issued_token);
            assert.equal(changed.status, 200);
            assert.deepEqual(changed.body.document, {id: 'browser', version: 2});
            assert.equal('csrf' in changed.body, false);
            assert.deepEqual(await context.cookies(), cookiesBeforeBusiness);
            const afterBusiness = state();
            assert.equal(afterBusiness.format, 3);
            assert.equal(afterBusiness.matches, true);
            assert.equal(afterBusiness.intent.action, 'api.credentials.execute');
            assert.equal(afterBusiness.documents.find(row => row.id === 'browser').title, 'Browser document update');
            assert.equal((await rename('1', issued.data.issued_token)).status, 403);
            assert.deepEqual(state(), afterBusiness);
            console.log('PASS business Chromium: real credentials-omit Bearer write, Cookie-only and stale-version refusals, format 3 exact execution and unchanged cookies');
        }
        assert.equal((await call('api_revoke_all')).data.revoked, 1);
        const [logout] = await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'), page.locator('button[value="logout"]').click()]);
        assert.equal(logout.status(), 200);
        assert.equal(await page.locator('button[value="login"]').count(), 1);
        assert.deepEqual(errors, []);
        console.log('PASS protected state Chromium: actual forms, recovery factor, Secure/HttpOnly/SameSite rotation, CSRF and actual cross-origin cookies with unchanged state, native API management, Bearer cookie isolation, no repeated secrets, logout');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
