'use strict';
// Configured SDK wiring only: synthetic SDK scripts and intercepted POST responses, never real credentials.
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path');
const net = require('node:net'); const {spawn} = require('node:child_process');
(async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sosecurity-provider-ui-'));
    for (const name of ['storage', 'sessions']) { fs.mkdirSync(path.join(directory, name), {mode: 0o700}); }
    const probe = net.createServer(); await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
    const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
    const env = {...process.env, SOSECURITY_DEMO_STORAGE: path.join(directory, 'storage')};
    for (const provider of ['TURNSTILE', 'HCAPTCHA', 'RECAPTCHA', 'RECAPTCHA_V3']) {
        env[`SOSECURITY_DEMO_${provider}_SECRET`] = 'test-only-not-a-real-credential';
        env[`SOSECURITY_DEMO_${provider}_SITE_KEY`] = 'public-test-sitekey';
    }
    const server = spawn(process.env.SOSECURITY_BROWSER_PHP || 'php72', ['-d', 'session.save_path=' + path.join(directory, 'sessions'), '-S', '127.0.0.1:' + port, '-t', path.resolve(__dirname, '../demo/public')], {env, stdio: ['ignore', 'ignore', 'ignore']});
    let browser;
    try {
        const base = 'http://127.0.0.1:' + port + '/';
        for (let attempt = 0; ; ++attempt) {
            try { await fetch(base); break; } catch (error) { if (attempt > 100 || server.exitCode !== null) { throw error; } await new Promise(resolve => setTimeout(resolve, 30)); }
        }
        browser = await chromium.launch({headless: true}); const page = await browser.newPage(); const scripts = []; const submissions = []; const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.route('https://**/*', async route => {
            const url = route.request().url(); scripts.push(url);
            let body;
            if (url.includes('challenges.cloudflare.com')) { body = 'window.turnstile={reset(){window.turnstileReset=true}};'; }
            else if (url.includes('js.hcaptcha.com')) { body = 'window.hcaptcha={reset(){window.hcaptchaReset=true}};'; }
            else if (url.includes('recaptcha/api.js?render=')) { body = 'window.grecaptcha={ready(cb){cb()},execute(key,options){window.lastV3={key,options};return Promise.resolve("simulated-v3-token")}};'; }
            else { body = 'window.grecaptcha={reset(){window.recaptchaReset=true}};'; }
            await route.fulfill({contentType: 'application/javascript', body});
        });
        await page.route(base + '**', async route => {
            if (route.request().method() !== 'POST') { await route.continue(); return; }
            submissions.push(route.request().postData());
            if (route.request().headers().accept?.includes('application/json')) {
                await route.fulfill({status: 503, contentType: 'application/json', body: JSON.stringify({result: {message: '模拟外部服务故障，未执行真实服务'}})});
            } else { await route.fulfill({contentType: 'text/html', body: '<p>captured native v3 submission</p>'}); }
        });
        await page.goto(base + '?module=captcha');
        assert.equal(scripts.filter(url => url.includes('recaptcha/api.js')).length, 1);
        assert.equal(scripts.some(url => url.includes('recaptchacompat=off')), true);
        for (const [action, flag] of [['turnstile', 'turnstileReset'], ['hcaptcha', 'hcaptchaReset'], ['recaptcha', 'recaptchaReset']]) {
            const form = page.locator('[data-demo-form]').filter({has: page.locator(`button[value="${action}"]`)});
            await form.locator('[data-ajax]').click(); await form.locator('.ajax-output').filter({hasText: /^HTTP 503/}).waitFor();
            assert.equal(await page.evaluate(flag => window[flag], flag), true);
        }
        scripts.length = 0;
        await page.goto(base + '?module=captcha&provider=recaptcha_v3');
        assert.equal(scripts.filter(url => url.includes('recaptcha/api.js')).length, 1);
        assert.equal(scripts.some(url => url.includes('?render=public-test-sitekey')), true);
        const v3Form = page.locator('[data-demo-form]').filter({has: page.locator('button[value="recaptcha_v3"]')});
        await v3Form.locator('[data-ajax]').click(); await v3Form.locator('.ajax-output').filter({hasText: /^HTTP 503/}).waitFor();
        assert.deepEqual(await page.evaluate(() => window.lastV3), {key: 'public-test-sitekey', options: {action: 'demo'}});
        assert.match(submissions.at(-1), /name="g-recaptcha-response"[\s\S]*simulated-v3-token/);
        await v3Form.locator('button[value="recaptcha_v3"]').click();
        await page.getByText('captured native v3 submission').waitFor();
        const native = new URLSearchParams(submissions.at(-1));
        assert.equal(native.get('g-recaptcha-response'), 'simulated-v3-token'); assert.equal(native.get('action'), 'recaptcha_v3');
        assert.deepEqual(errors, []);
        console.log('PASS configured provider UI: SDK separation, hCaptcha compatibility opt-out, AJAX reset, v3 action/fresh token and native form; scripts/POST responses simulated, no live provider acceptance');
    } finally {
        if (browser) { await browser.close(); }
        server.kill('SIGTERM'); await new Promise(resolve => server.once('exit', resolve)); fs.rmSync(directory, {recursive: true, force: true});
    }
})().catch(error => { console.error(error); process.exit(1); });
