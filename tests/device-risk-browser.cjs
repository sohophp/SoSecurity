'use strict';
// Local test bridge: actual Chromium navigation, fetch and cookie storage.
const readline = require('node:readline');
const { chromium } = require(process.env.SOSECURITY_TEST_PLAYWRIGHT);
(async () => {
  const browser = await chromium.launch({ headless: true });
  const contexts = new Map();
  let next = 0;
  try {
    for await (const line of readline.createInterface({ input: process.stdin })) {
      const command = JSON.parse(line);
      try {
        if (command.action === 'new') {
          const context = await browser.newContext({ extraHTTPHeaders: { Accept: 'application/json' } });
          await context.route('**/*', route => {
            const url = new URL(route.request().url());
            return url.protocol === 'http:' && url.hostname === '127.0.0.1'
              ? route.continue({ headers: { ...route.request().headers(), accept: 'application/json' } }) : route.abort();
          });
          if (command.copy !== undefined) {
            const cookies = await contexts.get(command.copy).context.cookies();
            await context.addCookies(cookies.filter(cookie => cookie.name === 'SoSecurityRememberLocal'));
          }
          const id = ++next;
          contexts.set(id, { context, page: await context.newPage() });
          process.stdout.write(JSON.stringify({ id }) + '\n');
          continue;
        }
        const { context, page } = contexts.get(command.id);
        if (command.action === 'cookie') {
          const cookie = (await context.cookies()).find(cookie => cookie.name === command.name);
          process.stdout.write(JSON.stringify({ value: cookie ? cookie.value : null }) + '\n');
          continue;
        }
        const target = new URL(command.url);
        if (target.hostname !== '127.0.0.1' || target.protocol !== 'http:') throw Error('Local test URL required');
        let response, data;
        if (command.body === null) {
          response = await page.goto(command.url);
        } else {
          const waiting = page.waitForResponse(r => r.url() === command.url && r.request().method() === 'POST');
          data = await page.evaluate(async ({ url, body }) => {
            const result = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body, signal: AbortSignal.timeout(10000) });
            return await result.json();
          }, { url: command.url, body: command.body });
          response = await waiting;
        }
        process.stdout.write(JSON.stringify({ status: response.status(), data: data === undefined ? await response.json() : data, headers: await response.headersArray() }) + '\n');
      } catch (error) {
        process.stdout.write(JSON.stringify({ error: String(error) }) + '\n');
      }
    }
  } finally {
    await browser.close();
  }
})().catch(error => { process.stderr.write(String(error) + '\n'); process.exitCode = 1; });
