'use strict';
// Optional visual workflow acceptance using an existing Playwright installation.
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
(async () => {
    const browser = await chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 390, height: 844}});
    const page = await context.newPage(); const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const base = process.argv[2] || 'http://72.rocky.wsl/SoSecurity/';
    async function ajax(action) {
        const form = page.locator('[data-demo-form]').filter({has: page.locator(`button[name="action"][value="${action}"]`)});
        await form.locator('select[aria-label="选择 AJAX 演示操作"]').selectOption(action);
        await form.locator('[data-ajax]').click();
        await form.locator('.ajax-output').filter({hasText: /^HTTP /}).waitFor();
        return form.locator('.ajax-output').textContent();
    }
    try {
        await page.goto(base + '?module=captcha');
        await ajax('slider');
        await page.locator('.captcha-surface > img').first().evaluate(image => image.decode());
        const target = await page.locator('.captcha-surface').evaluate(surface => {
            const background = surface.querySelector('img');
            // The current AJAX challenge lives in DOM geometry; derive its solution from public pixels.
            const canvas = document.createElement('canvas'); canvas.width = background.naturalWidth; canvas.height = background.naturalHeight;
            const ctx = canvas.getContext('2d'); ctx.drawImage(background, 0, 0);
            const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
            for (let y = 0; y < canvas.height; ++y) {
                for (let x = 0; x < canvas.width; ++x) {
                    const i = (y * canvas.width + x) * 4;
                    if (pixels[i] === 35 && pixels[i + 1] === 48 && pixels[i + 2] === 65) { return x - 1; }
                }
            }
            throw new Error('No puzzle slot found in public image');
        });
        await page.locator('input[type="range"]').fill(String(target));
        assert.equal(await page.locator('input[name="answer"]').inputValue(), String(target));
        assert.match(await ajax('verify'), /HTTP 200/);
        assert.match(await ajax('verify'), /HTTP 403/);
        await page.locator('.challenge').screenshot({path: '/tmp/sosecurity-captcha-slider-mobile.png'});
        await ajax('click');
        assert.equal(await page.locator('.captcha-grid button').count(), 9);
        await page.locator('.captcha-grid button').nth(0).click();
        await page.locator('.captcha-grid button').nth(0).click();
        assert.equal(await page.locator('input[name="answer"]').inputValue(), '0');
        await page.getByRole('button', {name: '重新点选'}).click();
        assert.equal(await page.locator('input[name="answer"]').inputValue(), '');
        // Read public letter shapes against independently generated GD font templates; no private answer API.
        const php = process.env.SOSECURITY_BROWSER_PHP || 'php72';
        const templateCode = '$result=[];foreach(str_split("ABCDEFGHJKLMNPQRSTUVWXYZ") as $letter){$i=imagecreatetruecolor(9,16);imagefill($i,0,0,imagecolorallocate($i,235,242,250));imagechar($i,5,0,0,$letter,imagecolorallocate($i,25,45,70));ob_start();imagepng($i);$result[$letter]=base64_encode(ob_get_clean());if(PHP_VERSION_ID<80000){imagedestroy($i);}}echo json_encode($result);';
        const templates = JSON.parse(execFileSync(php, ['-r', templateCode], {encoding: 'utf8'}));
        const indices = await page.locator('.captcha-surface > img').evaluate(async (image, templates) => {
            await image.decode();
            const canvas = document.createElement('canvas'); canvas.width = image.naturalWidth; canvas.height = image.naturalHeight;
            const ctx = canvas.getContext('2d'); ctx.drawImage(image, 0, 0);
            const bitmap = ctx.getImageData(0, 0, 300, 180).data;
            const patterns = {};
            for (const [letter, png] of Object.entries(templates)) {
                const template = new Image(); template.src = 'data:image/png;base64,' + png; await template.decode();
                const tile = document.createElement('canvas'); tile.width = 9; tile.height = 16;
                const c = tile.getContext('2d'); c.drawImage(template, 0, 0);
                const pixels = c.getImageData(0, 0, 9, 16).data;
                patterns[letter] = Array.from({length: 144}, (_, i) => pixels[i * 4] === 25 && pixels[i * 4 + 1] === 45 && pixels[i * 4 + 2] === 70);
            }
            const cells = [];
            for (let cell = 0; cell < 9; ++cell) {
                let best = {score: Infinity, letter: null};
                for (let offset = 34; offset <= 42; ++offset) {
                    for (const [letter, pattern] of Object.entries(patterns)) {
                        let score = 0;
                        for (let y = 0; y < 16; ++y) { for (let x = 0; x < 9; ++x) {
                            const index = ((Math.floor(cell / 3) * 60 + 8 + y * 3 + 1) * 300 + cell % 3 * 100 + offset + x * 3 + 1) * 4;
                            const ink = bitmap[index] === 25 && bitmap[index + 1] === 45 && bitmap[index + 2] === 70;
                            if (ink !== pattern[y * 9 + x]) { ++score; }
                        } }
                        if (score < best.score) { best = {score, letter}; }
                    }
                }
                if (best.score !== 0) { throw new Error('Glyph recognition test failed'); }
                cells.push(best.letter);
            }
            const prompt = document.querySelector('.challenge strong').textContent;
            return prompt.split('：')[1].split(' → ').map(letter => cells.indexOf(letter));
        }, templates);
        for (const index of indices) {
            await page.locator('.captcha-grid button').nth(index).focus();
            await page.keyboard.press('Enter');
        }
        assert.equal(await page.locator('input[name="answer"]').inputValue(), indices.join(','));
        await page.locator('.challenge').screenshot({path: '/tmp/sosecurity-captcha-click-mobile.png'});
        assert.match(await ajax('verify'), /HTTP 200/);
        assert.match(await ajax('verify'), /HTTP 403/);
        await ajax('digits'); assert.equal(await page.locator('input[type="range"]').count(), 0);
        assert.equal(await page.locator('.captcha-grid').count(), 0);
        await page.locator('button[name="action"][value="slider"]').click();
        await page.locator('input[type="range"]').waitFor();
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        assert.deepEqual(errors, []);
        console.log('PASS actual Chromium CAPTCHA: public-image solving, slider/click server success and replay refusal, keyboard/reset, AJAX type switching, traditional form, 390px layout');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
