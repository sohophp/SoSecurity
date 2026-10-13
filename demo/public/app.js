'use strict';
function renderCaptcha(container, challenge) {
    if (!challenge) { return; }
    if (container.dataset.challengeId === challenge.id) { return; }
    container.dataset.challengeId = challenge.id;
    container.replaceChildren();
    const prompt = document.createElement('strong'); prompt.textContent = challenge.prompt;
    container.append(prompt);
    document.querySelectorAll('input[name="challenge_id"]').forEach(input => { input.value = challenge.id; });
    const answer = document.querySelector('input[name="answer"]');
    if (answer) { answer.value = ''; }
    const metadata = challenge.presentation || {};
    if (!challenge.image) { return; }
    const surface = document.createElement('div');
    surface.className = 'captcha-surface';
    const picture = document.createElement('img'); picture.alt = '图片验证码'; picture.src = challenge.image;
    surface.append(picture); container.append(surface);
    if (metadata.kind === 'slider') {
        surface.classList.add('captcha-slider');
        const piece = document.createElement('img'); piece.alt = '移动拼图片段'; piece.src = metadata.piece;
        piece.className = 'captcha-piece';
        piece.style.width = `${metadata.piece_width / metadata.width * 100}%`;
        piece.style.top = `${metadata.piece_y / metadata.height * 100}%`;
        surface.append(piece);
        const label = document.createElement('label'); label.textContent = '拖动或用方向键移动拼图';
        const range = document.createElement('input'); range.type = 'range'; range.min = '0';
        range.max = String(metadata.width - metadata.piece_width); range.step = '1'; range.value = '0';
        range.setAttribute('aria-label', '拼图水平位置');
        range.addEventListener('input', () => {
            piece.style.left = `${Number(range.value) / metadata.width * 100}%`;
            if (answer) { answer.value = range.value; }
        });
        label.append(range); container.append(label);
    } else if (metadata.kind === 'click') {
        const grid = document.createElement('div'); grid.className = 'captcha-grid';
        const selected = [];
        const status = document.createElement('p'); status.setAttribute('aria-live', 'polite');
        const update = () => { status.textContent = `已选择 ${selected.length} / ${metadata.count} 个字符`; if (answer) { answer.value = selected.join(','); } };
        for (let i = 0; i < metadata.rows * metadata.columns; ++i) {
            const cell = document.createElement('button'); cell.type = 'button';
            cell.setAttribute('aria-label', `第 ${i + 1} 格`); cell.setAttribute('aria-pressed', 'false');
            cell.addEventListener('click', () => {
                if (selected.includes(i) || selected.length >= metadata.count) { return; }
                selected.push(i); cell.textContent = String(selected.length); cell.setAttribute('aria-pressed', 'true'); update();
            });
            grid.append(cell);
        }
        surface.append(grid); container.append(status);
        const reset = document.createElement('button'); reset.type = 'button'; reset.className = 'secondary'; reset.textContent = '重新点选';
        reset.addEventListener('click', () => {
            selected.length = 0; grid.querySelectorAll('button').forEach(cell => { cell.textContent = ''; cell.setAttribute('aria-pressed', 'false'); }); update();
        });
        container.append(reset); update();
    }
}
document.querySelectorAll('[data-captcha]').forEach(container => {
    try { renderCaptcha(container, JSON.parse(container.dataset.captcha)); } catch (_) { container.textContent = '验证码无法显示，请重新生成。'; }
});

async function prepareProvider(form) {
    const widget = form.querySelector('[data-recaptcha-v3]');
    if (!widget) { return; }
    if (!window.grecaptcha?.ready || !window.grecaptcha?.execute) { throw new Error('Provider unavailable'); }
    let deadline;
    try {
        const request = new Promise(resolve => window.grecaptcha.ready(resolve))
            .then(() => window.grecaptcha.execute(widget.dataset.recaptchaV3, {action: 'demo'}));
        const token = await Promise.race([request, new Promise((_, reject) => {
            deadline = setTimeout(() => reject(new Error('Provider timeout')), 10000);
        })]);
        if (typeof token !== 'string' || token.length === 0 || token.length > 8192) { throw new Error('Invalid provider token'); }
        form.querySelector('input[name="g-recaptcha-response"]').value = token;
    } finally { clearTimeout(deadline); }
}
document.querySelectorAll('[data-demo-form]').forEach((form) => {
    if (form.querySelector('[data-recaptcha-v3]')) {
        form.addEventListener('submit', async event => {
            event.preventDefault();
            if (form.dataset.submitting) { return; }
            form.dataset.submitting = '1';
            try {
                await prepareProvider(form);
                const action = document.createElement('input'); action.type = 'hidden'; action.name = 'action'; action.value = 'recaptcha_v3'; form.append(action);
                HTMLFormElement.prototype.submit.call(form);
            } catch (_) { const output = form.querySelector('.ajax-output'); output.dataset.visible = ''; output.textContent = '外部验证码服务不可用，请稍后重试。'; delete form.dataset.submitting; }
        });
    }
    const ajax = form.querySelector('[data-ajax]');
    const choices = document.createElement('select');
    choices.setAttribute('aria-label', '选择 AJAX 演示操作');
    form.querySelectorAll('button[name="action"]').forEach((button) => {
        const option = document.createElement('option');
        option.value = button.value;
        option.textContent = button.textContent;
        choices.append(option);
    });
    form.insertBefore(choices, ajax);
    ajax.textContent = 'AJAX 提交';
    ajax.addEventListener('click', async () => {
        if (!choices.value || ajax.disabled) { return; }
        ajax.disabled = true;
        const output = form.querySelector('.ajax-output');
        output.dataset.visible = '';
        output.textContent = '正在提交…';
        try {
            await prepareProvider(form);
            const data = new FormData(form);
            data.set('action', choices.value);
            const response = await fetch(window.location.href, {method: 'POST', body: data,
                credentials: 'same-origin', headers: {'Accept': 'application/json'}});
            const result = await response.json();
            if (choices.value === 'turnstile' && window.turnstile?.reset) { window.turnstile.reset(); }
            if (choices.value === 'hcaptcha' && window.hcaptcha?.reset) { window.hcaptcha.reset(); }
            if (choices.value === 'recaptcha' && window.grecaptcha?.reset) { window.grecaptcha.reset(); }
            output.textContent = `HTTP ${response.status}\n${JSON.stringify(result.result ?? result, null, 2)}`;
            if (result.controls_token) {
                document.querySelectorAll('input[name="_csrf"]').forEach((input) => { input.value = result.controls_token; });
            }
            if (result.state?.token) {
                document.querySelectorAll('input[name="token"]').forEach((input) => { input.value = result.state.token; });
            }
            if (result.state?.challenge) {
                const challenge = result.state.challenge;
                const container = document.querySelector('.challenge');
                if (container) {
                    renderCaptcha(container, challenge);
                } else { window.location.reload(); }
            }
            const state = document.querySelector('[data-demo-state]');
            if (state && result.state) {
                const display = {...result.state};
                if (display.challenge?.image) {
                    display.challenge = {...display.challenge, image: '[PNG 图片已在上方显示]', presentation: {...display.challenge.presentation}};
                    if (display.challenge.presentation.piece) { display.challenge.presentation.piece = '[PNG 拼图片段已在上方显示]'; }
                }
                state.textContent = JSON.stringify(display, null, 2);
            }
            form.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ''; });
        } catch (_) { output.textContent = '演示服务暂时不可用，请刷新后重试。'; }
        finally { ajax.disabled = false; }
    });
});
