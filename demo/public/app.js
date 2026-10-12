'use strict';
document.querySelectorAll('[data-demo-form]').forEach((form) => {
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
            const data = new FormData(form);
            data.set('action', choices.value);
            const response = await fetch(window.location.href, {method: 'POST', body: data,
                credentials: 'same-origin', headers: {'Accept': 'application/json'}});
            const result = await response.json();
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
                    container.replaceChildren();
                    if (challenge.image) {
                        const picture = document.createElement('img'); picture.alt = '图片验证码'; picture.src = challenge.image; container.append(picture);
                    } else { container.textContent = challenge.prompt; }
                    document.querySelectorAll('input[name="challenge_id"]').forEach((input) => { input.value = challenge.id; });
                } else { window.location.reload(); }
            }
            const state = document.querySelector('[data-demo-state]');
            if (state && result.state) {
                const display = {...result.state};
                if (display.challenge?.image) {
                    display.challenge = {...display.challenge, image: '[PNG 图片已在上方显示]'};
                }
                state.textContent = JSON.stringify(display, null, 2);
            }
            form.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ''; });
        } catch (_) { output.textContent = '演示服务暂时不可用，请刷新后重试。'; }
        finally { ajax.disabled = false; }
    });
});
