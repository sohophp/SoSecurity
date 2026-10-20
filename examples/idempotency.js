'use strict';
(() => {
  const form = document.getElementById('order-form');
  const credential = document.getElementById('credential');
  const key = document.getElementById('request-key');
  const status = document.getElementById('status');
  const result = document.getElementById('result');
  const submit = document.getElementById('submit-order');
  const next = document.getElementById('new-key');
  const newKey = () => {
    if (!globalThis.crypto || !globalThis.crypto.getRandomValues) {
      status.textContent = '当前浏览器无法安全生成请求键，请使用支持的浏览器和 HTTPS。';
      submit.disabled = true;
      return;
    }
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
    key.value = 'order-' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  };
  newKey();
  next.addEventListener('click', newKey);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    submit.disabled = true;
    next.disabled = true;
    status.textContent = '正在提交，请保留当前请求键。';
    try {
      const response = await fetch(location.pathname, {
        method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
        headers: { 'Authorization': 'Bearer ' + credential.value, 'Content-Type': 'application/json', 'Idempotency-Key': key.value },
        body: JSON.stringify({ reference: document.getElementById('reference').value, amount: Number(document.getElementById('amount').value) })
      });
      const data = await response.json();
      const replay = response.headers.get('Idempotency-Replayed') === 'true';
      status.textContent = response.ok ? (replay ? '已返回原请求结果，未再次创建订单。' : '订单已提交。') : '请求未完成：HTTP ' + response.status + '。请核对结果并保留原请求键。';
      result.textContent = JSON.stringify(data, null, 2);
    } catch (_) {
      status.textContent = '尚未确认处理结果。请保留原请求键和业务参考编号重试。';
      result.textContent = '未取得可确认的响应。';
    } finally {
      submit.disabled = false;
      next.disabled = false;
    }
  });
})();
