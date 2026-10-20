'use strict';
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const {chromium} = require(process.env.SOSECURITY_PLAYWRIGHT_MODULE || 'playwright');

const [php, backend, primary, alternate] = process.argv.slice(2);
function call(action, handle = '', id = '', body = '') {
    const result = spawnSync(php, [backend, action, handle, id], {
        env: process.env, input: body, encoding: 'utf8', maxBuffer: 1024 * 1024,
    });
    return {ok: result.status === 0, value: result.status === 0 ? JSON.parse(result.stdout) : null,
        error: result.stderr};
}

(async () => {
    const browser = await chromium.launch({headless: true});
    const context = await browser.newContext({ignoreHTTPSErrors: true});
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    try {
        await cdp.send('WebAuthn.enable');
        const virtualOptions = {
            protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
            hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
        };
        const firstAuthenticator = (await cdp.send('WebAuthn.addVirtualAuthenticator',
            {options: virtualOptions})).authenticatorId;
        await page.goto(primary);
        assert.equal(await page.evaluate(() => isSecureContext && !!navigator.credentials), true);
        async function browserCredential(kind, options) {
            return page.evaluate(async ({kind, options}) => {
                function bytes(encoded) {
                    const padded = encoded.replace(/-/g, '+').replace(/_/g, '/');
                    const raw = atob(padded);
                    return Uint8Array.from(raw, value => value.charCodeAt(0));
                }
                function encode(data) {
                    return btoa(String.fromCharCode(...new Uint8Array(data)))
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                }
                let publicKey;
                if (kind === 'create') {
                    publicKey = PublicKeyCredential.parseCreationOptionsFromJSON
                        ? PublicKeyCredential.parseCreationOptionsFromJSON(options)
                        : {...options, challenge: bytes(options.challenge),
                            user: {...options.user, id: bytes(options.user.id)},
                            excludeCredentials: options.excludeCredentials.map(item => ({...item, id: bytes(item.id)}))};
                } else {
                    publicKey = PublicKeyCredential.parseRequestOptionsFromJSON
                        ? PublicKeyCredential.parseRequestOptionsFromJSON(options)
                        : {...options, challenge: bytes(options.challenge),
                            allowCredentials: options.allowCredentials.map(item => ({...item, id: bytes(item.id)}))};
                }
                const credential = await navigator.credentials[kind]({publicKey});
                if (credential.toJSON) { return credential.toJSON(); }
                const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
                if (kind === 'create') { response.attestationObject = encode(credential.response.attestationObject); }
                else {
                    response.authenticatorData = encode(credential.response.authenticatorData);
                    response.signature = encode(credential.response.signature);
                    response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;
                }
                return {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
                    response, clientExtensionResults: credential.getClientExtensionResults()};
            }, {kind, options});
        }
        let pending = call('begin-register'); assert.equal(pending.ok, true, pending.error);
        const created = await browserCredential('create', pending.value.options);
        let finished = call('finish-register', pending.value.handle, '', JSON.stringify(created));
        assert.equal(finished.ok, true, finished.error);
        assert.equal(finished.value.id, created.rawId);
        assert.equal(call('status').value.devices, 1);
        assert.equal(call('finish-register', pending.value.handle, '', JSON.stringify(created)).ok, false);
        const signal = call('signal');
        assert.equal(signal.ok, true, signal.error);
        assert.equal(signal.value.rpId, 'localhost');
        assert.deepEqual(signal.value.allAcceptedCredentialIds, [created.rawId]);
        assert.equal(await page.evaluate(async data => {
            if (typeof PublicKeyCredential.signalAllAcceptedCredentials !== 'function') { return false; }
            await PublicKeyCredential.signalAllAcceptedCredentials(data);
            return true;
        }, signal.value), true);

        async function login(origin = primary, expectSuccess = true) {
            await page.goto(origin);
            const request = call('begin-login'); assert.equal(request.ok, true, request.error);
            const asserted = await browserCredential('get', request.value.options);
            const result = call('finish-login', request.value.handle, asserted.rawId, JSON.stringify(asserted));
            assert.equal(result.ok, expectSuccess, result.error);
            return {request, asserted, result};
        }
        let verified = await login();
        assert.equal(verified.result.value.id, created.rawId);
        assert.equal(call('finish-login', verified.request.value.handle, verified.asserted.rawId,
            JSON.stringify(verified.asserted)).ok, false);
        let fresh = call('begin-login'); assert.equal(fresh.ok, true, fresh.error);
        const stale = call('finish-login', fresh.value.handle, verified.asserted.rawId,
            JSON.stringify(verified.asserted));
        assert.equal(stale.ok, false);
        assert.match(stale.error, /challenge/i);
        fresh = call('begin-login'); assert.equal(fresh.ok, true, fresh.error);
        const signed = await browserCredential('get', fresh.value.options);
        const altered = structuredClone(signed);
        const signature = altered.response.signature;
        altered.response.signature = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
        const tampered = call('finish-login', fresh.value.handle, altered.rawId,
            JSON.stringify(altered));
        assert.equal(tampered.ok, false);
        assert.match(tampered.error, /signature/i);
        const wrongOrigin = await login(alternate, false);
        assert.match(wrongOrigin.result.error, /origin/i);
        verified = await login();
        assert.equal(verified.result.value.id, created.rawId);
        assert.equal(call('status').value.devices, 1);
        assert.equal((await cdp.send('WebAuthn.getCredentials',
            {authenticatorId: firstAuthenticator})).credentials.length, 1);
        const secondAuthenticator = (await cdp.send('WebAuthn.addVirtualAuthenticator',
            {options: {...virtualOptions, transport: 'usb'}})).authenticatorId;
        pending = call('begin-register'); assert.equal(pending.ok, true, pending.error);
        const second = await browserCredential('create', pending.value.options);
        finished = call('finish-register', pending.value.handle, '', JSON.stringify(second));
        assert.equal(finished.ok, true, finished.error);
        assert.equal(call('status').value.devices, 2);
        assert.equal((await cdp.send('WebAuthn.getCredentials',
            {authenticatorId: secondAuthenticator})).credentials.length, 1);
        const removed = call('remove', '', created.rawId);
        assert.equal(removed.ok, true, removed.error);
        assert.equal(removed.value.removed, true);
        assert.equal(call('status').value.devices, 1);
        const remaining = call('signal');
        assert.equal(remaining.ok, true, remaining.error);
        assert.deepEqual(remaining.value.allAcceptedCredentialIds, [second.rawId]);
        await page.evaluate(async data => PublicKeyCredential.signalAllAcceptedCredentials(data), remaining.value);
        assert.equal((await cdp.send('WebAuthn.getCredentials',
            {authenticatorId: firstAuthenticator})).credentials.length, 0);
        assert.equal((await cdp.send('WebAuthn.getCredentials',
            {authenticatorId: secondAuthenticator})).credentials.length, 1);
        console.log('WebAuthn Chromium virtual authenticator: register, signal, login, rejection paths and post-removal credential sync passed');
    } finally {
        await cdp.detach();
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
