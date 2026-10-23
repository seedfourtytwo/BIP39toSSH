const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createApp } = require('../src/server');

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function start(t) {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'bip39tossh-srv-'));
    const root = path.join(parent, 'app');
    fs.mkdirSync(root);
    const app = createApp({ root });
    const server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    t.after(() => {
        server.close();
        fs.rmSync(parent, { recursive: true, force: true });
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (url, body) => fetch(base + url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    return { parent, root, base, post, port: server.address().port };
}

function assertHardened(res) {
    assert.match(res.headers.get('cache-control') || '', /no-store/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    const csp = res.headers.get('content-security-policy') || '';
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.doesNotMatch(csp, /script-src[^;]*'unsafe-inline'/);
    assert.equal(res.headers.get('x-powered-by'), null);
}

test('the page is served with security headers and loads nothing from outside', async (t) => {
    const { base } = await start(t);
    const res = await fetch(base + '/');
    assert.equal(res.status, 200);
    assertHardened(res);
    const html = await res.text();
    assert.doesNotMatch(html, /(src|href)=["']https?:\/\//);
    const nonce = /script-src[^;]*'nonce-([^']+)'/.exec(res.headers.get('content-security-policy'))[1];
    for (const tag of html.match(/<script\b[^>]*>/g)) {
        assert.ok(tag.includes(`nonce="${nonce}"`), `script without nonce: ${tag}`);
    }
    assert.doesNotMatch(html, /\son[a-z]+=["']/i, 'inline event handlers are blocked by the CSP');
});

test('responses that carry keys are never cached', async (t) => {
    const { post } = await start(t);
    const res = await post('/generate', { action: 'existing', mnemonic: MNEMONIC, count: 1 });
    assert.equal(res.status, 200);
    assertHardened(res);
});

test('a request for another host name is refused (DNS rebinding)', async (t) => {
    const { port } = await start(t);
    const status = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/', headers: { Host: `attacker.example:${port}` } }, (res) => {
            res.resume();
            resolve(res.statusCode);
        }).on('error', reject);
    });
    assert.equal(status, 403);
});

test('a cross-site form post is not parsed', async (t) => {
    const { base, root } = await start(t);
    const res = await fetch(base + '/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=existing&mnemonic=${encodeURIComponent(MNEMONIC)}&count=1`
    });
    assert.equal(res.status, 400);
    assert.equal(fs.existsSync(path.join(root, 'src', 'generated-keys')), false);
});

test('the key count is bounded', async (t) => {
    const { post } = await start(t);
    for (const count of [0, 11, 'lots', 1e9]) {
        const res = await post('/generate', { action: 'existing', mnemonic: MNEMONIC, count });
        assert.equal(res.status, 400, `count ${count}`);
    }
    const paths = Array.from({ length: 11 }, (_, i) => `m/44'/0'/0'/0/${i}`);
    const res = await post('/restore', { mnemonic: MNEMONIC, derivationPaths: paths });
    assert.equal(res.status, 400);
});

test('the output folder cannot leave the app folder, even by a shared name prefix', async (t) => {
    const { post, parent } = await start(t);
    for (const outputDir of ['../outside', '../app-evil', '/tmp']) {
        const res = await post('/generate', { action: 'existing', mnemonic: MNEMONIC, count: 1, outputDir });
        assert.equal(res.status, 400, outputDir);
    }
    assert.equal(fs.existsSync(path.join(parent, 'app-evil')), false);
});

test('read-key returns generated keys and nothing else', async (t) => {
    const { base, post, root, parent } = await start(t);
    const gen = await (await post('/generate', { action: 'existing', mnemonic: MNEMONIC, count: 1 })).json();
    const ok = await fetch(`${base}/read-key?path=${encodeURIComponent(gen.keys[0].publicKeyPath)}`);
    assert.equal(ok.status, 200);
    assertHardened(ok);
    assert.match(await ok.text(), /^ssh-ed25519 /);

    fs.writeFileSync(path.join(root, 'notes.txt'), 'secret');
    const sibling = path.join(parent, 'app-evil');
    fs.mkdirSync(sibling);
    fs.writeFileSync(path.join(sibling, 'id_ed25519'), 'secret');
    for (const p of ['notes.txt', path.join(root, 'notes.txt'), path.join(sibling, 'id_ed25519'), '../app-evil/id_ed25519', '/etc/passwd']) {
        const res = await fetch(`${base}/read-key?path=${encodeURIComponent(p)}`);
        assert.ok(res.status === 400 || res.status === 404, `${p} -> ${res.status}`);
        assert.doesNotMatch(await res.text(), /secret|root:/);
    }
});
