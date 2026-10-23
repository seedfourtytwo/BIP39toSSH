const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const BIP39ToSSH = require('../src/bip39ToSSH');

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PATH0 = "m/44'/0'/0'/0/0";

function tmpDir(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bip39tossh-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
}

function hasSshKeygen() {
    try {
        execFileSync('ssh-keygen', ['-?'], { stdio: 'ignore' });
    } catch (e) {
        return e.code !== 'ENOENT';
    }
    return true;
}

test('restored keys are real OpenSSH files that ssh-keygen accepts', { skip: !hasSshKeygen() && 'ssh-keygen not installed' }, async (t) => {
    const dir = tmpDir(t);
    const result = await new BIP39ToSSH(dir).restoreFromSeed(MNEMONIC, [PATH0], 'TREZOR');
    const key = result.keys[0];

    assert.equal(fs.statSync(key.privateKeyPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(key.privateKeyPath)).mode & 0o777, 0o700);

    const fromPrivate = execFileSync('ssh-keygen', ['-y', '-f', key.privateKeyPath], { encoding: 'utf8' });
    const pub = fs.readFileSync(key.publicKeyPath, 'utf8');
    assert.deepEqual(fromPrivate.trim().split(' ').slice(0, 2), pub.trim().split(' ').slice(0, 2));

    // The wire blob carries the pinned public key from the derivation test.
    const blob = Buffer.from(pub.trim().split(' ')[1], 'base64');
    assert.equal(blob.subarray(-32).toString('hex'), '1c5ff956609130e7b745c6ad8bb28ec7b123a4bac282d9487f29dee8cff38fe9');

    const fingerprint = execFileSync('ssh-keygen', ['-l', '-f', key.publicKeyPath], { encoding: 'utf8' });
    assert.match(fingerprint, /^256 SHA256:\S+ .*\(ED25519\)\s*$/);
});

test('the same seed and path always write the same key files', async (t) => {
    const a = await new BIP39ToSSH(tmpDir(t)).restoreFromSeed(MNEMONIC, [PATH0], 'TREZOR');
    const b = await new BIP39ToSSH(tmpDir(t)).restoreFromSeed(MNEMONIC, [PATH0], 'TREZOR');
    assert.equal(fs.readFileSync(a.keys[0].privateKeyPath, 'utf8'), fs.readFileSync(b.keys[0].privateKeyPath, 'utf8'));
    assert.equal(fs.readFileSync(a.keys[0].publicKeyPath, 'utf8'), fs.readFileSync(b.keys[0].publicKeyPath, 'utf8'));
});

test('generate and restore agree on the default paths', async (t) => {
    const gen = await new BIP39ToSSH(tmpDir(t)).deriveSSHKeys(MNEMONIC, 2, 'TREZOR');
    const res = await new BIP39ToSSH(tmpDir(t)).restoreFromSeed(MNEMONIC, [gen.keys[1].derivationPath], 'TREZOR');
    assert.equal(fs.readFileSync(gen.keys[1].publicKeyPath, 'utf8'), fs.readFileSync(res.keys[0].publicKeyPath, 'utf8'));
});

test('the mnemonic is never written to disk', async (t) => {
    const dir = tmpDir(t);
    await new BIP39ToSSH(dir).deriveSSHKeys(MNEMONIC, 1, 'TREZOR');
    for (const f of fs.readdirSync(dir, { recursive: true })) {
        const full = path.join(dir, f);
        if (fs.statSync(full).isFile()) {
            assert.doesNotMatch(fs.readFileSync(full, 'utf8'), /abandon/, f);
        }
    }
});
