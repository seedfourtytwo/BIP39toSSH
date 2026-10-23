const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const BIP39ToSSH = require('../src/bip39ToSSH');
const bip39 = require('bip39');
const openssh = require('../src/openssh');
const SSHTestServer = require('../src/public/js/ssh-test-server');

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function keys(t, paths) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bip39tossh-chk-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const result = await new BIP39ToSSH(dir).restoreFromSeed(MNEMONIC, paths, 'TREZOR');
    return result.keys.map((k) => ({
        file: k.publicKeyPath,
        priv: fs.readFileSync(k.privateKeyPath, 'utf8'),
        pub: fs.readFileSync(k.publicKeyPath, 'utf8')
    }));
}

test('a real pair passes and shows the same fingerprint as ssh-keygen', async (t) => {
    const [k] = await keys(t, ["m/44'/0'/0'/0/0"]);
    const result = await new SSHTestServer().testKeyPair(k.pub, k.priv);
    assert.equal(result.success, true, result.error);
    const expected = execFileSync('ssh-keygen', ['-l', '-f', k.file], { encoding: 'utf8' }).split(' ')[1];
    assert.equal(result.fingerprint, expected);
});

test('keys from two different paths do not pass as a pair', async (t) => {
    const [a, b] = await keys(t, ["m/44'/0'/0'/0/0", "m/44'/0'/0'/0/1"]);
    const result = await new SSHTestServer().testKeyPair(a.pub, b.priv);
    assert.equal(result.success, false);
});

test('a private key whose stored public half was swapped does not pass', async (t) => {
    // The old checker only compared the last 32 bytes; a real check signs with the private half.
    const converter = new BIP39ToSSH(null, { createDir: false });
    const seed = await bip39.mnemonicToSeed(MNEMONIC, 'TREZOR');
    const a = converter.deriveKeyPair(seed, "m/44'/0'/0'/0/0");
    const b = converter.deriveKeyPair(seed, "m/44'/0'/0'/0/1");
    const forged = openssh.encodePrivateKey(a.seed, b.publicKey);
    const result = await new SSHTestServer().testKeyPair(openssh.encodePublicKey(b.publicKey), forged);
    assert.equal(result.success, false);
});

test('garbage is refused without throwing', async () => {
    const checker = new SSHTestServer();
    for (const [pub, priv] of [['', ''], ['ssh-ed25519 !!!', 'nope'], ['ssh-rsa AAAA', '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----']]) {
        const result = await checker.testKeyPair(pub, priv);
        assert.equal(result.success, false);
    }
});
