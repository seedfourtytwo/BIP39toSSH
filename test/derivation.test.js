const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bip39 = require('bip39');
const BIP39ToSSH = require('../src/bip39ToSSH');

// Official BIP39 test vector (bitcoin/bips, passphrase "TREZOR").
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSPHRASE = 'TREZOR';
const BIP39_SEED = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04';

// Computed independently with Python hashlib + pyca/cryptography (OpenSSL), not with this code:
// ed25519 seed = PBKDF2-HMAC-SHA512(bip39 seed, salt = path, 100000 rounds, 32 bytes).
const VECTORS = [
    {
        path: "m/44'/0'/0'/0/0",
        seed: '64cbfd0fcf825ff980fbec02cb5a4eed00798dadf8161638194d2c0857a32695',
        publicKey: '1c5ff956609130e7b745c6ad8bb28ec7b123a4bac282d9487f29dee8cff38fe9'
    },
    {
        path: "m/44'/0'/0'/0/1",
        seed: '248ca11524552dfdb551373abf7bf076d8be1bd88a9cc381dc6e9d8841d61e11',
        publicKey: '0d2eb5dedeba50c2dc6077122b5da2caec8128f0202d9791e62232ac5be57a1c'
    }
];

const OFFICIAL_ENGLISH_SHA256 = '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda';

test('the English word list is the official BIP39 list, all 2048 words', () => {
    const words = bip39.wordlists.english;
    assert.equal(words.length, 2048);
    const digest = crypto.createHash('sha256').update(words.join('\n') + '\n').digest('hex');
    assert.equal(digest, OFFICIAL_ENGLISH_SHA256);
});

test('the BIP39 seed matches the official test vector', async () => {
    const seed = await bip39.mnemonicToSeed(MNEMONIC, PASSPHRASE);
    assert.equal(seed.toString('hex'), BIP39_SEED);
});

test('a mnemonic with a bad checksum is refused', () => {
    const bad = MNEMONIC.replace(/about$/, 'abandon');
    assert.equal(bip39.validateMnemonic(bad), false);
});

for (const v of VECTORS) {
    test(`derives the pinned ed25519 key for ${v.path}`, () => {
        const converter = new BIP39ToSSH(null, { createDir: false });
        const pair = converter.deriveKeyPair(Buffer.from(BIP39_SEED, 'hex'), v.path);
        assert.equal(Buffer.from(pair.seed).toString('hex'), v.seed);
        assert.equal(Buffer.from(pair.publicKey).toString('hex'), v.publicKey);
    });
}

test('the public key is the one that belongs to the private key', () => {
    const converter = new BIP39ToSSH(null, { createDir: false });
    const pair = converter.deriveKeyPair(Buffer.from(BIP39_SEED, 'hex'), VECTORS[0].path);
    // Independent check through Node's own ed25519 (OpenSSL), not tweetnacl.
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(pair.seed)]);
    const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
    assert.equal(spki.subarray(-32).toString('hex'), Buffer.from(pair.publicKey).toString('hex'));
});

test('new seeds come from the system random source, never Math.random', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const srcDir = path.join(__dirname, '..', 'src');
    const files = fs.readdirSync(srcDir, { recursive: true }).filter((f) => f.endsWith('.js'));
    for (const f of files) {
        assert.doesNotMatch(fs.readFileSync(path.join(srcDir, f), 'utf8'), /Math\.random/, f);
    }
});
