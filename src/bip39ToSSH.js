const bip39 = require('bip39');
const tweetnacl = require('tweetnacl');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const openssh = require('./openssh');

class BIP39ToSSH {
    constructor(outputDir, { createDir = true } = {}) {
        this.outputDir = outputDir || path.join(__dirname, 'generated-keys');
        if (createDir) {
            fs.mkdirSync(this.outputDir, { recursive: true, mode: 0o700 });
        }
    }

    async generateNewSeed(wordCount = 24) {
        // 12 words = 128 bits, 24 words = 256 bits, from the system random source.
        const entropyBits = wordCount === 12 ? 128 : 256;
        return bip39.generateMnemonic(entropyBits);
    }

    async deriveSSHKeys(mnemonic, count = 1, passphrase = '') {
        const paths = Array.from({ length: count }, (_, i) => `m/44'/0'/0'/0/${i}`);
        const result = await this.writeKeys(mnemonic, paths, passphrase);
        return { ...result, mnemonic };
    }

    async restoreFromSeed(mnemonic, derivationPaths, passphrase = '') {
        const paths = Array.isArray(derivationPaths) ? derivationPaths : [derivationPaths];
        for (const p of paths) {
            if (typeof p !== 'string' || !p.startsWith('m/')) {
                throw new Error(`Invalid derivation path: ${p}. Must start with "m/"`);
            }
        }
        return this.writeKeys(mnemonic, paths, passphrase);
    }

    async writeKeys(mnemonic, paths, passphrase = '') {
        if (typeof mnemonic !== 'string' || !bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic');
        }
        const seed = await bip39.mnemonicToSeed(mnemonic, passphrase || '');

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const baseDir = path.join(this.outputDir, `seed-${timestamp}`);
        fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });

        const keys = paths.map((derivationPath, i) => {
            const pair = this.deriveKeyPair(seed, derivationPath);
            const keyDir = path.join(baseDir, `key-${i + 1}`);
            fs.mkdirSync(keyDir, { mode: 0o700 });

            const privateKeyPath = path.join(keyDir, 'id_ed25519');
            fs.writeFileSync(privateKeyPath, openssh.encodePrivateKey(pair.seed, pair.publicKey), { mode: 0o600 });

            const publicKeyPath = path.join(keyDir, 'id_ed25519.pub');
            fs.writeFileSync(publicKeyPath, openssh.encodePublicKey(pair.publicKey));

            const derivationInfo = `Derivation Path: ${derivationPath}`;
            fs.writeFileSync(path.join(keyDir, 'derivation.txt'), derivationInfo, 'utf8');

            return { privateKeyPath, publicKeyPath, derivationPath, derivationInfo };
        });

        return { success: true, keys, baseDir };
    }

    /**
     * Derive an ed25519 key pair from a BIP39 seed and a path label.
     * The ed25519 seed is PBKDF2-HMAC-SHA512(seed, salt = path, 100000 rounds, 32 bytes).
     * The path is only a salt: this is not BIP32/SLIP-10 derivation.
     * @param {Buffer} seed - 64-byte BIP39 seed
     * @param {string} derivationPath - e.g. m/44'/0'/0'/0/0
     * @returns {{seed: Uint8Array, publicKey: Uint8Array}}
     */
    deriveKeyPair(seed, derivationPath) {
        const edSeed = crypto.pbkdf2Sync(seed, Buffer.from(derivationPath, 'utf8'), 100000, 32, 'sha512');
        const keyPair = tweetnacl.sign.keyPair.fromSeed(edSeed);
        return { seed: edSeed, publicKey: keyPair.publicKey };
    }
}

module.exports = BIP39ToSSH;
