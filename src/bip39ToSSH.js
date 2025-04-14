const bip39 = require('bip39');
const tweetnacl = require('tweetnacl');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class BIP39ToSSH {
    constructor(outputDir) {
        this.outputDir = outputDir || path.join(__dirname, 'generated-keys');
        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }

    async generateNewSeed(wordCount = 24) {
        // Generate a new mnemonic with specified word count
        // 12 words = 128 bits, 24 words = 256 bits
        const entropyBits = wordCount === 12 ? 128 : 256;
        const mnemonic = bip39.generateMnemonic(entropyBits);
        return mnemonic;
    }

    async deriveSSHKeys(mnemonic, count = 1, passphrase = '', customPath = null) {
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic');
        }

        const seed = await bip39.mnemonicToSeed(mnemonic, passphrase);
        const keys = [];
        
        // Create a single timestamped directory for all keys
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const baseDir = path.join(this.outputDir, `seed-${timestamp}`);
        fs.mkdirSync(baseDir, { recursive: true });

        for (let i = 0; i < count; i++) {
            // Use custom path if provided, otherwise use default derivation path
            const derivationPath = customPath || `m/44'/0'/0'/0/${i}`;
            
            // Use the seed and path to generate a deterministic private key
            const privateKey = this.derivePrivateKey(seed, derivationPath);
            
            // Generate the public key from the private key
            const keyPair = tweetnacl.sign.keyPair.fromSecretKey(privateKey);
            
            // Create a subdirectory for this key pair
            const keyDir = path.join(baseDir, `key-${i + 1}`);
            fs.mkdirSync(keyDir, { recursive: true });

            // Save the private key in OpenSSH format
            const privateKeyPath = path.join(keyDir, 'id_ed25519');
            const privateKeyPEM = this.convertToOpenSSHFormat(privateKey, 'private');
            fs.writeFileSync(privateKeyPath, privateKeyPEM, { mode: 0o600 });

            // Save the public key in OpenSSH format
            const publicKeyPath = path.join(keyDir, 'id_ed25519.pub');
            const publicKeyPEM = this.convertToOpenSSHFormat(keyPair.publicKey, 'public');
            fs.writeFileSync(publicKeyPath, publicKeyPEM);

            // Save the derivation path information
            const derivationInfoPath = path.join(keyDir, 'derivation.txt');
            fs.writeFileSync(derivationInfoPath, `Derivation Path: ${derivationPath}`, 'utf8');

            keys.push({
                privateKeyPath,
                publicKeyPath,
                derivationPath,
                derivationInfo: `Derivation Path: ${derivationPath}`
            });
        }

        return {
            success: true,
            keys: keys,
            baseDir,
            mnemonic
        };
    }

    async restoreFromSeed(mnemonic, derivationPaths, passphrase = '') {
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic');
        }

        // Handle single path as string or array of paths
        const paths = Array.isArray(derivationPaths) ? derivationPaths : [derivationPaths];
        
        // Validate all paths
        for (const path of paths) {
            if (!path || !path.startsWith('m/')) {
                throw new Error(`Invalid derivation path: ${path}. Must start with "m/"`);
            }
        }

        const seed = await bip39.mnemonicToSeed(mnemonic, passphrase);
        const keys = [];
        
        // Create a single timestamped directory for all restored keys
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const baseDir = path.join(this.outputDir, `seed-${timestamp}`);
        fs.mkdirSync(baseDir, { recursive: true });

        for (let i = 0; i < paths.length; i++) {
            const derivationPath = paths[i];
            
            // Use the seed and path to generate a deterministic private key
            const privateKey = this.derivePrivateKey(seed, derivationPath);
            
            // Generate the public key from the private key
            const keyPair = tweetnacl.sign.keyPair.fromSecretKey(privateKey);
            
            // Create a subdirectory for this key pair
            const keyDir = path.join(baseDir, `key-${i + 1}`);
            fs.mkdirSync(keyDir, { recursive: true });

            // Save the private key in OpenSSH format
            const privateKeyPath = path.join(keyDir, 'id_ed25519');
            const privateKeyPEM = this.convertToOpenSSHFormat(privateKey, 'private');
            fs.writeFileSync(privateKeyPath, privateKeyPEM, { mode: 0o600 });

            // Save the public key in OpenSSH format
            const publicKeyPath = path.join(keyDir, 'id_ed25519.pub');
            const publicKeyPEM = this.convertToOpenSSHFormat(keyPair.publicKey, 'public');
            fs.writeFileSync(publicKeyPath, publicKeyPEM);

            // Save the derivation path information
            const derivationInfoPath = path.join(keyDir, 'derivation.txt');
            fs.writeFileSync(derivationInfoPath, `Derivation Path: ${derivationPath}`, 'utf8');

            keys.push({
                privateKeyPath,
                publicKeyPath,
                derivationPath,
                derivationInfo: `Derivation Path: ${derivationPath}`
            });
        }

        return {
            success: true,
            keys,
            baseDir
        };
    }

    /**
     * Derive a private key from seed and path
     * @param {Buffer} seed - The seed to derive from
     * @param {string} path - The derivation path
     * @returns {Buffer} The derived private key
     */
    derivePrivateKey(seed, path) {
        // Use PBKDF2 to derive a proper Ed25519 private key
        const salt = Buffer.from(path, 'utf8');
        const key = crypto.pbkdf2Sync(seed, salt, 100000, 32, 'sha512');
        
        // Ensure the key is properly formatted for Ed25519
        // Ed25519 requires the private key to be 64 bytes
        const privateKey = Buffer.alloc(64);
        key.copy(privateKey, 0);
        
        // Generate a deterministic second half using HMAC-SHA512
        const hmac = crypto.createHmac('sha512', key);
        const secondHalf = hmac.update(Buffer.from(path, 'utf8')).digest();
        secondHalf.copy(privateKey, 32, 0, 32);
        
        return privateKey;
    }

    /**
     * Convert a key to OpenSSH format
     * @param {Buffer|Uint8Array} key - The key to convert
     * @param {string} type - The type of key ('public' or 'private')
     * @returns {string} The key in OpenSSH format
     */
    convertToOpenSSHFormat(key, type) {
        if (type === 'private') {
            // Convert to OpenSSH private key format
            const header = '-----BEGIN OPENSSH PRIVATE KEY-----\n';
            const footer = '\n-----END OPENSSH PRIVATE KEY-----';
            const encoded = Buffer.from(key).toString('base64');
            return header + encoded + footer;
        } else {
            // Convert to OpenSSH public key format
            const keyType = 'ssh-ed25519';
            const encoded = Buffer.from(key).toString('base64');
            return `${keyType} ${encoded}`;
        }
    }
}

module.exports = BIP39ToSSH; 