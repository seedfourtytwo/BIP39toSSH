const bip39 = require('bip39');
const crypto = require('crypto');

class SeedManager {
    /**
     * Generate a new random mnemonic phrase
     * @param {number} strength - Bit strength (128 produces 12 words, 256 produces 24 words)
     * @returns {string} The mnemonic phrase
     */
    generateMnemonic(strength = 256) {
        return bip39.generateMnemonic(strength);
    }

    /**
     * Import and validate an existing mnemonic phrase
     * @param {string} mnemonic - The existing mnemonic phrase
     * @returns {boolean} True if valid and imported successfully
     * @throws {Error} If mnemonic is invalid
     */
    importMnemonic(mnemonic) {
        if (!this.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }
        return true;
    }

    /**
     * Validate if a mnemonic phrase is valid
     * @param {string} mnemonic - The mnemonic phrase to validate
     * @returns {boolean} True if valid, false otherwise
     */
    validateMnemonic(mnemonic) {
        return bip39.validateMnemonic(mnemonic);
    }

    /**
     * Convert mnemonic to seed
     * @param {string} mnemonic - The mnemonic phrase
     * @param {string} passphrase - Optional passphrase for additional security
     * @returns {Buffer} The seed buffer
     */
    mnemonicToSeed(mnemonic, passphrase = '') {
        return bip39.mnemonicToSeedSync(mnemonic, passphrase);
    }

    /**
     * Derive a deterministic key for SSH from the seed
     * @param {Buffer} seed - The seed buffer
     * @param {number} index - The index for key derivation path
     * @returns {Buffer} Derived key material
     */
    deriveSshKeyMaterial(seed, index = 0) {
        // Use HMAC-SHA512 for key derivation
        const hmac = crypto.createHmac('sha512', 'ssh');
        // Add index to make it deterministic
        const data = Buffer.concat([seed, Buffer.from([index])]);
        return hmac.update(data).digest();
    }
}

module.exports = new SeedManager();
