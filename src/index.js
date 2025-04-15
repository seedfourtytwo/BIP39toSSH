const seedManager = require('./seed');
const keyDeriver = require('./keyDeriver');
const fs = require('fs');
const path = require('path');
const express = require('express');

class BIP39toSSH {
    /**
     * Initialize the BIP39 to SSH converter
     * @param {Object} options - Configuration options
     * @param {string} options.outputDir - Directory to save generated keys (default: './keys')
     */
    constructor(options = {}) {
        this.outputDir = options.outputDir || './keys';
        this.ensureOutputDirectory();
    }

    /**
     * Ensure the output directory exists
     */
    ensureOutputDirectory() {
        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }

    /**
     * Generate new SSH keys from a new seed
     * @param {Object} options - Generation options
     * @param {number} options.count - Number of key pairs to generate
     * @param {string} options.passphrase - Optional passphrase for the seed
     * @returns {Object} Information about the generated keys
     */
    generateNewKeys(options = {}) {
        const count = options.count || 1;
        const passphrase = options.passphrase || '';

        // Generate a new mnemonic
        const mnemonic = seedManager.generateMnemonic();
        
        // Generate key pairs
        const keyPairs = keyDeriver.generateMultipleKeyPairs(mnemonic, count, passphrase);
        
        // Save keys and return information
        return this.saveKeys(keyPairs, mnemonic);
    }

    /**
     * Generate SSH keys from an existing seed
     * @param {Object} options - Generation options
     * @param {string} options.mnemonic - The existing mnemonic phrase
     * @param {number} options.count - Number of key pairs to generate
     * @param {string} options.passphrase - Optional passphrase for the seed
     * @returns {Object} Information about the generated keys
     */
    generateFromExistingSeed(options) {
        if (!options.mnemonic) {
            throw new Error('Mnemonic phrase is required');
        }

        const count = options.count || 1;
        const passphrase = options.passphrase || '';

        // Validate the mnemonic
        if (!seedManager.importMnemonic(options.mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }

        // Generate key pairs
        const keyPairs = keyDeriver.generateMultipleKeyPairs(options.mnemonic, count, passphrase);
        
        // Save keys and return information
        return this.saveKeys(keyPairs, options.mnemonic);
    }

    /**
     * Save generated keys to files
     * @param {Array} keyPairs - Array of key pair objects
     * @param {string} mnemonic - The mnemonic phrase used
     * @returns {Object} Information about the saved keys
     */
    saveKeys(keyPairs, mnemonic) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const baseDir = path.join(this.outputDir, `keys-${timestamp}`);
        
        // Create a directory for this set of keys
        fs.mkdirSync(baseDir, { recursive: true });

        // Save the mnemonic (in a separate file for security)
        const mnemonicPath = path.join(baseDir, 'mnemonic.txt');
        fs.writeFileSync(mnemonicPath, mnemonic, 'utf8');

        // Save each key pair
        const keyInfo = keyPairs.map((pair, index) => {
            const keyDir = path.join(baseDir, `key-${index}`);
            fs.mkdirSync(keyDir, { recursive: true });

            // Save private key
            const privateKeyPath = path.join(keyDir, 'id_ed25519');
            fs.writeFileSync(privateKeyPath, pair.privateKey, 'utf8');

            // Save public key
            const publicKeyPath = path.join(keyDir, 'id_ed25519.pub');
            fs.writeFileSync(publicKeyPath, pair.publicKey, 'utf8');

            // Save derivation info
            const derivationPath = path.join(keyDir, 'derivation.txt');
            fs.writeFileSync(derivationPath, 
                `Derivation Path: ${pair.derivationPath}\n\n${pair.derivationInfo}`, 
                'utf8'
            );

            return {
                index,
                privateKeyPath,
                publicKeyPath,
                derivationPath,
                derivationInfo: pair.derivationInfo
            };
        });

        return {
            baseDir,
            mnemonicPath,
            keyInfo,
            message: `Generated ${keyPairs.length} key pair(s) in ${baseDir}`
        };
    }
}

// Export a function to create a new instance
module.exports = (options) => new BIP39toSSH(options);

// Add route to read key files
const app = express();
app.get('/read-key', (req, res) => {
    try {
        const keyPath = req.query.path;
        
        // Basic security check to prevent directory traversal
        if (!keyPath || keyPath.includes('..')) {
            return res.status(400).json({ error: 'Invalid key path' });
        }
        
        // Read the key file
        const keyContent = fs.readFileSync(keyPath, 'utf8');
        res.send(keyContent);
    } catch (error) {
        console.error('Error reading key file:', error);
        res.status(500).json({ error: 'Failed to read key file' });
    }
});
