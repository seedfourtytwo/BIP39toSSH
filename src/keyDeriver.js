const nacl = require('tweetnacl');
const seedManager = require('./seed');

class KeyDeriver {
    /**
     * Generate an SSH key pair from seed material
     * @param {Buffer} seedMaterial - The seed material from SeedManager
     * @param {string} derivationPath - The derivation path used for this key
     * @returns {Object} Object containing public and private keys in SSH format and derivation info
     */
    generateKeyPair(seedMaterial, derivationPath) {
        // Use the first 32 bytes of seed material as the private key seed
        const privateKeySeed = seedMaterial.slice(0, 32);
        
        // Generate Ed25519 key pair from the seed
        const keyPair = nacl.sign.keyPair.fromSeed(privateKeySeed);
        
        // Convert to SSH format
        return {
            privateKey: this.convertToSSHPrivateKey(keyPair),
            publicKey: this.convertToSSHPublicKey(keyPair.publicKey),
            derivationPath: derivationPath,
            derivationInfo: this.getDerivationInfo(derivationPath)
        };
    }

    /**
     * Get human-readable explanation of the derivation path
     * @param {string} derivationPath - The derivation path
     * @returns {string} Human-readable explanation
     */
    getDerivationInfo(derivationPath) {
        const parts = derivationPath.split('/');
        let explanation = 'This key was derived from the master seed using the following path:\n';
        
        parts.forEach((part, index) => {
            if (part === 'm') {
                explanation += '- m: Master seed\n';
            } else if (part.endsWith("'")) {
                const number = part.slice(0, -1);
                explanation += `- ${number}': Hardened derivation (index ${number})\n`;
            } else {
                explanation += `- ${part}: Normal derivation (index ${part})\n`;
            }
        });
        
        explanation += '\nThis path ensures deterministic key generation and allows you to regenerate the same key later.';
        return explanation;
    }

    /**
     * Convert Ed25519 key pair to SSH private key format
     * @param {Object} keyPair - The Ed25519 key pair
     * @returns {string} SSH private key in PEM format
     */
    convertToSSHPrivateKey(keyPair) {
        // Create the SSH private key header and footer
        const header = '-----BEGIN OPENSSH PRIVATE KEY-----\n';
        const footer = '\n-----END OPENSSH PRIVATE KEY-----';
        
        // Combine the private and public key data
        const privateKeyData = Buffer.concat([
            keyPair.secretKey,
            keyPair.publicKey
        ]);
        
        // Base64 encode the key data
        const encodedKey = privateKeyData.toString('base64');
        
        // Format with line breaks every 64 characters
        const formattedKey = encodedKey.match(/.{1,64}/g).join('\n');
        
        return header + formattedKey + footer;
    }

    /**
     * Convert Ed25519 public key to SSH public key format
     * @param {Uint8Array} publicKey - The Ed25519 public key
     * @returns {string} SSH public key in authorized_keys format
     */
    convertToSSHPublicKey(publicKey) {
        // Create the SSH public key format
        const keyType = 'ssh-ed25519';
        const encodedKey = Buffer.from(publicKey).toString('base64');
        
        return `${keyType} ${encodedKey}`;
    }

    /**
     * Generate multiple SSH key pairs from a master seed
     * @param {string} mnemonic - The BIP39 mnemonic phrase
     * @param {number} count - Number of key pairs to generate
     * @param {string} passphrase - Optional passphrase for the seed
     * @param {string} purpose - Purpose of the keys (default: 'ssh')
     * @returns {Array} Array of key pair objects with derivation information
     */
    generateMultipleKeyPairs(mnemonic, count = 1, passphrase = '', purpose = 'ssh') {
        // Convert mnemonic to seed
        const seed = seedManager.mnemonicToSeed(mnemonic, passphrase);
        
        const keyPairs = [];
        for (let i = 0; i < count; i++) {
            // Create a BIP44-style derivation path
            // Format: m/purpose'/coin'/account'/change/index
            // We use 44' for BIP44, 0' for Bitcoin (can be changed), 0' for account, 0 for external keys, i for index
            const derivationPath = `m/44'/0'/0'/0/${i}`;
            
            // Derive unique seed material for each key pair
            const seedMaterial = seedManager.deriveSshKeyMaterial(seed, i);
            const keyPair = this.generateKeyPair(seedMaterial, derivationPath);
            keyPairs.push(keyPair);
        }
        
        return keyPairs;
    }
}

module.exports = new KeyDeriver();
