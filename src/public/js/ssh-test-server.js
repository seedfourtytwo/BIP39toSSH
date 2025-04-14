/**
 * SSH Test Server - A browser-based SSH key verification tool
 * This module provides a simple way to test SSH key pairs without needing a real server
 */

class SSHTestServer {
    constructor() {
        this.authenticated = false;
        this.lastTestResult = null;
    }

    /**
     * Test an SSH key pair by simulating an authentication attempt
     * @param {string} publicKey - The public key in OpenSSH format
     * @param {string} privateKey - The private key in OpenSSH format
     * @returns {Object} - Test result with success status and details
     */
    async testKeyPair(publicKey, privateKey) {
        try {
            console.log('Testing key pair...');
            
            // Extract the key data from the OpenSSH format
            const publicKeyData = this.extractKeyData(publicKey, 'public');
            const privateKeyData = this.extractKeyData(privateKey, 'private');
            
            if (!publicKeyData || !privateKeyData) {
                console.error('Failed to extract key data');
                return {
                    success: false,
                    error: 'Invalid key format. Please ensure you are using OpenSSH format keys.'
                };
            }

            console.log('Key data extracted successfully');
            console.log('Public key length:', publicKeyData.length);
            console.log('Private key length:', privateKeyData.length);

            // For Ed25519 keys, we can verify the pair by checking if the public key
            // matches the public key portion of the private key
            // In OpenSSH format, the private key contains both private and public key data
            const privateKeyFull = this.extractFullKeyData(privateKey);
            if (!privateKeyFull) {
                return {
                    success: false,
                    error: 'Failed to extract full private key data'
                };
            }

            // The public key portion is the last 32 bytes of the private key data
            const publicKeyFromPrivate = privateKeyFull.slice(-32);
            
            // Compare the public key from the private key with the provided public key
            const keysMatch = this.compareArrays(publicKeyData, publicKeyFromPrivate);
            
            if (!keysMatch) {
                return {
                    success: false,
                    error: 'The provided public and private keys do not form a valid key pair.'
                };
            }

            // Generate a fingerprint for the public key
            const fingerprint = await this.generateFingerprint(publicKeyData);
            
            // Store the test result
            this.lastTestResult = {
                success: true,
                message: 'Authentication successful! The key pair is valid.',
                fingerprint: fingerprint
            };
            
            return this.lastTestResult;
        } catch (error) {
            console.error('Error testing key pair:', error);
            return {
                success: false,
                error: 'Error testing key pair: ' + (error.message || 'Unknown error')
            };
        }
    }

    /**
     * Extract the full key data from OpenSSH format
     * @param {string} key - The key in OpenSSH format
     * @returns {Uint8Array|null} - The extracted key data or null if invalid
     */
    extractFullKeyData(key) {
        try {
            if (!key.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
                console.error('Invalid private key format: Missing OpenSSH header');
                return null;
            }
            
            if (!key.includes('-----END OPENSSH PRIVATE KEY-----')) {
                console.error('Invalid private key format: Missing OpenSSH footer');
                return null;
            }
            
            const match = key.match(/-----BEGIN OPENSSH PRIVATE KEY-----\n([\s\S]*?)\n-----END OPENSSH PRIVATE KEY-----/);
            if (!match) {
                console.error('Invalid private key format: Could not extract key data');
                return null;
            }
            
            const keyData = this.base64ToUint8Array(match[1]);
            if (!keyData) {
                console.error('Failed to decode private key base64');
                return null;
            }
            
            return keyData;
        } catch (error) {
            console.error('Error extracting full key data:', error);
            return null;
        }
    }

    /**
     * Compare two Uint8Arrays for equality
     * @param {Uint8Array} arr1 - First array
     * @param {Uint8Array} arr2 - Second array
     * @returns {boolean} - True if arrays are equal
     */
    compareArrays(arr1, arr2) {
        if (arr1.length !== arr2.length) {
            return false;
        }
        for (let i = 0; i < arr1.length; i++) {
            if (arr1[i] !== arr2[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Extract the key data from OpenSSH format
     * @param {string} key - The key in OpenSSH format
     * @param {string} type - 'public' or 'private'
     * @returns {Uint8Array|null} - The extracted key data or null if invalid
     */
    extractKeyData(key, type) {
        try {
            console.log(`Extracting ${type} key data...`);
            console.log('Input key:', key.substring(0, 50) + '...');
            
            if (type === 'public') {
                // Format: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
                const parts = key.trim().split(' ');
                console.log('Public key parts:', parts);
                
                if (parts.length < 2) {
                    console.error('Invalid public key format: Not enough parts');
                    return null;
                }
                
                if (parts[0] !== 'ssh-ed25519') {
                    console.error('Invalid public key format: Not an Ed25519 key');
                    return null;
                }
                
                const keyData = this.base64ToUint8Array(parts[1]);
                if (!keyData) {
                    console.error('Failed to decode public key base64');
                    return null;
                }
                
                console.log(`Public key extracted, length: ${keyData.length}`);
                return keyData;
            } else {
                // Format: -----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----
                if (!key.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
                    console.error('Invalid private key format: Missing OpenSSH header');
                    return null;
                }
                
                if (!key.includes('-----END OPENSSH PRIVATE KEY-----')) {
                    console.error('Invalid private key format: Missing OpenSSH footer');
                    return null;
                }
                
                const match = key.match(/-----BEGIN OPENSSH PRIVATE KEY-----\n([\s\S]*?)\n-----END OPENSSH PRIVATE KEY-----/);
                if (!match) {
                    console.error('Invalid private key format: Could not extract key data');
                    return null;
                }
                
                const keyData = this.base64ToUint8Array(match[1]);
                if (!keyData) {
                    console.error('Failed to decode private key base64');
                    return null;
                }
                
                if (keyData.length < 64) {
                    console.error(`Invalid private key length: ${keyData.length} (expected at least 64 bytes)`);
                    return null;
                }
                
                // The OpenSSH private key format for Ed25519 contains:
                // 1. A header (32 bytes)
                // 2. The private key (32 bytes)
                // 3. The public key (32 bytes)
                const privateKeyData = keyData.slice(32, 64);
                console.log(`Private key extracted, length: ${privateKeyData.length}`);
                return privateKeyData;
            }
        } catch (error) {
            console.error('Error extracting key data:', error);
            return null;
        }
    }

    /**
     * Generate a fingerprint for a public key
     * @param {Uint8Array} publicKeyData - The public key data
     * @returns {string} - The key fingerprint
     */
    async generateFingerprint(publicKeyData) {
        try {
            console.log('Generating fingerprint...');
            // Create a SHA-256 hash of the public key
            const hashBuffer = await crypto.subtle.digest('SHA-256', publicKeyData);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            
            // Convert to hex string with colons
            const fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join(':');
            console.log('Fingerprint generated:', fingerprint);
            return fingerprint;
        } catch (error) {
            console.error('Error generating fingerprint:', error);
            return 'Error generating fingerprint';
        }
    }

    /**
     * Convert a base64 string to a Uint8Array
     * @param {string} base64 - The base64 string
     * @returns {Uint8Array} - The decoded data
     */
    base64ToUint8Array(base64) {
        try {
            console.log('Converting base64 to Uint8Array...');
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            console.log(`Converted base64 to Uint8Array, length: ${bytes.length}`);
            return bytes;
        } catch (error) {
            console.error('Error converting base64 to Uint8Array:', error);
            return null;
        }
    }

    /**
     * Get the last test result
     * @returns {Object|null} - The last test result or null if no test has been performed
     */
    getLastTestResult() {
        return this.lastTestResult;
    }
}

// Export the class for use in the browser
window.SSHTestServer = SSHTestServer; 