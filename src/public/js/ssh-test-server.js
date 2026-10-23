/**
 * Browser-side check that an OpenSSH ed25519 private key and public key belong together.
 * It parses both files, then signs a random challenge with the private key and verifies it
 * with the public key, the same proof an SSH server asks for. Nothing leaves the page.
 */
(function () {
    const KEY_TYPE = 'ssh-ed25519';
    // PKCS#8 prefix for a raw 32-byte ed25519 seed (RFC 8410).
    const PKCS8_ED25519_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

    function base64ToBytes(b64) {
        const binary = atob(b64.replace(/\s+/g, ''));
        return Uint8Array.from(binary, (c) => c.charCodeAt(0));
    }

    function bytesToBase64(bytes) {
        return btoa(String.fromCharCode(...bytes));
    }

    function equalBytes(a, b) {
        return a.length === b.length && a.every((v, i) => v === b[i]);
    }

    class Reader {
        constructor(bytes) {
            this.bytes = bytes;
            this.pos = 0;
        }
        take(n) {
            if (this.pos + n > this.bytes.length) throw new Error('Key data is truncated');
            const out = this.bytes.subarray(this.pos, this.pos + n);
            this.pos += n;
            return out;
        }
        uint32() {
            const b = this.take(4);
            return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
        }
        string() {
            return this.take(this.uint32());
        }
        text() {
            return new TextDecoder().decode(this.string());
        }
    }

    function parsePublicBlob(blob) {
        const r = new Reader(blob);
        if (r.text() !== KEY_TYPE) throw new Error('Not an ed25519 key');
        const pub = r.string();
        if (pub.length !== 32) throw new Error('Wrong ed25519 public key length');
        return pub;
    }

    function parsePublicKey(text) {
        const parts = text.trim().split(/\s+/);
        if (parts[0] !== KEY_TYPE || !parts[1]) throw new Error('Public key must start with ssh-ed25519');
        const blob = base64ToBytes(parts[1]);
        return { blob, pub: parsePublicBlob(blob) };
    }

    function parsePrivateKey(text) {
        const match = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(text);
        if (!match) throw new Error('Private key must be in OpenSSH format');
        const r = new Reader(base64ToBytes(match[1]));
        if (new TextDecoder().decode(r.take(15)) !== 'openssh-key-v1\0') throw new Error('Not an openssh-key-v1 file');
        if (r.text() !== 'none') throw new Error('Encrypted private keys cannot be checked here');
        r.string(); // kdf name
        r.string(); // kdf options
        if (r.uint32() !== 1) throw new Error('Expected exactly one key');
        const outerPub = parsePublicBlob(r.string());

        const s = new Reader(r.string());
        if (s.uint32() !== s.uint32()) throw new Error('Private key check values differ');
        if (s.text() !== KEY_TYPE) throw new Error('Not an ed25519 private key');
        const innerPub = s.string();
        const secret = s.string();
        if (secret.length !== 64) throw new Error('Wrong ed25519 private key length');
        if (!equalBytes(outerPub, innerPub) || !equalBytes(secret.subarray(32), innerPub)) {
            throw new Error('The private key file is inconsistent');
        }
        return { seed: secret.subarray(0, 32), pub: innerPub };
    }

    async function provesPossession(seed, pub) {
        const subtle = globalThis.crypto && globalThis.crypto.subtle;
        if (!subtle) throw new Error('This browser has no Web Crypto; open the page over http://localhost');
        const pkcs8 = new Uint8Array([...PKCS8_ED25519_PREFIX, ...seed]);
        let privateKey;
        let publicKey;
        try {
            privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
            publicKey = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
        } catch {
            throw new Error('This browser cannot check ed25519 keys; use ssh-keygen -y -f id_ed25519 instead');
        }
        const challenge = globalThis.crypto.getRandomValues(new Uint8Array(32));
        const signature = await subtle.sign({ name: 'Ed25519' }, privateKey, challenge);
        return subtle.verify({ name: 'Ed25519' }, publicKey, signature, challenge);
    }

    class SSHTestServer {
        /**
         * @param {string} publicKey - id_ed25519.pub contents
         * @param {string} privateKey - id_ed25519 contents
         * @returns {Promise<{success: boolean, fingerprint?: string, error?: string}>}
         */
        async testKeyPair(publicKey, privateKey) {
            try {
                const given = parsePublicKey(String(publicKey));
                const priv = parsePrivateKey(String(privateKey));
                if (!equalBytes(given.pub, priv.pub) || !(await provesPossession(priv.seed, given.pub))) {
                    return { success: false, error: 'The public and private keys are not a pair.' };
                }
                return { success: true, fingerprint: await this.fingerprint(given.blob) };
            } catch (error) {
                return { success: false, error: error.message || 'Could not read the keys' };
            }
        }

        // Same text as `ssh-keygen -l`: SHA256 of the public key blob, unpadded base64.
        async fingerprint(blob) {
            const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', blob));
            return 'SHA256:' + bytesToBase64(digest).replace(/=+$/, '');
        }
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = SSHTestServer;
    } else {
        window.SSHTestServer = SSHTestServer;
    }
})();
