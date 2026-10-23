const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const BIP39ToSSH = require('./bip39ToSSH');

const MAX_KEYS = 10;
const KEY_FILE_NAMES = new Set(['id_ed25519', 'id_ed25519.pub']);
const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

// Resolve `requested` against `root` and return it only if it stays inside `root`.
// A plain startsWith() check would accept a sibling such as "<root>-evil".
function resolveInside(root, requested) {
    const resolved = path.resolve(root, requested);
    const rel = path.relative(root, resolved);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return resolved;
}

function parseCount(value) {
    if (value === undefined || value === null || value === '') return 1;
    const n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= MAX_KEYS ? n : null;
}

function securityHeaders(req, res, next) {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    res.set({
        'Content-Security-Policy': [
            "default-src 'self'",
            `script-src 'self' 'nonce-${nonce}'`,
            `style-src 'self' 'nonce-${nonce}'`,
            "img-src 'self' data:",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'"
        ].join('; '),
        // Every response here may carry a seed phrase or a private key.
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    });
    next();
}

// Refuse requests addressed to any other host name, so a web page cannot use
// DNS rebinding to read keys from this local server.
function hostCheck(allowedHosts) {
    return (req, res, next) => {
        const host = (req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
        if (!allowedHosts.includes(host)) {
            return res.status(403).type('text').send('Forbidden host');
        }
        next();
    };
}

function createApp({ root = path.resolve(__dirname, '..'), allowedHosts = LOOPBACK_HOSTS } = {}) {
    const defaultOutputDir = path.join(root, 'src', 'generated-keys');
    const defaultRestoreDir = path.join(root, 'src', 'restored-keys');

    const app = express();
    app.disable('x-powered-by');
    app.use(hostCheck(allowedHosts));
    app.use(securityHeaders);
    // JSON only: a cross-site HTML form cannot send application/json without CORS approval.
    app.use(express.json({ limit: '16kb' }));
    app.use(express.static(path.join(__dirname, 'public')));

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));

    function outputDirFor(requested, fallback) {
        if (!requested) return fallback;
        return resolveInside(root, String(requested));
    }

    app.get('/', (req, res) => {
        res.render('index');
    });

    app.post('/generate', async (req, res) => {
        try {
            const { action, mnemonic, passphrase } = req.body || {};
            const count = parseCount(req.body && req.body.count);
            if (count === null) {
                return res.status(400).json({ success: false, error: `Number of keys must be 1 to ${MAX_KEYS}` });
            }
            const outputDir = outputDirFor(req.body && req.body.outputDir, defaultOutputDir);
            if (!outputDir) {
                return res.status(400).json({ success: false, error: 'Output directory must be within the project folder' });
            }

            if (action === 'new') {
                const keyConverter = new BIP39ToSSH(outputDir);
                const wordCount = parseInt(req.body.wordCount, 10) || 24;
                const newMnemonic = await keyConverter.generateNewSeed(wordCount);
                const result = await keyConverter.deriveSSHKeys(newMnemonic, count, passphrase);
                return res.json({ success: true, keys: result.keys, baseDir: result.baseDir, mnemonic: newMnemonic });
            } else if (action === 'existing') {
                const keyConverter = new BIP39ToSSH(outputDir);
                const result = await keyConverter.deriveSSHKeys(mnemonic, count, passphrase);
                return res.json({ success: true, keys: result.keys, baseDir: result.baseDir });
            }
            return res.status(400).json({ success: false, error: 'Invalid action. Use "new" or "existing".' });
        } catch (error) {
            console.error('Error generating keys:', error.message);
            return res.status(500).json({ success: false, error: error.message || 'Error generating keys' });
        }
    });

    app.post('/restore', async (req, res) => {
        try {
            const { mnemonic, derivationPaths, passphrase } = req.body || {};
            if (!mnemonic || !derivationPaths) {
                return res.status(400).json({ success: false, error: 'Mnemonic and derivation paths are required' });
            }
            const paths = Array.isArray(derivationPaths) ? derivationPaths : [derivationPaths];
            if (paths.length > MAX_KEYS) {
                return res.status(400).json({ success: false, error: `At most ${MAX_KEYS} derivation paths at once` });
            }
            const outputDir = outputDirFor(req.body.outputDir, defaultRestoreDir);
            if (!outputDir) {
                return res.status(400).json({ success: false, error: 'Output directory must be within the project folder' });
            }

            const result = await new BIP39ToSSH(outputDir).restoreFromSeed(mnemonic, paths, passphrase);
            return res.json(result);
        } catch (error) {
            console.error('Error restoring keys:', error.message);
            return res.status(500).json({ success: false, error: error.message || 'Error restoring keys' });
        }
    });

    // Lets the page load a key it just generated into the checker. Only key files
    // inside the app folder are served, never any other file.
    app.get('/read-key', (req, res) => {
        const requested = typeof req.query.path === 'string' ? req.query.path : '';
        const keyPath = requested && resolveInside(root, requested);
        if (!keyPath || !KEY_FILE_NAMES.has(path.basename(keyPath))) {
            return res.status(400).json({ error: 'Invalid key path' });
        }
        let realPath;
        try {
            realPath = fs.realpathSync(keyPath);
        } catch {
            return res.status(404).json({ error: 'Key file not found' });
        }
        if (!resolveInside(fs.realpathSync(root), realPath) || !KEY_FILE_NAMES.has(path.basename(realPath))) {
            return res.status(400).json({ error: 'Invalid key path' });
        }
        res.type('text').send(fs.readFileSync(realPath, 'utf8').trim());
    });

    return app;
}

if (require.main === module) {
    const port = Number(process.env.PORT) || 3000;
    // Loopback only by default: the page handles seed phrases and private keys.
    const host = process.env.HOST || '127.0.0.1';
    const allowedHosts = LOOPBACK_HOSTS.includes(host) ? LOOPBACK_HOSTS : [...LOOPBACK_HOSTS, host.toLowerCase()];
    createApp({ allowedHosts }).listen(port, host, () => {
        console.log(`Server is running on http://${host}:${port}`);
    });
}

module.exports = { createApp, resolveInside };
