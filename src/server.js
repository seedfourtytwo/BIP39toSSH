const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const bip39ToSSH = require('./bip39ToSSH');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Initialize BIP39 to SSH converter with default output directories
const defaultOutputDir = path.join(__dirname, 'generated-keys');
const defaultRestoreDir = path.join(__dirname, 'restored-keys');
const converter = new bip39ToSSH(defaultOutputDir);

// Routes
app.get('/', (req, res) => {
    res.render('index');
});

app.post('/generate', async (req, res) => {
    try {
        const { action, mnemonic, count, passphrase, outputDir } = req.body;
        
        // Validate and create output directory if specified
        let finalOutputDir = defaultOutputDir;
        if (outputDir) {
            const projectRoot = path.resolve(__dirname, '..');
            const requestedPath = path.resolve(projectRoot, outputDir);
            
            // Security check: ensure the path is within the project directory
            if (!requestedPath.startsWith(projectRoot)) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Output directory must be within the project folder' 
                });
            }
            
            // Create the directory if it doesn't exist
            if (!fs.existsSync(requestedPath)) {
                fs.mkdirSync(requestedPath, { recursive: true });
            }
            
            finalOutputDir = requestedPath;
        }
        
        // Create a new converter instance with the specified output directory
        const keyConverter = new bip39ToSSH(finalOutputDir);
        
        let keys;
        if (action === 'new') {
            // Generate new seed and keys
            const wordCount = parseInt(req.body.wordCount) || 24;
            const newMnemonic = await keyConverter.generateNewSeed(wordCount);
            const result = await keyConverter.deriveSSHKeys(newMnemonic, parseInt(count) || 1, passphrase);
            return res.json({ 
                success: true, 
                keys: result.keys,
                baseDir: result.baseDir,
                mnemonic: newMnemonic 
            });
        } else if (action === 'existing') {
            // Generate keys from existing seed
            const result = await keyConverter.deriveSSHKeys(mnemonic, parseInt(count) || 1, passphrase);
            return res.json({ 
                success: true, 
                keys: result.keys,
                baseDir: result.baseDir
            });
        } else {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid action. Use "new" or "existing".' 
            });
        }
    } catch (error) {
        console.error('Error generating keys:', error);
        return res.status(500).json({ 
            success: false, 
            error: error.message || 'Error generating keys' 
        });
    }
});

app.post('/restore', async (req, res) => {
    try {
        const { mnemonic, derivationPaths, passphrase, outputDir } = req.body;
        
        if (!mnemonic || !derivationPaths) {
            return res.status(400).json({ 
                success: false, 
                error: 'Mnemonic and derivation paths are required' 
            });
        }
        
        // Validate and create output directory if specified
        let finalOutputDir = defaultRestoreDir;
        if (outputDir) {
            const projectRoot = path.resolve(__dirname, '..');
            const requestedPath = path.resolve(projectRoot, outputDir);
            
            // Security check: ensure the path is within the project directory
            if (!requestedPath.startsWith(projectRoot)) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Output directory must be within the project folder' 
                });
            }
            
            // Create the directory if it doesn't exist
            if (!fs.existsSync(requestedPath)) {
                fs.mkdirSync(requestedPath, { recursive: true });
            }
            
            finalOutputDir = requestedPath;
        }
        
        // Create a new converter instance with the specified output directory
        const keyConverter = new bip39ToSSH(finalOutputDir);
        
        // Restore the keys
        const result = await keyConverter.restoreFromSeed(mnemonic, derivationPaths, passphrase);
        return res.json(result);
    } catch (error) {
        console.error('Error restoring keys:', error);
        return res.status(500).json({ 
            success: false, 
            error: error.message || 'Error restoring keys' 
        });
    }
});

app.get('/read-key', (req, res) => {
    try {
        const { path: keyPath } = req.query;
        
        if (!keyPath) {
            return res.status(400).json({ 
                success: false, 
                error: 'Key path is required' 
            });
        }
        
        // Security check: ensure the path is within the project directory
        const projectRoot = path.resolve(__dirname, '..');
        const requestedPath = path.resolve(projectRoot, keyPath);
        
        if (!requestedPath.startsWith(projectRoot)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Key path must be within the project folder' 
            });
        }
        
        // Check if the file exists
        if (!fs.existsSync(requestedPath)) {
            return res.status(404).json({ 
                success: false, 
                error: 'Key file not found' 
            });
        }
        
        // Read the key file
        const content = fs.readFileSync(requestedPath, 'utf8');
        return res.json({ success: true, content });
    } catch (error) {
        console.error('Error reading key:', error);
        return res.status(500).json({ 
            success: false, 
            error: error.message || 'Error reading key' 
        });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
}); 