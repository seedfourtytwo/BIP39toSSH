# BIP39 to SSH Key Generator

A web application for generating and managing SSH keys from BIP39 seed phrases. This application provides web interface that allows you to generate new seed phrases or use existing ones to create Ed25519 SSH key pairs, with support for multiple derivation paths and optional passphrase protection.

## Prerequisites

- Node.js (v20 or higher)
- npm

## Dependencies

- `bip39` (BIP39 seed phrase generation and checksum validation)
- `tweetnacl` (Ed25519 key pair generation)
- `express` (local web server)
- `ejs` (template engine)
- `crypto` (Node.js built-in: PBKDF2, random numbers)

The page loads no third-party scripts or stylesheets; Tailwind CSS is served from `src/public/css/`.

## Features

### Key Generation
- Generate new BIP39 seed phrases (12 or 24 words)
- Use existing BIP39 seed phrases
- Generate multiple SSH key pairs from a single seed
- Optional passphrase protection
- Customizable output directory
- Default output directory: src/generated-keys
- Automatic derivation path management
- Default derivation path: m/44'/0'/0'/0/0 (increments for each key pair)

### Key Restoration
- Restore SSH keys from existing seed phrases
- Support for multiple derivation paths
- Maintains original key generation parameters
- Optional passphrase protection
- Customizable output directory
- Default output directory: src/restored-keys
- Default derivation path: m/44'/0'/0'/0/0 (can be customized)

### Key Testing
- Verify SSH key pair validity
- Generate and display key fingerprints
- Test both newly generated and existing keys
- Standalone key testing interface

## Security Features

### Cryptographic Algorithms
- **BIP39**: For seed phrase generation and management
- **PBKDF2-HMAC-SHA512**: For key derivation with 100,000 iterations
- **Ed25519**: For SSH key pair generation
- **SHA-256**: For key fingerprints (same `SHA256:` text as `ssh-keygen -l`)

### Security Measures
- Deterministic key generation
- Secure random number generation for new seeds
- Private keys written with mode 0600 in folders with mode 0700; the seed phrase is never written to disk
- Passphrase protection support
- The server listens on 127.0.0.1 only and refuses requests for any other host name
- Responses are sent with `Cache-Control: no-store` and a strict Content Security Policy

**Where the work happens:** key derivation runs in the local Node.js server, not in the
browser. The seed phrase travels from the page to `127.0.0.1` and the keys are written to
disk on the same machine. Run it on a computer you trust, ideally offline. Setting `HOST`
to anything other than a loopback address exposes seed phrases to your network.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/BIP39toSSH.git
cd BIP39toSSH
```

2. Install dependencies:
```bash
npm install
```

3. Start the application:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Usage

### Generating New Keys

1. Select "Generate New Seed" or "Use Existing Seed"
2. For new seeds:
   - Choose between 12 or 24 words (24 words recommended for maximum security)
   - Select the number of key pairs to generate (1-10)
   - Optionally add a passphrase (recommended for additional security)
   - Specify output directory (optional, defaults to src/generated-keys)
   - Default derivation paths will be:
     * First key: m/44'/0'/0'/0/0
     * Second key: m/44'/0'/0'/0/1
     * Third key: m/44'/0'/0'/0/2
     * And so on...
3. For existing seeds:
   - Enter your seed phrase (12 or 24 words)
   - Select the number of key pairs to generate
   - Enter the same passphrase used during generation (if any)
   - Specify output directory (optional, defaults to src/generated-keys)
   - Same default derivation paths as above
4. Click "Generate Keys"
5. **IMPORTANT**: If generating a new seed, write down and securely store the seed phrase

### Restoring Keys

1. Enter your seed phrase (12 or 24 words)
2. Enter derivation paths (one per line)
   - Default path: m/44'/0'/0'/0/0
   - For multiple keys, increment the last number:
     * m/44'/0'/0'/0/0
     * m/44'/0'/0'/0/1
     * m/44'/0'/0'/0/2
   - You can use different paths for different purposes
3. Enter passphrase if used during generation
4. Specify output directory (optional, defaults to src/restored-keys)
5. Click "Restore Keys"

### Testing Keys

1. Use the "Test Keys" tab
2. Paste your public and private keys
   - Private key: Content of id_ed25519 file
   - Public key: Content of id_ed25519.pub file
3. Click "Test Key Pair"
4. View the verification result and fingerprint

## File Structure

Generated keys are saved in the following structure:
```
output-directory/
├── key-1/
│   ├── id_ed25519        # Private key
│   ├── id_ed25519.pub    # Public key
│   └── derivation.txt    # Derivation path information
├── key-2/
│   ├── id_ed25519
│   ├── id_ed25519.pub
│   └── derivation.txt
└── ...
```

## Security Considerations

1. **Seed Phrase Security**
   - Store seed phrases securely offline
   - Never share seed phrases
   - Consider using a passphrase for additional security

2. **Key Management**
   - Keep private keys secure
   - Use appropriate file permissions
   - Back up keys and seed phrases separately

3. **Passphrase Usage**
   - Use strong passphrases
   - Store passphrases securely
   - Remember that lost passphrases cannot be recovered

## Technical Details

### Key Derivation Process
1. Seed phrase + passphrase → 64-byte BIP39 seed (standard BIP39)
2. Ed25519 seed = PBKDF2-HMAC-SHA512(BIP39 seed, salt = derivation path text, 100,000 rounds, 32 bytes)
3. Ed25519 seed → Ed25519 key pair

The derivation path is used only as a label (the PBKDF2 salt). It is **not** BIP32 or
SLIP-10 derivation, so other wallets or tools will not produce the same keys from the same path.

Keys written before October 2026 were not valid OpenSSH files and their public key did not
match the private key. The private seed is unchanged, so restoring with the same seed phrase,
passphrase and path now writes working files.

### File Formats
- Private keys: unencrypted OpenSSH format (`openssh-key-v1`); add a passphrase with `ssh-keygen -p -f id_ed25519`
- Public keys: OpenSSH `authorized_keys` format
- Derivation paths: BIP32-style text, used as a salt

### Tests
`npm test` checks the word list against the official BIP39 list, the official BIP39 test
vector, pinned Ed25519 keys computed with an independent implementation, that `ssh-keygen`
accepts the files, and the server's security headers and path checks.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and practical purposes. Users are responsible for maintaining the security of their keys and seed phrases. You are solely responsible for any loss of funds or data resulting from the use of this tool.

## Troubleshooting

### Common Issues

1. **Key Generation Fails**
   - Ensure seed phrase is valid (12 or 24 words)
   - Check that words are from BIP39 word list
   - Verify passphrase if used during generation

2. **Key Restoration Fails**
   - Verify seed phrase is correct
   - Ensure derivation paths are in correct format
   - Check that passphrase matches original

3. **Key Testing Fails**
   - Verify key format is correct
   - Ensure private and public keys are from the same pair
   - Check file permissions

### Error Messages

- "Invalid seed phrase": Words must be from BIP39 word list
- "Invalid derivation path": Path must follow BIP32 format
- "Key pair verification failed": Keys are not a valid pair
- "File permission error": Check directory permissions
