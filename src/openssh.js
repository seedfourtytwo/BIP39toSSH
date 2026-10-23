// OpenSSH file formats for ed25519 keys, as ssh-keygen writes them.
// Public key: RFC 4253 / RFC 8709 wire blob, base64, in authorized_keys form.
// Private key: the unencrypted "openssh-key-v1" container (OpenSSH PROTOCOL.key).
const crypto = require('crypto');

const KEY_TYPE = 'ssh-ed25519';
const MAGIC = Buffer.from('openssh-key-v1\0', 'binary');

function sshString(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length);
    return Buffer.concat([len, buf]);
}

function uint32(n) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(n);
    return buf;
}

function publicBlob(publicKey) {
    return Buffer.concat([sshString(KEY_TYPE), sshString(Buffer.from(publicKey))]);
}

function encodePublicKey(publicKey, comment = '') {
    const line = `${KEY_TYPE} ${publicBlob(publicKey).toString('base64')}`;
    return (comment ? `${line} ${comment}` : line) + '\n';
}

function encodePrivateKey(seed, publicKey, comment = '') {
    const pub = Buffer.from(publicKey);
    // The check value only lets OpenSSH detect a wrong decryption passphrase; for an
    // unencrypted file any value works. Taking it from the public key keeps output reproducible.
    const check = crypto.createHash('sha256').update(pub).digest().readUInt32BE(0);
    let section = Buffer.concat([
        uint32(check),
        uint32(check),
        sshString(KEY_TYPE),
        sshString(pub),
        sshString(Buffer.concat([Buffer.from(seed), pub])),
        sshString(comment)
    ]);
    const padding = [];
    for (let i = 1; (section.length + padding.length) % 8 !== 0; i++) padding.push(i);
    section = Buffer.concat([section, Buffer.from(padding)]);

    const body = Buffer.concat([
        MAGIC,
        sshString('none'),
        sshString('none'),
        sshString(''),
        uint32(1),
        sshString(publicBlob(pub)),
        sshString(section)
    ]).toString('base64');

    return '-----BEGIN OPENSSH PRIVATE KEY-----\n'
        + body.match(/.{1,70}/g).join('\n')
        + '\n-----END OPENSSH PRIVATE KEY-----\n';
}

module.exports = { encodePublicKey, encodePrivateKey };
