import forge from "node-forge";
import "./seed.js"; // registers SEED-CBC with forge.cipher

// Per-WebSocket-connection state. Recreated on every new connection.
export class Session {
  constructor() {
    // Page-JSP session id, captured from INTEGRITY_INIT envelope; echoed back to client.
    this.sessionId = null;
    // Client-chosen 16B keyId prefix (from min.js: random.generate(16), set inside kcaseagt.init).
    // We never generate it — we observe it and use it for parse-side sanity only.
    this.sessionKeyId = null;

    // 1024-bit RSA keypair we mint for this session. Client encrypts its SEED key to our pubKey.
    this.rsaKeys = forge.pki.rsa.generateKeyPair(1024);

    // Set after HANDSHAKE:
    this.seedKey = null; // 16 bytes binary string
    this.seedIv = null;  // 16 bytes binary string
    this.nonce32 = null; // 32 bytes binary string — must be echoed in HandshakeMsg
    this.secure = false;
  }

  // PubKey: raw RSAPublicKey DER base64 (not SPKI). Real agent capture shows
  // `30 81 89 02 81 81 00 ...` = SEQUENCE { INTEGER modulus, INTEGER exponent }.
  // min.js publicKeyFromAsn1 accepts both, but we match the real format.
  getPubKeyBase64Spki() {
    const { n, e } = this.rsaKeys.publicKey;
    const asn1 = forge.asn1;
    const intNode = (bn) => {
      let hex = bn.toString(16);
      if (hex.length % 2) hex = "0" + hex;
      // Prepend 0x00 if high bit set to keep INTEGER positive.
      if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = "00" + hex;
      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, forge.util.hexToBytes(hex));
    };
    const rsaPubAsn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      intNode(n),
      intNode(e),
    ]);
    const derBytes = asn1.toDer(rsaPubAsn1).getBytes();
    return forge.util.encode64(derBytes);
  }

  // Sign sha256(Hash_string_bytes_as_received) with our private key — PKCS#1 v1.5.
  // Returns base64.
  signIntMsg(hashStr) {
    const md = forge.md.sha256.create();
    md.update(hashStr);
    const sig = this.rsaKeys.privateKey.sign(md);
    return forge.util.encode64(sig);
  }

  // Extract SEED key/iv/nonce from the RSA-encrypted EncryptedKey base64 blob.
  // Client packs: key(16) || iv(16) || nonce(32) = 64 bytes, PKCS#1 v1.5 padded, RSA(PubKey).
  ingestEncryptedKey(base64EncKey) {
    const ciphertext = forge.util.decode64(base64EncKey);
    const plain = this.rsaKeys.privateKey.decrypt(ciphertext, "RSAES-PKCS1-V1_5");
    if (plain.length !== 64) {
      throw new Error(`EncryptedKey plaintext is ${plain.length}B, expected 64`);
    }
    this.seedKey = plain.substring(0, 16);
    this.seedIv = plain.substring(16, 32);
    this.nonce32 = plain.substring(32, 64);
    this.secure = true;
  }

  // HandshakeMsg to send back: SEED-CBC(key, iv, nonce32) → base64.
  getHandshakeMsgBase64() {
    return forge.util.encode64(this.seedEncrypt(this.nonce32));
  }

  seedEncrypt(plainBytes) {
    const c = forge.cipher.createCipher("SEED-CBC", this.seedKey);
    c.start({ iv: this.seedIv });
    c.update(forge.util.createBuffer(plainBytes));
    c.finish();
    return c.output.getBytes();
  }

  seedDecrypt(cipherBytes) {
    const d = forge.cipher.createDecipher("SEED-CBC", this.seedKey);
    d.start({ iv: this.seedIv });
    d.update(forge.util.createBuffer(cipherBytes));
    d.finish();
    return d.output.getBytes();
  }
}
