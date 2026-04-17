// Decrypt a Korean NPKI PKCS#8 EncryptedPrivateKeyInfo (signPri.key) into a forge RSA key.
//
// Supports two formats seen in 공동인증서:
//   1) PBES2 (pkcs5PBES2 1.2.840.113549.1.5.13)
//        keyDerivationFunc = pkcs5PBKDF2 (1.2.840.113549.1.5.12) — salt, iter, optional prf
//        encryptionScheme  = seedCBC (1.2.410.200004.1.4) — OCTET STRING IV
//   2) PBES1 pbeWithSHA1AndSEED-CBC (1.2.410.200004.1.15)
//        params = SEQ { salt OCTET STRING, iter INTEGER }
//        Key+IV derived via PKCS#5 v1.5 style PBKDF1-SHA1 producing 20B,
//        key = first 16B, iv = last 16B wraps into (bytes[4..20] ++ SHA1(dk)[0..12])
//        per the de-facto 공동인증서 implementation. We use the widely-accepted variant
//        where the iteration hashes password||salt then repeatedly hashes, and the
//        final 32 bytes = T_1 || T_2 where T_1 = H^c(pw||salt), T_2 = H(T_1 || pw||salt).
//        See NPKI Service Provider's key file parsing.
import forge from "node-forge";
import "./seed.js";

const OID = {
  pbes2:              "1.2.840.113549.1.5.13",
  pbkdf2:             "1.2.840.113549.1.5.12",
  hmacWithSha1:       "1.2.840.113549.2.7",
  hmacWithSha256:     "1.2.840.113549.2.9",
  seedCBC:            "1.2.410.200004.1.4",
  pbeWithSha1AndSeed: "1.2.410.200004.1.15",
  rsaEncryption:      "1.2.840.113549.1.1.1",
};

function asn1OidOf(obj) {
  return forge.asn1.derToOid(obj.value);
}

// PBKDF2-HMAC (forge supports sha1 + sha256).
function pbkdf2(password, salt, iter, keyLen, prf) {
  const md = prf === "sha256" ? forge.md.sha256.create() : forge.md.sha1.create();
  return forge.pkcs5.pbkdf2(password, salt, iter, keyLen, md);
}

// Korean PBES1 (pbeWithSHA1AndSEED-CBC) key+iv derivation — matches PyPinkSign reference.
//   dk  = SHA1^iter(pw || salt)           // 20B
//   key = dk[0..16]
//   iv  = SHA1(dk[16..20])[0..16]         // IV hashes the 4-byte tail only
function kdfPbes1SeedSha1(password, salt, iter) {
  const pw = forge.util.encodeUtf8(password);
  const sha1 = () => forge.md.sha1.create();

  let h = sha1();
  h.update(pw + salt);
  let dk = h.digest().bytes();
  for (let i = 1; i < iter; i++) {
    const hi = sha1();
    hi.update(dk);
    dk = hi.digest().bytes();
  }

  const key = dk.substring(0, 16);

  const hiv = sha1();
  hiv.update(dk.substring(16, 20));
  const iv = hiv.digest().bytes().substring(0, 16);

  return { key, iv };
}

function seedCbcDecrypt(key, iv, ciphertext) {
  const d = forge.cipher.createDecipher("SEED-CBC", key);
  d.start({ iv });
  d.update(forge.util.createBuffer(ciphertext));
  if (!d.finish()) throw new Error("SEED-CBC decrypt failed (bad password?)");
  return d.output.getBytes();
}

// Parse an EncryptedPrivateKeyInfo ASN.1 and decrypt it with password → PrivateKeyInfo bytes.
function decryptEpki(epkiAsn1, password) {
  // EncryptedPrivateKeyInfo ::= SEQUENCE {
  //   encryptionAlgorithm AlgorithmIdentifier,
  //   encryptedData OCTET STRING }
  const [algIdent, encData] = epkiAsn1.value;
  const algOid = asn1OidOf(algIdent.value[0]);
  const ciphertext = encData.value;

  if (algOid === OID.pbes2) {
    // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
    const [kdfAlg, encAlg] = algIdent.value[1].value;
    const kdfOid = asn1OidOf(kdfAlg.value[0]);
    if (kdfOid !== OID.pbkdf2) throw new Error(`unsupported KDF ${kdfOid}`);
    // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iter INTEGER, [keyLen INTEGER], [prf AlgorithmIdentifier] }
    const kdfParams = kdfAlg.value[1].value;
    const salt = kdfParams[0].value;
    const iter = parseInt(forge.util.bytesToHex(kdfParams[1].value), 16);
    let prf = "sha1";
    for (let i = 2; i < kdfParams.length; i++) {
      const p = kdfParams[i];
      if (p.type === forge.asn1.Type.SEQUENCE) {
        const pid = asn1OidOf(p.value[0]);
        if (pid === OID.hmacWithSha256) prf = "sha256";
      }
    }

    const encOid = asn1OidOf(encAlg.value[0]);
    if (encOid !== OID.seedCBC) throw new Error(`unsupported cipher ${encOid}`);
    // params is OCTET STRING (16-byte IV)
    const iv = encAlg.value[1].value;
    if (iv.length !== 16) throw new Error(`SEED IV must be 16B, got ${iv.length}`);

    const keyLen = 16;
    const key = pbkdf2(forge.util.encodeUtf8(password), salt, iter, keyLen, prf);
    return seedCbcDecrypt(key, iv, ciphertext);
  }

  if (algOid === OID.pbeWithSha1AndSeed) {
    // params = SEQUENCE { salt OCTET STRING, iter INTEGER }
    const params = algIdent.value[1].value;
    const salt = params[0].value;
    const iter = parseInt(forge.util.bytesToHex(params[1].value), 16);
    const { key, iv } = kdfPbes1SeedSha1(password, salt, iter);
    return seedCbcDecrypt(key, iv, ciphertext);
  }

  throw new Error(`unsupported PBE algorithm: ${algOid}`);
}

// Load a signPri.key (encrypted PKCS#8 DER) and return forge RSA private key.
export function loadEncryptedKeyDer(derBytes, password) {
  const epki = forge.asn1.fromDer(derBytes);
  const pkiDer = decryptEpki(epki, password);
  const pkiAsn1 = forge.asn1.fromDer(pkiDer);
  // PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey OCTET STRING }
  // forge helper accepts the ASN.1 directly:
  return forge.pki.privateKeyFromAsn1(pkiAsn1);
}
