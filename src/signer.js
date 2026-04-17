// Build a PKCS#7 SignedData blob over the `Input` that the kcaseagt client asked us to sign.
// For HIRA login: Input = base64(utf8(subjectDN)) because options.signedDN=true (min.js 8122).
// The captured Windows agent output has:
//   - no signedAttrs (signature is computed directly over the raw content)
//   - encapContentInfo OCTET STRING = CP949/EUC-KR bytes of the DN, not UTF-8
// so we re-encode UTF-8 → CP949 before signing.
import forge from "node-forge";
import fs from "node:fs";
import iconv from "iconv-lite";
import { loadEncryptedKeyDer } from "./krPbe.js";
import { findSignCertPairs } from "./npkiLocator.js";

let cachedKey = null;
let cachedKeyPw = null;
let cachedKeyPath = null;

function pickPair() {
  const pairs = findSignCertPairs();
  if (pairs.length === 0) {
    throw new Error("no signCert.der found (set HIRA_SIGN_CERT or install cert under ~/Library/Preferences/NPKI/<CA>/USER/<dn>/)");
  }
  return pairs[0];
}

function loadCert() {
  const { certPath } = pickPair();
  const der = fs.readFileSync(certPath, "binary");
  return forge.pki.certificateFromAsn1(forge.asn1.fromDer(der));
}

function loadKey(password) {
  const { keyPath } = pickPair();
  if (cachedKey && cachedKeyPw === password && cachedKeyPath === keyPath) return cachedKey;
  const der = fs.readFileSync(keyPath, "binary");
  cachedKey = loadEncryptedKeyDer(der, password);
  cachedKeyPw = password;
  cachedKeyPath = keyPath;
  return cachedKey;
}

export async function signDn({ dn, inputB64, password }) {
  const cert = loadCert();
  const key = loadKey(password);

  // Client sends Input = base64(utf8(subjectDN)); convert to CP949 so our
  // CMS encapContentInfo matches the Windows agent byte-for-byte.
  const utf8Bytes = forge.util.decode64(inputB64);
  const unicode = forge.util.decodeUtf8(utf8Bytes);
  const contentBytes = iconv.encode(unicode, "cp949").toString("binary");

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(contentBytes);
  p7.addCertificate(cert);
  p7.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
  });
  p7.sign({ detached: false });

  // forge defaults signatureAlgorithm to rsaEncryption (1.2.840.113549.1.1.1);
  // Windows-produced CMS advertises sha256WithRSAEncryption (1.2.840.113549.1.1.11).
  // Mutate before toAsn1 so the wire format matches.
  for (const s of p7.signers) s.signatureAlgorithm = forge.pki.oids.sha256WithRSAEncryption;

  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return forge.util.encode64(der);
}
