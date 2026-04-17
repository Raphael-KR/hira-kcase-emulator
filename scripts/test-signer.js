// End-to-end signer test without a real 공동인증서:
//   1. Generate 2048-bit RSA + self-signed cert
//   2. Wrap the key as PKCS#8 EncryptedPrivateKeyInfo with PBES2 (PBKDF2-SHA1 + SEED-CBC)
//   3. Write DERs to a tempdir, set env vars, invoke signer.signDn()
//   4. Parse the returned CMS, verify the RSA-SHA256 signature over signedAttrs
import forge from "node-forge";
import "../src/seed.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PW = "testpw1234";

// --- 1. keypair + cert ---
const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = "01";
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date(Date.now() + 365 * 86400_000);
const dnAttrs = [
  { name: "countryName", value: "KR" },
  { name: "organizationName", value: "TEST" },
  { name: "commonName", value: "test-cn-0000000000000000" },
];
cert.setSubject(dnAttrs);
cert.setIssuer(dnAttrs);
cert.sign(keys.privateKey, forge.md.sha256.create());

// --- 2. build PKCS#8 EncryptedPrivateKeyInfo (PBES2 / PBKDF2-SHA1 / SEED-CBC) ---
const pkiBytes = forge.asn1.toDer(forge.pki.privateKeyToAsn1(keys.privateKey)).getBytes();
const pkiInfoBytes = forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey))).getBytes();
const salt = forge.random.getBytesSync(16);
const iter = 2048;
const iv = forge.random.getBytesSync(16);
const derivedKey = forge.pkcs5.pbkdf2(forge.util.encodeUtf8(PW), salt, iter, 16, forge.md.sha1.create());

const c = forge.cipher.createCipher("SEED-CBC", derivedKey);
c.start({ iv });
c.update(forge.util.createBuffer(pkiInfoBytes));
c.finish();
const ciphertext = c.output.getBytes();

const asn1 = forge.asn1;
const oidBytes = (o) => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(o).getBytes());
const int = (n) => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, forge.util.hexToBytes(hex));
};
const octet = (b) => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, b);

const kdfAlg = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  oidBytes("1.2.840.113549.1.5.12"),
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [octet(salt), int(iter)]),
]);
const encAlg = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  oidBytes("1.2.410.200004.1.4"),
  octet(iv),
]);
const pbes2Params = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [kdfAlg, encAlg]);
const algIdent = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  oidBytes("1.2.840.113549.1.5.13"), // pbes2
  pbes2Params,
]);
const epki = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  algIdent,
  octet(ciphertext),
]);
const epkiDer = asn1.toDer(epki).getBytes();

// --- 3. write DERs and invoke signer ---
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hira-signer-"));
const certPath = path.join(dir, "signCert.der");
const keyPath = path.join(dir, "signPri.key");
fs.writeFileSync(certPath, Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), "binary"));
fs.writeFileSync(keyPath, Buffer.from(epkiDer, "binary"));
console.log("wrote", certPath, "and", keyPath);

process.env.HIRA_SIGN_CERT = certPath;
process.env.HIRA_SIGN_KEY = keyPath;

const { signDn } = await import("../src/signer.js");
const dnStr = cert.subject.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(",");
const inputB64 = forge.util.encode64(forge.util.encodeUtf8(dnStr));
const cmsB64 = await signDn({ dn: dnStr, inputB64, password: PW });
console.log("CMS length:", cmsB64.length, "chars (base64)");

// --- 4. verify with openssl CLI (authoritative) ---
import { execFileSync } from "node:child_process";

// Write CMS to DER file, extracted content to file, cert to PEM
const cmsPath = path.join(dir, "signed.cms");
const contentPath = path.join(dir, "content.bin");
const certPem = path.join(dir, "cert.pem");
fs.writeFileSync(cmsPath, Buffer.from(forge.util.decode64(cmsB64), "binary"));
fs.writeFileSync(contentPath, Buffer.from(forge.util.decode64(inputB64), "binary"));
fs.writeFileSync(certPem, forge.pki.certificateToPem(cert));

// openssl cms -verify -inform der -content <bytes> -certfile cert -noverify (skip chain)
try {
  const out = execFileSync(
    "openssl",
    [
      "cms",
      "-verify",
      "-in", cmsPath,
      "-inform", "der",
      "-certfile", certPem,
      "-CAfile", certPem, // self-signed — trust as root
      "-purpose", "any",
      "-no_check_time",
    ],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  console.log("openssl cms -verify output:");
  console.log(out);
  console.log("\n✅ signer end-to-end test OK (openssl accepted the CMS)");
} catch (e) {
  console.error("openssl verify FAILED:");
  console.error("stdout:", e.stdout?.toString());
  console.error("stderr:", e.stderr?.toString());
  process.exit(1);
}
