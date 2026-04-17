// Generate a self-signed RSA cert for wss://127.0.0.1:8443
// Output: certs/server.key, certs/server.crt (PEM)
// Install once:
//   security add-trusted-cert -d -r trustAsRoot -k ~/Library/Keychains/login.keychain-db certs/server.crt
import forge from "node-forge";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, "..", "certs");
fs.mkdirSync(outDir, { recursive: true });

const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = "01" + forge.util.bytesToHex(forge.random.getBytesSync(8));

const now = new Date();
cert.validity.notBefore = new Date(now.getTime() - 24 * 3600 * 1000);
cert.validity.notAfter = new Date(now.getFullYear() + 10, now.getMonth(), now.getDate());

const attrs = [
  { name: "commonName", value: "127.0.0.1" },
  { name: "countryName", value: "KR" },
  { name: "organizationName", value: "HIRA-eform-poc" },
];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([
  { name: "basicConstraints", cA: true },
  { name: "keyUsage", keyCertSign: true, digitalSignature: true, keyEncipherment: true },
  { name: "extKeyUsage", serverAuth: true, clientAuth: true },
  {
    name: "subjectAltName",
    altNames: [
      { type: 7, ip: "127.0.0.1" },
      { type: 2, value: "localhost" },
    ],
  },
]);
cert.sign(keys.privateKey, forge.md.sha256.create());

fs.writeFileSync(path.join(outDir, "server.key"), forge.pki.privateKeyToPem(keys.privateKey));
fs.writeFileSync(path.join(outDir, "server.crt"), forge.pki.certificateToPem(cert));
console.log(`wrote ${outDir}/server.{key,crt}`);
console.log(
  `trust with: security add-trusted-cert -d -r trustAsRoot -k ~/Library/Keychains/login.keychain-db ${path.join(outDir, "server.crt")}`,
);
