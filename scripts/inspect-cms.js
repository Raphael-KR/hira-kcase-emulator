// Pretty-print a CMS/SignedData blob from a file containing base64.
import fs from "node:fs";
import forge from "node-forge";

const f = process.argv[2];
if (!f) {
  console.error("usage: node inspect-cms.js <file-with-b64-or-der>");
  process.exit(1);
}
let buf = fs.readFileSync(f, "binary");
// Try to detect base64
if (/^[A-Za-z0-9+/=\n\r]+$/.test(buf.slice(0, 200))) {
  const b64 = buf.replace(/\s+/g, "");
  buf = forge.util.decode64(b64);
}
const asn1 = forge.asn1.fromDer(buf);
console.log(forge.asn1.prettyPrint(asn1));
