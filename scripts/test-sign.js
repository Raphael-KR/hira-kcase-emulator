// Produce a CMS for the DN using our signer and dump its structure.
// Usage: node scripts/test-sign.js <password>
import forge from "node-forge";
import { signDn } from "../src/signer.js";
import { listConfiguredCerts } from "../src/certInfo.js";

const pw = process.argv[2];
if (!pw) { console.error("usage: node test-sign.js <password>"); process.exit(1); }

const entries = listConfiguredCerts();
if (!entries.length) { console.error("no cert found"); process.exit(1); }
const dn = entries[0].certObj.subjectDN;
console.log("dn =", dn);

const inputB64 = forge.util.encode64(forge.util.encodeUtf8(dn));
const cms = await signDn({ dn, inputB64, password: pw });
const der = forge.util.decode64(cms);
console.log("cms bytes =", der.length);
const asn1 = forge.asn1.fromDer(der);
console.log(forge.asn1.prettyPrint(asn1));
