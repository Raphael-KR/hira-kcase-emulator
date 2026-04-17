// Parse a signCert.der into the JSON schema the kcaseagt client expects in CERT_LIST responses.
// Shape is dictated by min.js 6691 _certObjToCertInfo (fields read off certObj).
import forge from "node-forge";
import fs from "node:fs";
import { findSignCertPairs } from "./npkiLocator.js";

function pad2(n) { return String(n).padStart(2, "0"); }

function fmtDate(d) {
  // "YYYY-MM-DD HH:MM:SS" — min.js splits notAfter on the space (line 6788).
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
         `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function decUtf8(s) {
  if (typeof s !== "string" || !s) return s || "";
  // forge returns UTF8String / BMPString values as raw byte-strings;
  // decodeUtf8 promotes them to proper JS unicode.
  try { return forge.util.decodeUtf8(s); } catch { return s; }
}

function dnToString(attrs) {
  // Korean CP format: "cn=...,ou=...,o=...,c=kr" — KICA uses lowercase short names.
  return attrs.map((a) => `${(a.shortName || a.name || "").toLowerCase()}=${decUtf8(a.value)}`).join(",");
}

function findExt(cert, name) {
  return cert.extensions.find((e) => e.name === name);
}

function bytesHex(bytes) {
  return forge.util.bytesToHex(bytes || "");
}

export function certDerToCertObj(derBytes, certIndex) {
  const asn1 = forge.asn1.fromDer(derBytes);
  const cert = forge.pki.certificateFromAsn1(asn1);

  const subjectCN = decUtf8(cert.subject.getField("CN")?.value || "");
  const subjectDN = dnToString(cert.subject.attributes);
  const issuerDN = dnToString(cert.issuer.attributes);
  const issuerOrg = decUtf8(cert.issuer.getField("O")?.value || "");

  const pubKeyAsn1 = forge.pki.publicKeyToAsn1(cert.publicKey);
  const pubKeyDer = forge.asn1.toDer(pubKeyAsn1).getBytes();
  const pubKey = forge.util.encode64(pubKeyDer);
  const pubKeyLength = cert.publicKey.n.bitLength();

  const sigAlgoName = forge.pki.oids[cert.siginfo.algorithmOid] || cert.siginfo.algorithmOid;

  let authorityKeyId = "";
  const akiExt = findExt(cert, "authorityKeyIdentifier");
  if (akiExt) {
    authorityKeyId = bytesHex(akiExt.keyIdentifier);
  }

  let subjectKeyId = "";
  const skiExt = findExt(cert, "subjectKeyIdentifier");
  if (skiExt) {
    subjectKeyId = bytesHex(skiExt.subjectKeyIdentifier);
  }

  let subjectAltName = "";
  const sanExt = findExt(cert, "subjectAltName");
  if (sanExt && sanExt.altNames) {
    subjectAltName = sanExt.altNames.map((a) => a.value || bytesHex(a.value)).join(",");
  }

  let keyUsage = "";
  const kuExt = findExt(cert, "keyUsage");
  if (kuExt) {
    const flags = [];
    for (const k of ["digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment",
                     "keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"]) {
      if (kuExt[k]) flags.push(k);
    }
    keyUsage = flags.join(",");
  }

  let policyOid = "";
  let cps = "";
  const polExt = cert.extensions.find((e) => e.id === "2.5.29.32"); // certificatePolicies
  if (polExt) {
    // forge doesn't decode certPolicies natively — pull first OID from the raw ASN.1.
    try {
      const polAsn1 = forge.asn1.fromDer(polExt.value);
      const first = polAsn1.value?.[0];
      const oidNode = first?.value?.[0];
      if (oidNode) policyOid = forge.asn1.derToOid(oidNode.value);
    } catch {}
  }

  let dp = "";
  const dpExt = findExt(cert, "cRLDistributionPoints");
  if (dpExt) {
    try {
      const dpAsn1 = forge.asn1.fromDer(dpExt.value);
      // Walk into the first distributionPoint → fullName → URI.
      const uri = dpAsn1.value?.[0]?.value?.[0]?.value?.[0]?.value?.[0]?.value;
      if (uri) dp = uri;
    } catch {}
  }

  let authorityInfoAccessOCSP = "";
  const aiaExt = cert.extensions.find((e) => e.id === "1.3.6.1.5.5.7.1.1");
  if (aiaExt) {
    try {
      const aiaAsn1 = forge.asn1.fromDer(aiaExt.value);
      for (const descr of aiaAsn1.value || []) {
        const methodOid = forge.asn1.derToOid(descr.value[0].value);
        if (methodOid === "1.3.6.1.5.5.7.48.1") {
          authorityInfoAccessOCSP = descr.value[1].value;
          break;
        }
      }
    } catch {}
  }

  return {
    version: cert.version, // 2 → v3
    serialNumber: cert.serialNumber, // hex string from forge
    signAlgorithm: sigAlgoName,
    issuerDN,
    issuerOrg,
    notBefore: fmtDate(cert.validity.notBefore),
    notAfter: fmtDate(cert.validity.notAfter),
    subjectCN,
    subjectDN,
    pubKey,
    pubKeyAlgo: "RSA",
    pubKeyLength,
    authorityKeyId,
    subjectKeyId,
    policy: policyOid,
    cps,
    noti: "",
    subjectAltName,
    dp,
    authorityInfoAccessOCSP,
    keyUsage,
    authorityCertSerialNumber: "",
    signautre: "", // sic — min.js has a typo that we mirror
    certIndex,
  };
}

// Load certificates discovered under NPKI (or HIRA_SIGN_CERT override) and return
// entries ready for CERT_LIST. Returns [{ certObj, certPath, keyPath, status }].
export function listConfiguredCerts() {
  const pairs = findSignCertPairs();
  const out = [];
  pairs.forEach(({ certPath, keyPath }, idx) => {
    try {
      const der = fs.readFileSync(certPath, "binary");
      const certObj = certDerToCertObj(der, idx);
      out.push({ certObj, certPath, keyPath, status: 0 });
      console.log("[cert] loaded %s (CN=%s)", certPath, certObj.subjectCN);
    } catch (err) {
      console.error("[cert] failed to load", certPath, err);
    }
  });
  return out;
}
