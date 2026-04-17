// Try several documented KDF variants for pbeWithSHA1AndSEED (1.2.410.200004.1.15)
// against the user's signPri.key. Prints which variant yields a parseable RSA PrivateKeyInfo.
import fs from "node:fs";
import forge from "node-forge";
import "../src/seed.js";

const PW = process.argv[2];
const KEY = process.argv[3];
if (!PW || !KEY) {
  console.error("usage: node diagnose-pbes1.js <password> <signPri.key path>");
  process.exit(1);
}

const der = fs.readFileSync(KEY, "binary");
const asn1 = forge.asn1.fromDer(der);
const [algIdent, encData] = asn1.value;
const params = algIdent.value[1].value;
const salt = params[0].value;
const iter = parseInt(forge.util.bytesToHex(params[1].value), 16);
const ct = encData.value;
console.log("salt=", forge.util.bytesToHex(salt), "iter=", iter, "ctLen=", ct.length);

const sha1 = (s) => {
  const h = forge.md.sha1.create();
  h.update(s);
  return h.digest().bytes();
};

function iterateSha1(init, iter) {
  let d = sha1(init);
  for (let i = 1; i < iter; i++) d = sha1(d);
  return d;
}

function tryDecrypt(label, key, iv) {
  try {
    const d = forge.cipher.createDecipher("SEED-CBC", key);
    d.start({ iv });
    d.update(forge.util.createBuffer(ct));
    if (!d.finish()) return console.log(`[${label}] finish() returned false`);
    const pt = d.output.getBytes();
    // Check if it parses as PrivateKeyInfo (starts with SEQUENCE)
    const firstByte = pt.charCodeAt(0);
    if (firstByte !== 0x30) {
      return console.log(`[${label}] finish ok but first byte=0x${firstByte.toString(16)} (not SEQUENCE)`);
    }
    const pki = forge.asn1.fromDer(pt);
    const key2 = forge.pki.privateKeyFromAsn1(pki);
    console.log(`[${label}] ✓ DECRYPTED OK, modulus bits=${key2.n.bitLength()}`);
  } catch (e) {
    console.log(`[${label}] parse fail: ${e.message}`);
  }
}

const pw = forge.util.encodeUtf8(PW);

// V1: dk = SHA1^iter(pw||salt); key=dk[0..16]; iv = SHA1(dk[16..20]||pw||salt)[0..16]
{
  const dk = iterateSha1(pw + salt, iter);
  const key = dk.substring(0, 16);
  const iv = sha1(dk.substring(16, 20) + pw + salt).substring(0, 16);
  tryDecrypt("V1 pw||salt, iv=SHA1(dk[16..20]||pw||salt)", key, iv);
}

// V2: dk = SHA1^iter(salt||pw); same iv recipe
{
  const dk = iterateSha1(salt + pw, iter);
  const key = dk.substring(0, 16);
  const iv = sha1(dk.substring(16, 20) + pw + salt).substring(0, 16);
  tryDecrypt("V2 salt||pw, iv=SHA1(dk[16..20]||pw||salt)", key, iv);
}

// V3: dk = SHA1^iter(pw||salt); iv = SHA1(dk[16..20]||salt||pw)[0..16]
{
  const dk = iterateSha1(pw + salt, iter);
  const key = dk.substring(0, 16);
  const iv = sha1(dk.substring(16, 20) + salt + pw).substring(0, 16);
  tryDecrypt("V3 pw||salt, iv=SHA1(dk[16..20]||salt||pw)", key, iv);
}

// V4: KISA PBKDF1-like — c times of SHA1(pw||salt||prev) concatenated? Or classic PKCS#5 PBKDF1.
// Classic PBKDF1: T1 = H(pw||salt); Ti = H(T_{i-1}); output = T_c (20B). key+iv = first 24? N/A.
// Try: key=dk[0..16], iv=dk[4..20] (16B from tail overlap)
{
  const dk = iterateSha1(pw + salt, iter);
  const key = dk.substring(0, 16);
  const iv = dk.substring(4, 20);
  tryDecrypt("V4 pw||salt, key=dk[0..16], iv=dk[4..20]", key, iv);
}

// V5: dk = SHA1^iter(pw||salt); key=dk[0..16]; iv = dk2 where dk2 = SHA1(dk||pw||salt)[0..16]
{
  const dk = iterateSha1(pw + salt, iter);
  const key = dk.substring(0, 16);
  const iv = sha1(dk + pw + salt).substring(0, 16);
  tryDecrypt("V5 pw||salt, iv=SHA1(dk||pw||salt)", key, iv);
}

// V6: Two-round extend: T1 = SHA1^iter(pw||salt); T2 = SHA1^iter(T1||pw||salt); key=T1, iv=T2
{
  const t1 = iterateSha1(pw + salt, iter);
  const t2 = iterateSha1(t1 + pw + salt, iter);
  tryDecrypt("V6 two-round extend, key=T1[0..16], iv=T2[0..16]", t1.substring(0, 16), t2.substring(0, 16));
}

// V7: PKCS#12 style — extended password encoding (UTF-16BE + trailing null). Rare but possible.
{
  // encode password as UTF-16BE with trailing 0x0000
  let pw16 = "";
  for (let i = 0; i < PW.length; i++) {
    const c = PW.charCodeAt(i);
    pw16 += String.fromCharCode((c >> 8) & 0xff, c & 0xff);
  }
  pw16 += "\x00\x00";
  const dk = iterateSha1(pw16 + salt, iter);
  const key = dk.substring(0, 16);
  const iv = sha1(dk.substring(16, 20) + pw16 + salt).substring(0, 16);
  tryDecrypt("V7 UTF-16BE pw+\\0\\0", key, iv);
}

// V8: Some NPKI parsers use a 32-byte KDF via PKCS#12 v1 (id=1 for key, id=2 for IV)
// This is a big variant — implement PKCS12 PBE for completeness.
function pkcs12kdf(pw16, salt, id, iter, n) {
  const u = 20; // sha1
  const v = 64; // block
  const D = String.fromCharCode(id).repeat(v);
  const Slen = Math.ceil(salt.length / v) * v;
  let S = "";
  while (S.length < Slen) S += salt;
  S = S.substring(0, Slen);
  const Plen = Math.ceil(pw16.length / v) * v;
  let P = "";
  while (P.length < Plen) P += pw16;
  P = P.substring(0, Plen);
  const I = S + P;

  const out = [];
  while (out.join("").length < n) {
    let A = D + I;
    A = sha1(A);
    for (let r = 1; r < iter; r++) A = sha1(A);
    out.push(A);
    if (out.join("").length >= n) break;
    // Update I: B = repeat(A, v)
    let B = "";
    while (B.length < v) B += A;
    B = B.substring(0, v);
    // treat I as array of v-byte blocks; Ij = (Ij + B + 1) mod 2^(v*8)
    const newI = [];
    for (let j = 0; j < I.length; j += v) {
      const Ij = I.substring(j, j + v);
      // add Ij + B + 1
      let carry = 1;
      let res = "";
      for (let k = v - 1; k >= 0; k--) {
        const sum = (Ij.charCodeAt(k) + B.charCodeAt(k) + carry) & 0xffff;
        res = String.fromCharCode(sum & 0xff) + res;
        carry = (sum >> 8) & 0xff;
      }
      newI.push(res);
    }
    // replace I
    let ni = "";
    for (const b of newI) ni += b;
    I.substring = undefined; // noop marker
    // eslint-disable-next-line no-param-reassign
    arguments[6] = ni; // unused; we keep I by closure below
  }
  return out.join("").substring(0, n);
}

// V8 using PKCS#12 PBE with UTF-16BE password
{
  let pw16 = "";
  for (let i = 0; i < PW.length; i++) {
    const c = PW.charCodeAt(i);
    pw16 += String.fromCharCode((c >> 8) & 0xff, c & 0xff);
  }
  pw16 += "\x00\x00";
  try {
    const key = pkcs12kdf(pw16, salt, 1, iter, 16);
    const iv = pkcs12kdf(pw16, salt, 2, iter, 16);
    tryDecrypt("V8 PKCS#12 PBE id=1 key, id=2 iv", key, iv);
  } catch (e) {
    console.log("[V8] kdf error:", e.message);
  }
}
