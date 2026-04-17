# HIRA sign flow (APIName 21, CERT_GENERATE_SIGNDATA)

End-to-end trace of the `hira.sign("")` call that pkiLogin.jsp issues during
공동인증서 login. Covers plaintext → secure channel → CMS output.

Audience: anyone trying to build a non-Windows client for a site that depends
on the KSignCase / KCase browser agent. The only KCase-specific bit is the
WebSocket framing + the KICA-flavoured PBES1 key file; the CMS output is
plain RFC 3852 (CMS/PKCS #7) once you know the three quirks below.

## Bootstrap (once per page load)

1. **WS connect** to `wss://127.0.0.1:8443`. Browser sends the socket.io-style
   `0open` frame; emulator must *not* respond to it — see memory entry
   `kcase_0open_no_ack.md`. The first real request is `CHECK_INSTALL` (APIName 0,
   `Method="install"`).
2. **INTEGRITY_INIT** (APIName 1): emulator generates a fresh RSA-1024 keypair
   for the session, picks 128 random bytes as `Hash`, signs `sha256(hashB64)`
   with its RSA private key → returns `Hash`, `IntMsg`, `PubKey`
   (SPKI base64), `KcmvpVersion="2.5.1.1"`.
3. **HANDSHAKE** (APIName 2): client RSA-encrypts a random SEED session key +
   IV and sends as `EncryptedKey`. Emulator decrypts, stores `sessionKey` /
   `sessionIv`, and from this frame onward every `1data=` payload is
   SEED-CBC encrypted.

All subsequent frames carry a 16-byte `keyId` prefix, then
`SEED-CBC(sessionKey, sessionIv, b64nonce || b64json)`.

## CERT_LIST (APIName 10)

Returns `certObj` entries the client renders in the cert picker. Each entry is
`base64(utf8(JSON.stringify(certObj)))`, with `certObj` matching the schema in
`certInfo.js` (field names mirror min.js 6691). Status 0 = usable.

## CERT_GENERATE_SIGNDATA (APIName 21)

Client payload, after SEED decrypt:

```jsonc
{
  "APIName": 21,
  "CertDn":  "<base64(utf8(DN))>",
  "Input":   "<base64(utf8(DN))>",                 // options.signedDN=true
  "Password":"{\"IsSec\":0,\"Data\":\"<plaintext>\"}"
}
```

Handler in `src/protocol.js`:

1. Unwrap the `Password` JSON envelope. `IsSec=0` means plaintext; non-zero is
   a transit cipher we have never observed.
2. Call `signDn({ dn, inputB64: Input, password })` in `src/signer.js`.
3. Response `{ Status: 0, Output: <base64 CMS DER> }` is SEED-encrypted and
   wrapped as `{ Output: base64(cipher) }`.

Client JS posts the signeddata to
`https://extsso.hira.or.kr/sso/pmi-sso-login-certificate.jsp` (pkiLogin.jsp:113).
On accept, the iframe calls back into `parent.ssoReturn(...)` which the
KAccess SSO stub (port 39091) finishes with
`/KAService/kcase/ssoLogin`.

## `signDn` (src/signer.js)

```
Input (b64 UTF-8 DN)
  → decodeUtf8               → JS unicode string
  → iconv.encode("cp949")    → byte string (EUC-KR DN)  ← encapContent
  → forge.pkcs7.createSignedData
       content                = <CP949 DN bytes>
       certificates           = [signCert.der]
       signers[0]:
         key                  = RSA from signPri.key (via krPbe.js)
         digestAlgorithm      = sha256
         authenticatedAttributes: absent
  → p7.sign()                 (PKCS#1 v1.5, signs content directly)
  → signatureAlgorithm ← sha256WithRSAEncryption (override forge default)
  → DER encode → base64
```

`src/krPbe.js` handles the encrypted `signPri.key` (PBES1
`pbeWithSHA1AndSEED-CBC`, OID 1.2.410.200004.1.15): KDF is
`dk = SHA1^iter(pw || salt)`, key = `dk[0..16]`, iv = `SHA1(dk[16..20])[0..16]`.
Matches the PyPinkSign reference.

## CMS shape requirements

See `docs/reference-cms.txt` for the structural template. Three non-obvious
byte-level requirements HIRA enforces:

1. No `signedAttrs` — SignerInfo has exactly 5 fields; signature is over raw
   encapContent, not over a DER-encoded Attributes SET.
2. encapContent = CP949 bytes of the DN (re-encode from the UTF-8 `Input`).
3. signatureAlgorithm = sha256WithRSAEncryption (forge defaults to
   rsaEncryption; HIRA currently accepts both but Windows emits the former).

Symptom when any of those is wrong: extsso returns HTML that calls
`signError(8, "로그인 처리시 오류가 발생했습니다")`, which pkiLogin.jsp
displays as `[8] 로그인 처리시 오류가 발생했습니다`. The "8" is not in any
kcaseagent error table — it originates from the extsso iframe, not the agent.

## Tooling

| Script                          | Purpose                                       |
|---------------------------------|-----------------------------------------------|
| `scripts/test-sign.js <pw>`     | End-to-end signDn + ASN.1 pretty-print        |
| `scripts/inspect-cms.js <file>` | Pretty-print any base64/DER CMS               |
| `scripts/diagnose-pbes1.js`     | Brute-forces 8 KDF variants against signPri.key if decryption regresses |

Reference captures:
- `recon/hira-capture.jsonl` — CDP trace of a real Windows login. **Treat as a
  secret**: HIRA's CMS signs a static DN, so the embedded signeddata is a
  replayable login credential for this cert. Don't commit, don't paste into
  shared channels. Extract into a scratch file for diffing only when needed
  and delete it afterwards.
