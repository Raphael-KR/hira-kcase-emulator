# HIRA e-Form login for macOS

> Run HIRA e-Form 공동인증서 login on macOS — without Windows or KCase.

A minimal Node.js re-implementation of the Windows-only **KSignCase / KCase**
PKI browser agent, enough to complete 공동인증서 login on
`https://ef.hira.or.kr` (건강보험심사평가원 e-Form 시스템) from macOS.

The real KCase agent is a native Windows service that the HIRA login page
talks to over a local WebSocket. This project emulates the subset of its
protocol that HIRA uses, reads the 공동인증서 from `~/Library/Preferences/NPKI/`,
and produces a CMS SignedData that HIRA's extsso server accepts.

> **Status:** works for `ef.hira.or.kr` login as of 2026-04. Not tested on any
> other HIRA site (the main `portal.hira.or.kr`, `biz.hira.or.kr`, etc. use
> different auth flows and are out of scope). No warranty, no affiliation with
> HIRA or KSIGN.

## Why this exists

HIRA's 공동인증서 login page does not talk to the certificate directly. It
talks to a **local** Windows service (KCase agent) over `wss://127.0.0.1:8443`
and to a **local** KAccess SSO helper over `https://127.0.0.1:39091`. Both
ship only as Windows installers (historically ActiveX, now a native service),
so on macOS the login page has no one to talk to and fails before the
password prompt. This project runs those two endpoints locally on macOS with
just enough of the protocol to finish the login.

```
  Browser (ef.hira.or.kr)
      │  wss://127.0.0.1:8443   ← kcase agent
      │  https://127.0.0.1:39091 ← kaccess sso
      ▼
  this repo ──► reads ~/Library/Preferences/NPKI/ ──► CMS SignedData
      │
      ▼  POST /sso/pmi-sso-login-certificate.jsp
  extsso.hira.or.kr
```

## Three non-obvious CMS quirks

Once the WebSocket handshake works, 90% of remaining time is spent fighting
HIRA's extsso verifier (`[8] 로그인 처리시 오류가 발생했습니다`). The Windows
KCase agent emits a CMS SignedData with three things forge/openssl defaults
get wrong:

1. **No `signedAttrs`.** SignerInfo has exactly 5 fields. The signature is
   computed over the raw encapContent bytes, not over a DER-encoded
   Attributes SET. With node-forge, omit `authenticatedAttributes` in
   `addSigner({...})`.
2. **encapContent is CP949, not UTF-8.** The browser sends
   `Input = base64(utf8(DN))`, but the Windows agent re-encodes to CP949
   before it goes into the OCTET STRING. Example: `미` is `B9 CC` in CP949,
   not `EB AF BC`. Use `iconv-lite.encode(dn, "cp949")`.
3. **`signatureAlgorithm = sha256WithRSAEncryption`** (OID
   `1.2.840.113549.1.1.11`), not the bare `rsaEncryption` OID that forge
   emits by default.

See [`docs/SIGN_FLOW.md`](docs/SIGN_FLOW.md) for the full walk-through and
[`docs/reference-cms.txt`](docs/reference-cms.txt) for an ASN.1 template.

## What it replaces

| Windows component       | This project                                             |
|-------------------------|----------------------------------------------------------|
| KCase agent (WSS 8443)  | `src/server.js` + `src/protocol.js` + `src/session.js`   |
| KAccess SSO (HTTPS 39091)| `src/ssoServer.js`                                      |
| Cert store access       | `src/npkiLocator.js` scans `~/Library/Preferences/NPKI/` |
| Encrypted key parsing   | `src/krPbe.js` (PBES1 `pbeWithSHA1AndSEED-CBC`)          |
| CMS signing             | `src/signer.js` (node-forge pkcs7 + iconv-lite for CP949)|

## Prerequisites

1. **Node.js ≥ 18**.
2. **공동인증서 installed** under `~/Library/Preferences/NPKI/<CA>/USER/<DN>/`,
   containing `signCert.der` + `signPri.key`. If your cert is on a USB stick
   or an iOS "인증서 관리" app, copy the pair to the NPKI directory first.
3. **SEED cipher in Node**. Node does not ship SEED; `src/seed.js` is a pure-JS
   port used through `node-forge`.

## Install & run

```bash
git clone <this repo>
cd macos_agent
npm install

# Generate a self-signed TLS cert for the local WSS endpoint.
npm run gen-cert

# Trust the generated cert so Chrome accepts wss://127.0.0.1:8443.
security add-trusted-cert -d -r trustAsRoot \
  -k ~/Library/Keychains/login.keychain-db certs/server.crt

npm start
```

Then open `https://ef.hira.or.kr` → 공동인증서 로그인. The agent logs each
request to stdout; set `HIRA_DEBUG=1` for verbose protocol traces.

## Picking a specific cert

`findSignCertPairs()` returns the first cert found. Override with env vars:

```bash
HIRA_SIGN_CERT=/path/to/signCert.der HIRA_SIGN_KEY=/path/to/signPri.key npm start
```

## Documentation

- [`docs/SIGN_FLOW.md`](docs/SIGN_FLOW.md) — end-to-end walk-through of the
  WebSocket handshake, SEED-CBC session, and the three non-obvious CMS
  requirements HIRA enforces.
- [`docs/reference-cms.txt`](docs/reference-cms.txt) — ASN.1 template of a
  valid signeddata (generic DN; regenerate your own with
  `node scripts/test-sign.js <password>`).

## Scripts

| Script                          | Purpose                                             |
|---------------------------------|-----------------------------------------------------|
| `npm start`                     | Run the emulator (WSS 8443 + SSO 39091)             |
| `npm run gen-cert`              | Regenerate the self-signed WSS cert                 |
| `node scripts/test-sign.js <pw>`| Run the sign path standalone, print CMS structure   |
| `node scripts/inspect-cms.js`   | Pretty-print any base64/DER CMS blob                |
| `node scripts/diagnose-pbes1.js`| Brute-force 8 PBES1 KDF variants if decryption fails|

## Security notes

- The emulator's TLS private key (`certs/server.key`) and the trusted-root
  entry are local to your machine. Don't re-use them on another host.
- A successful CMS signs a static DN, so the output is a replayable login
  credential. Treat log files, capture traces, and CMS dumps as secrets.
- This project does **not** store your 공동인증서 password anywhere. It is
  passed through from the browser password prompt, used once to decrypt the
  RSA key, and kept only in memory (with the decrypted key cached per-path
  so repeat signs don't re-prompt).

## Legal

Reverse-engineered by looking at the browser-side JavaScript HIRA serves
(which runs unminified-enough in any browser), plus captured WebSocket frames
against a Windows KCase install. Does not redistribute any KSIGN, HIRA, or
KICA binaries or source. See also [PyPinkSign](https://github.com/bandoche/PyPinkSign)
for an independent Python reference of the 공동인증서 key format.
