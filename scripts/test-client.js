// Replays the real kcaseagt client protocol against our emulator.
// Verifies: CHECK_INSTALL, INTEGRITY_INIT (PubKey + IntMsg signature), HANDSHAKE
// (EncryptedKey round trip + HandshakeMsg nonce echo), and one secure round-trip.
import forge from "node-forge";
import "../src/seed.js";
import WebSocket from "ws";

const URL = "wss://127.0.0.1:8443/";
const JSP_SESS = "TEST_SESSION_ID!1234!5678";

const ws = new WebSocket(URL, { rejectUnauthorized: false });

const sessionKeyId = forge.random.getBytesSync(16);
let rsaPubKey = null;
let sessionId = null;
let seedKey = null;
let seedIv = null;
let step = "open";
let pending = null;

function sendEnv(method, sessId, sendObj, secure = false) {
  const inner = JSON.stringify(sendObj);
  let dataBytes;
  if (!secure) {
    dataBytes = sessionKeyId + inner;
    if (sendObj.APIName === 0) dataBytes = inner; // CHECK_INSTALL has no keyId
  } else {
    const nonce = forge.util.encode64(forge.random.getBytesSync(8));
    const plain = nonce + forge.util.encode64(inner);
    const c = forge.cipher.createCipher("SEED-CBC", seedKey);
    c.start({ iv: seedIv });
    c.update(forge.util.createBuffer(plain));
    c.finish();
    dataBytes = sessionKeyId + c.output.getBytes();
  }
  const env = {
    SessionId: sessId,
    Data: forge.util.encode64(dataBytes),
    Method: method,
  };
  ws.send("1data=" + JSON.stringify(env));
}

function expect(cond, msg) {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exit(1);
  }
  console.log("  OK", msg);
}

ws.on("open", () => {
  console.log("[client] connected");
  ws.send("0open");
});

ws.on("message", (buf) => {
  const txt = buf.toString("utf8");
  console.log("[client] recv:", txt.length > 120 ? txt.slice(0, 120) + "..." : txt);
  const msg = JSON.parse(txt);

  if (step === "open") {
    expect(Object.keys(msg).length === 0, "server ack'd 0open with {}");
    step = "check_install";
    sendEnv("install", "kcase", { APIName: 0 });
    return;
  }

  if (step === "check_install") {
    expect(msg.Status === 0, "CHECK_INSTALL Status=0");
    expect(msg.Version === "1.3.28", "Version=1.3.28");
    step = "integrity_init";
    sendEnv("post", forge.util.encode64(JSP_SESS), {
      APIName: 1,
      Version: "1.3.28",
      Config: '""',
      ubikeyVer: "1.4.1.3||HIRA|NULL||x||KSIGN|INCANOS|",
      ubiurl: "",
      maxpwdcnt: 5,
    });
    return;
  }

  if (step === "integrity_init") {
    expect(msg.Status === 0, "INTEGRITY_INIT Status=0");
    expect(typeof msg.PubKey === "string" && msg.PubKey.length > 50, "PubKey present");
    expect(typeof msg.IntMsg === "string" && msg.IntMsg.length > 50, "IntMsg present");
    expect(typeof msg.Hash === "string", "Hash present");

    // Verify IntMsg like the real client does
    const spki = forge.asn1.fromDer(forge.util.decode64(msg.PubKey));
    rsaPubKey = forge.pki.publicKeyFromAsn1(spki);
    const md = forge.md.sha256.create();
    md.update(msg.Hash);
    const intSig = forge.util.decode64(msg.IntMsg);
    const verified = rsaPubKey.verify(md.digest().bytes(), intSig);
    expect(verified === true, "IntMsg signature verifies against PubKey");

    sessionId = msg.SessionId;
    step = "handshake";
    // Generate key/iv/nonce like the real client, encrypt with RSA-PKCS1v1.5
    seedKey = forge.random.getBytesSync(16);
    seedIv = forge.random.getBytesSync(16);
    const nonce32 = forge.random.getBytesSync(32);
    const plaintext = seedKey + seedIv + nonce32;
    const encKey = rsaPubKey.encrypt(plaintext, "RSAES-PKCS1-V1_5");
    globalThis.__nonce32 = nonce32;
    sendEnv("post", sessionId, { APIName: 2, EncryptedKey: forge.util.encode64(encKey) });
    return;
  }

  if (step === "handshake") {
    expect(msg.Status === 0, "HANDSHAKE Status=0");
    expect(typeof msg.HandshakeMsg === "string", "HandshakeMsg present");
    // decrypt HandshakeMsg with seedKey/seedIv and verify it equals our nonce32
    const d = forge.cipher.createDecipher("SEED-CBC", seedKey);
    d.start({ iv: seedIv });
    d.update(forge.util.createBuffer(forge.util.decode64(msg.HandshakeMsg)));
    d.finish();
    const decryptedNonce = d.output.getBytes();
    expect(decryptedNonce === globalThis.__nonce32, "HandshakeMsg decrypts to our nonce");

    step = "cert_list";
    sendEnv("post", sessionId, { APIName: 10, Media: "HDD", Drive: "" }, true);
    return;
  }

  if (step === "cert_list") {
    expect(typeof msg.Output === "string", "CERT_LIST returned Output (SEED-encrypted)");
    // decrypt and parse
    const d = forge.cipher.createDecipher("SEED-CBC", seedKey);
    d.start({ iv: seedIv });
    d.update(forge.util.createBuffer(forge.util.decode64(msg.Output)));
    d.finish();
    const inner = JSON.parse(d.output.getBytes());
    expect(inner.Status === 0, "inner Status=0");
    console.log("  inner payload:", JSON.stringify(inner).slice(0, 80));
    console.log("\n✅ full bootstrap round-trip OK");
    ws.close();
    process.exit(0);
  }
});

ws.on("error", (err) => {
  console.error("[client] error:", err);
  process.exit(1);
});
