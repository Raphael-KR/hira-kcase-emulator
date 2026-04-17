import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { Session } from "./session.js";
import { parseEnvelope, handleEnvelope } from "./protocol.js";
import { startSsoServer } from "./ssoServer.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const certDir = path.resolve(here, "..", "certs");
const KEY = path.join(certDir, "server.key");
const CRT = path.join(certDir, "server.crt");

if (!fs.existsSync(KEY) || !fs.existsSync(CRT)) {
  console.error(`missing ${KEY} or ${CRT} — run: npm run gen-cert`);
  process.exit(1);
}

const tlsKey = fs.readFileSync(KEY);
const tlsCrt = fs.readFileSync(CRT);

const httpsServer = https.createServer({ key: tlsKey, cert: tlsCrt });

startSsoServer({ key: tlsKey, cert: tlsCrt });

const wss = new WebSocketServer({ server: httpsServer });

wss.on("connection", (ws, req) => {
  console.log("[conn] open from %s", req.socket.remoteAddress);
  const session = new Session();
  let opened = false;

  ws.on("message", async (buf, isBinary) => {
    if (isBinary) {
      console.warn("[conn] binary frame ignored (%dB)", buf.length);
      return;
    }
    const frame = buf.toString("utf8");

    if (!opened && frame === "0open") {
      opened = true;
      console.log("[conn] 0open (no ack)");
      return;
    }

    try {
      const env = parseEnvelope(frame);
      const resp = await handleEnvelope(env, session);
      const out = JSON.stringify(resp);
      console.log("[conn] → %s (%dB resp)", peekApi(env, session), out.length);
      if (process.env.HIRA_DEBUG) {
        console.log("[conn]   resp =", out);
      }
      ws.send(out);
    } catch (err) {
      console.error("[conn] error:", err, err?.stack);
      ws.send(JSON.stringify({ Status: -1, Error: String(err) }));
    }
  });

  ws.on("close", () => console.log("[conn] close"));
  ws.on("error", (err) => console.error("[conn] err", err));
});

function peekApi(env, session) {
  try {
    if (!session.secure) {
      const decoded = Buffer.from(env.Data || "", "base64").toString("binary");
      const i = decoded.indexOf("{");
      if (i >= 0) {
        const m = decoded.slice(i).match(/"APIName"\s*:\s*(\d+)/);
        if (m) return `APIName=${m[1]}`;
      }
    }
    return `secure(${env.Method})`;
  } catch {
    return "?";
  }
}

const PORT = 8443;
httpsServer.listen(PORT, "127.0.0.1", () => {
  console.log(`hira-kcase-emulator listening on wss://127.0.0.1:${PORT}`);
});
