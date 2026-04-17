// KAccess SSO agent emulator.
// pkiLogin.jsp calls KAccess on https://127.0.0.1:39091 after our PKI init succeeds.
// Endpoints and expected resultCodes are derived from recon/KAccess_utf8.js.
import https from "node:https";

const ENDPOINTS = {
  "/init":            { resultCode: "INIT1" },
  "/CheckVersion":    { resultCode: "UPDATE00" }, // up to date
  "/SetData":         { resultCode: "SET01" },
  "/SetPlainToken":   { resultCode: "SET01" },
  "/GetData":         { resultCode: "GET01", userID: "emulated-user" },
  "/GetEncryptToken": { resultCode: "GETENC01", userID: "emulated-user" },
  "/Logout":          { resultCode: "LOGOUT01" },
};

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

export function startSsoServer({ key, cert, port = 39091 }) {
  const server = https.createServer({ key, cert }, async (req, res) => {
    const body = await readBody(req);
    const resp = ENDPOINTS[req.url];
    console.log("[sso] %s %s body=%s → %s", req.method, req.url, body.slice(0, 80), resp ? JSON.stringify(resp) : "404");

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (!resp) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ resultCode: "UNKNOWN", resultMsg: "endpoint not emulated" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(resp));
  });
  server.listen(port, "127.0.0.1", () => {
    console.log(`sso-emulator listening on https://127.0.0.1:${port}`);
  });
  return server;
}
