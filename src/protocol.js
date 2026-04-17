import forge from "node-forge";
import { signDn } from "./signer.js";
import { listConfiguredCerts } from "./certInfo.js";

export const API = {
  CHECK_INSTALL: 0,
  INTEGRITY_INIT: 1,
  HANDSHAKE: 2,
  AGENT_CHECK: 8,
  CERT_LIST: 10,
  CERT_GENERATE_SIGNDATA: 21,
};

const VERSION = "1.3.28";
// Windows agent returns a bare "2.5.1.1"; client UI prepends "v" when rendering.
const KCMVP_VERSION = "2.5.1.1";

// Decode envelope "1data=<json>" → { SessionId, Data, Method }.
export function parseEnvelope(frame) {
  if (!frame.startsWith("1data=")) {
    throw new Error(`unexpected frame prefix: ${frame.slice(0, 8)}`);
  }
  const env = JSON.parse(frame.slice("1data=".length));
  return env;
}

// Given an envelope and the current session, decode the inner sendObj and dispatch.
// Returns a JSON-serializable response object (which the server will wrap per-protocol).
export async function handleEnvelope(env, session) {
  const dataBytes = forge.util.decode64(env.Data || "");

  let inner;
  let secureRequest = false;

  if (!session.secure) {
    // plaintext: CHECK_INSTALL (Method="install") has no keyId prefix;
    // every other call carries a 16-byte sessionKeyId prefix (min.js 1377, 4949).
    const prefixLen = env.Method === "install" ? 0 : 16;
    if (prefixLen > 0) {
      if (dataBytes.length < prefixLen) throw new Error("Data shorter than keyId prefix");
      session.sessionKeyId = dataBytes.substring(0, prefixLen);
    }
    inner = JSON.parse(dataBytes.substring(prefixLen));
  } else {
    // secure: keyId(16B) || SEED-CBC(sessionKey, sessionIv, base64(nonce8) + base64(JSON))
    const keyIdLen = session.sessionKeyId?.length ?? 16;
    const cipher = dataBytes.substring(keyIdLen);
    const decrypted = session.seedDecrypt(cipher);
    // decrypted = 12-char base64 nonce (base64 of 8 random bytes) + base64(JSON)
    const b64Json = decrypted.substring(12);
    const jsonStr = forge.util.decode64(b64Json);
    inner = JSON.parse(jsonStr);
    secureRequest = true;
  }

  if (process.env.HIRA_DEBUG) {
    console.log("[proto] req APIName=%s secure=%s keyId=%s",
      inner.APIName, secureRequest,
      forge.util.bytesToHex(session.sessionKeyId || "").slice(0, 32));
    console.log("[proto]   inner =", JSON.stringify(inner).slice(0, 400));
  }

  const resp = await dispatch(inner, env, session);

  if (secureRequest) {
    const outCipher = session.seedEncrypt(JSON.stringify(resp));
    return { Output: forge.util.encode64(outCipher) };
  }
  return resp;
}

async function dispatch(inner, env, session) {
  switch (inner.APIName) {
    case API.CHECK_INSTALL:
      return { Status: 0, Version: VERSION };

    case API.INTEGRITY_INIT: {
      // Capture the JSP session id (client sent it base64-encoded in envelope).
      const sidBytes = forge.util.decode64(env.SessionId || "");
      session.sessionId = env.SessionId;
      // We pick an arbitrary Hash, then sign sha256(Hash_str) per min.js 1697-1702.
      const hashBytes = forge.random.getBytesSync(128);
      const hashB64 = forge.util.encode64(hashBytes);
      const intMsg = session.signIntMsg(hashB64);
      return {
        Status: 0,
        Version: VERSION,
        SessionId: session.sessionId,
        PubKey: session.getPubKeyBase64Spki(),
        IntMsg: intMsg,
        Hash: hashB64,
        KcmvpVersion: KCMVP_VERSION,
      };
    }

    case API.HANDSHAKE: {
      session.ingestEncryptedKey(inner.EncryptedKey);
      return {
        Status: 0,
        SessionId: session.sessionId,
        HandshakeMsg: session.getHandshakeMsgBase64(),
      };
    }

    case API.AGENT_CHECK:
      return { Status: 0 };

    case API.CERT_LIST: {
      // Schema from min.js 6817: CertList[i] = base64(utf8(JSON.stringify(certObj))),
      // CertStatus[i] = integer status (0 = valid, -1 = invalid/expired).
      const entries = listConfiguredCerts();
      return {
        Status: 0,
        CertList: entries.map(({ certObj }) =>
          forge.util.encode64(forge.util.encodeUtf8(JSON.stringify(certObj)))
        ),
        CertStatus: entries.map(({ status }) => status),
      };
    }

    case API.CERT_GENERATE_SIGNDATA: {
      const dn = forge.util.decodeUtf8(forge.util.decode64(inner.CertDn || ""));
      const input = inner.Input || "";
      // Password envelope from min.js 8110ish: {"IsSec":0,"Data":"<plaintext>"} when no
      // client-side transit encryption is enabled. IsSec=1 would wrap Data in an
      // agent-side transport cipher which we haven't observed yet.
      let rawPw = inner.Password || "";
      try {
        const wrapper = JSON.parse(rawPw);
        if (wrapper && typeof wrapper === "object" && "Data" in wrapper) {
          if (wrapper.IsSec && wrapper.IsSec !== 0) {
            throw new Error(`Password wrapper IsSec=${wrapper.IsSec} not supported`);
          }
          rawPw = wrapper.Data;
        }
      } catch (e) {
        if (e.message.startsWith("Password wrapper")) throw e;
        // not JSON → assume already plaintext (defensive)
      }
      const cms = await signDn({ dn, inputB64: input, password: rawPw });
      return { Status: 0, Output: cms };
    }

    default:
      console.warn("unhandled APIName", inner.APIName, inner);
      return { Status: -1 };
  }
}
