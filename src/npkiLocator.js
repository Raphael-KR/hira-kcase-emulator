// Discover 공동인증서 pairs on this machine.
// macOS layout: ~/Library/Preferences/NPKI/<CA>/USER/<subjectDN>/{signCert.der, signPri.key}
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function npkiRoots() {
  return [
    path.join(os.homedir(), "Library", "Preferences", "NPKI"),
    path.join(os.homedir(), "AppData", "LocalLow", "NPKI"), // Windows fallback if ever ported
  ];
}

// Returns [{ certPath, keyPath }]. Explicit env overrides the scan.
export function findSignCertPairs() {
  const explicit = process.env.HIRA_SIGN_CERT;
  if (explicit && fs.existsSync(explicit)) {
    const dir = path.dirname(explicit);
    const keyPath = process.env.HIRA_SIGN_KEY || path.join(dir, "signPri.key");
    return [{ certPath: explicit, keyPath }];
  }

  const out = [];
  for (const root of npkiRoots()) {
    if (!fs.existsSync(root)) continue;
    for (const ca of safeReaddir(root)) {
      const userDir = path.join(root, ca, "USER");
      if (!fs.existsSync(userDir)) continue;
      for (const subj of safeReaddir(userDir)) {
        const certPath = path.join(userDir, subj, "signCert.der");
        const keyPath = path.join(userDir, subj, "signPri.key");
        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
          out.push({ certPath, keyPath });
        }
      }
    }
  }
  return out;
}

function safeReaddir(p) {
  try {
    return fs.readdirSync(p);
  } catch {
    return [];
  }
}
