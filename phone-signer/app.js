/**
 * CapAuth Bunker — phone-signer PWA controller (SPIKE).
 *
 * Wires the three steps:
 *   1. Import an armored PGP key → encrypt at rest (keyvault PBKDF2→AES-GCM) in
 *      localStorage. Unlock decrypts it into an in-memory session only.
 *   2. Pair: paste/scan the capauth-bunker:// URI, connect as role=signer.
 *   3. On each sign_request: show the approval modal (origin + fingerprint +
 *      exact bytes) and, if approved, sign with OpenPGP.js and return the sig.
 *
 * The private key is held in plaintext only transiently in `session.armoredKey`
 * after unlock; it is never sent anywhere. OpenPGP.js is loaded globally (UMD).
 */

import { encryptPrivateKey, decryptPrivateKey, isEncryptedEnvelope } from "./lib/keyvault.js";
import { startSigner } from "./lib/bunker-signer.js?v=3";
import { chunkPayload, parseKeyFrame, KeyFrameCollector } from "./lib/keyqr.js";

const openpgp = globalThis.openpgp;
const STORE_KEY = "capauth_bunker_envelope";
const FP_KEY = "capauth_bunker_fp";

const session = {
  armoredKey: null, // decrypted (from vault) armored key, in-memory only
  signingKey: null, // openpgp PrivateKey object, fully DECRYPTED + ready to sign
  fingerprint: "",
  signerHandle: null,
};

/**
 * Return an OpenPGP PrivateKey object that is fully DECRYPTED and ready to
 * sign. OpenPGP.js returns a *locked* key for passphrase-protected material;
 * `openpgp.sign` throws on a locked key — so we must decryptKey() first. We try
 * the no-passphrase case, then the vault passphrase (common: one passphrase for
 * both), then prompt for the PGP passphrase as a last resort.
 *
 * @param {string} armored - the recovered armored private key
 * @param {string} candidatePass - the vault passphrase (reused as a candidate)
 * @returns {Promise<Object>} decrypted PrivateKey, ready for openpgp.sign
 */
async function prepareSigningKey(armored, candidatePass) {
  const key = await openpgp.readPrivateKey({ armoredKey: armored });
  if (key.isDecrypted()) return key;
  const tries = ["", candidatePass].filter((v, i, a) => a.indexOf(v) === i);
  for (const p of tries) {
    try {
      return await openpgp.decryptKey({ privateKey: key, passphrase: p });
    } catch {
      /* try next candidate */
    }
  }
  // Last resort: the key has its own PGP passphrase distinct from the vault.
  const entered =
    typeof prompt === "function"
      ? prompt("This key has a PGP passphrase. Enter it to enable signing:")
      : "";
  if (entered) {
    try {
      return await openpgp.decryptKey({ privateKey: key, passphrase: entered });
    } catch {
      /* fall through to the error */
    }
  }
  throw new Error("PGP key passphrase required — could not unlock the key for signing");
}

// --- tiny DOM helpers -------------------------------------------------------
const $ = (id) => document.getElementById(id);
function setStatus(el, text, kind = "") {
  el.textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
}

// --- key import / encrypt-at-rest ------------------------------------------
async function fingerprintOf(armored) {
  const key = await openpgp.readKey({ armoredKey: armored });
  return key.getFingerprint().toUpperCase();
}

async function storeKey() {
  const armored = $("priv-key").value.trim();
  const vaultPass = $("vault-pass").value;
  const vaultConfirm = $("vault-pass-confirm").value;
  if (!armored) return setStatus($("key-status"), "Choose an armored private key file.", "err");
  if (!vaultPass) return setStatus($("key-status"), "Choose a browser vault passphrase.", "err");
  if (vaultPass !== vaultConfirm) {
    return setStatus($("key-status"), "The two browser vault passphrases do not match.", "err");
  }
  try {
    // Validate it's a real (private) key + capture fingerprint.
    const priv = await openpgp.readPrivateKey({ armoredKey: armored });
    const fp = priv.getFingerprint().toUpperCase();
    // If the key has its OWN (PGP) passphrase, strip it now — decrypt with the
    // PGP passphrase once and store the PASSPHRASELESS key inside the vault. The
    // vault passphrase (PBKDF2→AES-GCM) is then the only protection, so you
    // never have to type the long PGP passphrase again (just the vault one).
    let toStore = armored;
    if (!priv.isDecrypted()) {
      const pgpPass = $("pgp-pass").value;
      if (!pgpPass) {
        return setStatus($("key-status"),
          "This key has a PGP passphrase. Enter it in the 'Key passphrase (PGP)' box — I'll store the key under just your vault passphrase so you never need the long one again.", "err");
      }
      try {
        const dec = await openpgp.decryptKey({ privateKey: priv, passphrase: pgpPass });
        toStore = dec.armor();
      } catch (e) {
        return setStatus($("key-status"), "Wrong PGP key passphrase — couldn't unlock the key.", "err");
      }
    }
    const envelope = await encryptPrivateKey(toStore, vaultPass);
    localStorage.setItem(STORE_KEY, JSON.stringify(envelope));
    localStorage.setItem(FP_KEY, fp);
    $("priv-key").value = "";
    $("pgp-pass").value = "";
    $("vault-pass").value = "";
    $("vault-pass-confirm").value = "";
    setStatus($("key-status"), "Identity saved in this browser. Continue to passkey setup.", "ok");
    renderKeyState();
  } catch (err) {
    setStatus($("key-status"), "Could not read/store key: " + err.message, "err");
  }
}

async function unlockKey() {
  const raw = localStorage.getItem(STORE_KEY);
  const pass = $("unlock-pass").value;
  if (!raw) return setStatus($("key-status"), "No stored key.", "err");
  if (!pass) return setStatus($("key-status"), "Enter the vault passphrase.", "err");
  try {
    const envelope = JSON.parse(raw);
    if (!isEncryptedEnvelope(envelope)) throw new Error("corrupt envelope");
    session.armoredKey = await decryptPrivateKey(envelope, pass);
    session.fingerprint = await fingerprintOf(session.armoredKey);
    // Pre-decrypt the signing key NOW so a passphrase problem surfaces here,
    // not silently at approve-time. This is the bug that made the green button
    // appear to "do nothing": signing a locked key throws.
    session.signingKey = await prepareSigningKey(session.armoredKey, pass);
    $("unlock-pass").value = "";
    setStatus($("key-status"), "Unlocked + key ready to sign. Ready to pair.", "ok");
    setStatus($("pair-status"), "Ready — paste the desktop's Bunker URI.");
    $("btn-pair").disabled = false;
  } catch (err) {
    setStatus($("key-status"), "Unlock failed: " + err.message, "err");
  }
}

function forgetKey() {
  localStorage.removeItem(STORE_KEY);
  localStorage.removeItem(FP_KEY);
  session.armoredKey = null;
  session.signingKey = null;
  session.fingerprint = "";
  renderKeyState();
  setStatus($("key-status"), "Key forgotten.", "");
}

function renderKeyState() {
  const fp = localStorage.getItem(FP_KEY);
  if (fp) {
    $("key-import").classList.add("hidden");
    $("key-unlock").classList.remove("hidden");
    $("loaded-fp").textContent = fp;
    setStatus($("key-status"), session.armoredKey ? "Unlocked." : "Locked — unlock to sign.",
      session.armoredKey ? "ok" : "");
  } else {
    $("key-import").classList.remove("hidden");
    $("key-unlock").classList.add("hidden");
    setStatus($("key-status"), "Setup needed: choose your existing identity file.");
  }
}

async function loadKeyFile() {
  const file = $("key-file").files[0];
  if (!file) return;
  try {
    const armored = await file.text();
    if (!armored.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
      throw new Error("This is not an armored PGP private key file.");
    }
    $("priv-key").value = armored;
    setStatus($("key-status"), "Identity file loaded. Complete the two passphrase fields below.", "ok");
  } catch (err) {
    $("priv-key").value = "";
    setStatus($("key-status"), "Could not use that file: " + err.message, "err");
  }
}

// --- pairing + signer loop --------------------------------------------------
function parseBunkerUri(uri) {
  // capauth-bunker://<host>/<session>?key=<secret>&relay=<wss-url>
  const m = /^capauth-bunker:\/\/([^/]+)\/([^?]+)\?(.*)$/.exec(uri.trim());
  if (!m) throw new Error("not a capauth-bunker URI");
  const host = m[1];
  const sessionId = decodeURIComponent(m[2]);
  const params = new URLSearchParams(m[3]);
  const relay = params.get("relay") || `wss://${host}/bunker/ws`;
  return {
    host,
    sessionId,
    pairingSecret: params.get("key") || "",
    relay,
    // QR-only key fragment (active-MITM hardening). Present only when the
    // desktop rendered a frag-augmented URI; absent → plain E2E (passive-broker
    // safe, no active-MITM resistance).
    frag: params.get("f") || "",
  };
}

function connect() {
  if (!session.armoredKey) {
    return setStatus($("pair-status"), "Unlock a key first.", "err");
  }
  let parsed;
  try {
    parsed = parseBunkerUri($("bunker-uri").value);
  } catch (err) {
    return setStatus($("pair-status"), err.message, "err");
  }
  setStatus($("pair-status"), "Connecting to broker…");

  session.signerHandle = startSigner({
    relayWsUrl: parsed.relay,
    sessionId: parsed.sessionId,
    pairingSecret: parsed.pairingSecret,
    frag: parsed.frag,
    getFingerprint: () => session.fingerprint,
    requestApproval: showApproval,
    sign: async (canonicalPayload) => {
      // Use the key decrypted at unlock; fall back to (re)preparing it.
      const privateKey =
        session.signingKey ||
        (session.signingKey = await prepareSigningKey(session.armoredKey, ""));
      const signature = await openpgp.sign({
        message: await openpgp.createMessage({ text: canonicalPayload }),
        signingKeys: privateKey,
        detached: true,
      });
      return signature;
    },
    onStatus: (s) => {
      const map = {
        connected: ["Connected. Waiting to pair…", ""],
        paired: ["Paired with desktop. Securing channel…", "ok"],
        secured: ["🔒 Encrypted channel ready. Awaiting sign requests…", "ok"],
        signed: ["Signed + returned to desktop.", "ok"],
        rejected: ["You rejected the request.", ""],
        peer_left: ["Desktop disconnected.", "err"],
        closed: ["Connection closed.", ""],
        error: ["Relay error.", "err"],
      };
      let e = map[s];
      if (!e) {
        if (s.startsWith("error:")) e = ["Broker: " + s.slice(6), "err"];
        else if (s.startsWith("sign_error"))
          e = ["Signing failed: " + s.slice(s.indexOf(":") + 1).trim(), "err"];
        // Surface ANYTHING else rather than silently dropping it — a swallowed
        // status is what made signing failures look like "nothing happened".
        else e = [s, "err"];
      }
      setStatus($("pair-status"), e[0], e[1]);
    },
  });
}

// --- approval modal (phishing-resistant: shows the origin + bytes) ----------
function showApproval(req) {
  return new Promise((resolve) => {
    $("ap-origin").textContent = req.origin || "(no origin — INSECURE)";
    $("ap-fp").textContent = session.fingerprint;
    $("ap-payload").textContent = req.payload;
    const warn = [];
    if (!req.origin) warn.push("⚠ No origin bound — cannot verify the website.");
    if (req.version !== "CAPAUTH_NONCE_V2") warn.push("⚠ Legacy payload (" + req.version + ").");
    if (req.fingerprint && req.fingerprint.toUpperCase() !== session.fingerprint) {
      warn.push("⚠ Desktop expected a different fingerprint.");
    }
    $("ap-warn").textContent = warn.join("  ");
    $("approve-modal").classList.remove("hidden");

    const close = (val) => {
      $("approve-modal").classList.add("hidden");
      $("btn-approve").onclick = null;
      $("btn-reject").onclick = null;
      resolve(val);
    };
    $("btn-approve").onclick = () => close(true);
    $("btn-reject").onclick = () => close(false);
  });
}

// --- Key transfer via QR: show this device's key as an (animated) QR ---------
let _qrTimer = null;

async function showKeyQR() {
  const armored = $("priv-key").value.trim();
  const pin = $("xfer-pin").value;
  const st = $("qr-status");
  if (!armored) return setStatus(st, "Paste your armored key above first.", "err");
  try {
    await openpgp.readPrivateKey({ armoredKey: armored }); // validate
  } catch {
    return setStatus(st, "That doesn't look like a private key.", "err");
  }
  let payload, warn;
  if (pin) {
    payload = JSON.stringify(await encryptPrivateKey(armored, pin));
    warn = "🔒 PIN-encrypted. The other device asks for this PIN after scanning.";
  } else {
    if (!confirm("Show your UNENCRYPTED private key as a QR? Anyone who photographs it gets your key. Set a Transfer PIN to protect it.")) {
      return;
    }
    payload = armored;
    warn = "⚠ UNENCRYPTED private key — only show this to your own device's camera.";
  }
  const frames = chunkPayload(payload);
  $("qr-warn").textContent = warn;
  $("qr-box").classList.remove("hidden");
  if (!("qrcode" in globalThis)) return setStatus(st, "QR generator unavailable.", "err");
  let i = 0;
  const render = () => {
    const qr = globalThis.qrcode(0, "M");
    qr.addData(frames[i]);
    qr.make();
    $("qr-img").src = qr.createDataURL(6, 8);
    setStatus(
      st,
      frames.length > 1 ? `Frame ${i + 1}/${frames.length} — keep the other camera pointed here.` : "Scan this with your other device.",
      ""
    );
    i = (i + 1) % frames.length;
  };
  render();
  if (_qrTimer) clearInterval(_qrTimer);
  if (frames.length > 1) _qrTimer = setInterval(render, 350); // ~3 fps cycle
}

function hideKeyQR() {
  if (_qrTimer) {
    clearInterval(_qrTimer);
    _qrTimer = null;
  }
  $("qr-box").classList.add("hidden");
  $("qr-img").src = "";
  $("xfer-pin").value = "";
}

// --- Camera QR scan (scan the pairing QR instead of pasting) -----------------
let _scanStream = null;
let _scanRAF = null;
let _keyCollector = null;

// Handle a fully-reassembled key payload scanned from another device.
async function handleScannedKey(payload) {
  const ps = $("pair-status");
  let armored = payload;
  if (!payload.startsWith("-----BEGIN PGP")) {
    // PIN-encrypted envelope — ask for the transfer PIN and decrypt.
    let env;
    try {
      env = JSON.parse(payload);
    } catch {
      return setStatus(ps, "Scanned data wasn't a key.", "err");
    }
    if (!isEncryptedEnvelope(env)) return setStatus(ps, "Scanned data wasn't a key.", "err");
    const pin = typeof prompt === "function" ? prompt("Enter the Transfer PIN shown on the other device:") : "";
    if (!pin) return setStatus(ps, "Transfer PIN required to decrypt the scanned key.", "err");
    try {
      armored = await decryptPrivateKey(env, pin);
    } catch {
      return setStatus(ps, "Wrong Transfer PIN — could not decrypt the key.", "err");
    }
  }
  $("priv-key").value = armored;
  $("key-import").scrollIntoView({ behavior: "smooth", block: "center" });
  setStatus($("key-status"), "✅ Key received via QR — set a vault passphrase and tap Encrypt & store.", "ok");
  setStatus(ps, "Key received from the other device.", "ok");
}

async function startScan() {
  const ps = $("pair-status");
  if (!("BarcodeDetector" in window)) {
    return setStatus(ps, "Camera scanning isn't supported on this browser — paste the URI instead.", "err");
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    return setStatus(ps, "No camera access here — paste the URI instead.", "err");
  }
  try {
    _scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
    });
    const video = $("scan-video");
    video.srcObject = _scanStream;
    await video.play();
    $("scan-box").classList.remove("hidden");
    setStatus(ps, "Point the camera at a Bunker QR or a key-transfer QR…");
    _keyCollector = new KeyFrameCollector();
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const tick = async () => {
      if (!_scanStream) return;
      try {
        const codes = await detector.detect(video);
        for (const c of codes) {
          const v = c.rawValue;
          if (!v) continue;
          if (v.startsWith("capauth-bunker://")) {
            $("bunker-uri").value = v;
            stopScan();
            setStatus(
              ps,
              session.armoredKey ? "Scanned ✓ — tap Connect." : "Scanned ✓ — unlock a key, then Connect.",
              "ok"
            );
            return;
          }
          const frame = parseKeyFrame(v);
          if (frame && _keyCollector.add(frame)) {
            setStatus(ps, `Receiving key… ${_keyCollector.received}/${_keyCollector.total} frames`);
            if (_keyCollector.complete) {
              const payload = _keyCollector.assemble();
              stopScan();
              await handleScannedKey(payload);
              return;
            }
          }
        }
      } catch {
        /* transient detect error — keep scanning */
      }
      _scanRAF = requestAnimationFrame(tick);
    };
    tick();
  } catch (err) {
    setStatus(ps, "Camera error: " + err.message, "err");
    stopScan();
  }
}

function stopScan() {
  if (_scanRAF) {
    cancelAnimationFrame(_scanRAF);
    _scanRAF = null;
  }
  if (_scanStream) {
    _scanStream.getTracks().forEach((t) => t.stop());
    _scanStream = null;
  }
  $("scan-box").classList.add("hidden");
}

// --- Web Push: background approvals -----------------------------------------
function urlBase64ToUint8Array(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const base = (b64 + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function enablePush() {
  const fp = localStorage.getItem(FP_KEY);
  const st = $("push-status");
  if (!fp) return setStatus(st, "Load a key first.", "err");
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    return setStatus(st, "Push isn't supported on this browser.", "err");
  }
  try {
    const perm = await Notification.requestPermission();
    if (perm !== "granted") return setStatus(st, "Notifications were denied.", "err");
    const reg = await navigator.serviceWorker.ready;
    const { publicKey } = await (await fetch("vapid")).json();
    if (!publicKey) throw new Error("server has no VAPID key");
    const sub =
      (await reg.pushManager.getSubscription()) ||
      (await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey),
      }));
    const res = await fetch("subscribe", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fingerprint: fp, subscription: sub.toJSON() }),
    });
    if (!res.ok) throw new Error("server rejected subscription (" + res.status + ")");
    setStatus(st, "🔔 Background approvals enabled for " + fp.slice(0, 8) + "…", "ok");
  } catch (err) {
    setStatus(st, "Push setup failed: " + err.message, "err");
  }
}

// --- wire up ----------------------------------------------------------------
$("btn-store").onclick = storeKey;
$("key-file").onchange = loadKeyFile;
$("btn-unlock").onclick = unlockKey;
$("btn-forget").onclick = forgetKey;
$("btn-pair").onclick = connect;
$("btn-push").onclick = enablePush;
$("btn-scan").onclick = startScan;
$("btn-scan-stop").onclick = stopScan;
$("btn-show-qr").onclick = showKeyQR;
$("btn-hide-qr").onclick = hideKeyQR;

// Allow opening with the URI pre-filled: /bunker/?uri=... or #capauth-bunker://
const fromQuery = new URLSearchParams(location.search).get("uri");
const setupMode = new URLSearchParams(location.search).get("mode") === "setup";
const requestedNext = new URLSearchParams(location.search).get("next") || "";
const safeNext = requestedNext.startsWith("/") && !requestedNext.startsWith("//")
  ? requestedNext
  : "/oidc/passkey/enroll";
$("continue-passkey").href = safeNext;
if (setupMode) {
  $("page-title").textContent = "Set up this browser";
  $("page-subtitle").textContent = "Load your existing identity once, then create your passkey.";
  $("pair-card").classList.add("hidden");
}
const fromHash = location.hash.startsWith("#capauth-bunker")
  ? location.hash.slice(1)
  : "";
if (fromQuery || fromHash) $("bunker-uri").value = fromQuery || fromHash;

renderKeyState();

// PWA service worker. The ?v= bump changes the script URL so the browser drops
// any previously-installed (cache-first) worker and installs the network-first
// one — without this an old SW keeps serving stale cached code forever.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js?v=3").catch(() => {});
}
