/**
 * CapAuth Bunker — relay E2E-encryption (`capauth-bunker-e2e-v1`).
 *
 * Byte-compatible with:
 *   - phone-signer/lib/bunker-e2e.js          (identical copy)
 *   - src/capauth/service/bunker_e2e.py       (Python counterpart)
 *   - tests/fixtures/bunker_e2e_v1_vector.json (shared cross-impl vector)
 *
 * The bunker broker relays opaque messages desktop<->phone. This layer makes
 * the relayed `sign_request` payload + the returned signature unreadable to the
 * broker:
 *
 *   1. Each peer makes an EPHEMERAL X25519 keypair and sends its public key in a
 *      `kex` message. The broker forwards the pubkeys but can't compute the
 *      shared secret (X25519 hardness).
 *   2. shared = X25519(myPriv, peerPub)
 *   3. key = HKDF-SHA256(ikm=shared, salt=pairingSecret, info="capauth-bunker-e2e-v1", 32)
 *   4. Sensitive messages are AES-256-GCM sealed; wire ciphertext is
 *      base64(nonce[12] || ciphertext || tag) inside an `enc` envelope.
 *
 * Uses WebCrypto only (X25519 + HKDF + AES-GCM) — supported in modern Chrome
 * (133+) and current mobile browsers. No external crypto dependency.
 *
 * Threat model: defeats a PASSIVE / honest-but-curious broker (and broker
 * memory/log leakage + an untrusted intermediary relay). It does NOT defeat an
 * ACTIVE MITM by the broker itself (the broker knows the pairing secret and
 * relays the kex pubkeys); closing that needs a secret the broker never sees
 * (e.g. a key fragment carried only in the QR) — a documented follow-up.
 *
 * @module bunker-e2e
 */

const E2E_SCHEME = "capauth-bunker-e2e-v1";
const NONCE_LEN = 12; // AES-GCM standard nonce
const _subtle = () => globalThis.crypto.subtle;
const _enc = new TextEncoder();

/**
 * HKDF info. A non-empty `frag` (the QR-only key fragment — active-MITM
 * hardening, never seen by the broker) is mixed in so the broker cannot derive
 * the channel key even by substituting the relayed kex public keys.
 */
function infoBytes(frag) {
  return _enc.encode(frag ? `${E2E_SCHEME}\nfrag=${frag}` : E2E_SCHEME);
}

function b64encode(bytes) {
  let s = "";
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
function b64decode(str) {
  const bin = atob(str);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

/**
 * Generate an ephemeral X25519 keypair.
 * @returns {Promise<{privateKey: CryptoKey, publicKeyB64: string}>}
 *   publicKeyB64 is the base64 raw 32-byte public key (the `kex` wire value).
 */
export async function generateKexKeyPair() {
  const kp = await _subtle().generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const raw = await _subtle().exportKey("raw", kp.publicKey);
  return { privateKey: kp.privateKey, publicKeyB64: b64encode(raw) };
}

/**
 * HKDF-SHA256 a raw shared secret into a non-extractable AES-256-GCM key.
 * Split out so the cross-impl vector can pin the KDF+AEAD with a known secret.
 * @param {Uint8Array} sharedBytes
 * @param {string} pairingSecret
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKeyFromShared(sharedBytes, pairingSecret, frag = "") {
  const ikm = await _subtle().importKey("raw", sharedBytes, "HKDF", false, [
    "deriveKey",
  ]);
  return _subtle().deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: _enc.encode(pairingSecret),
      info: infoBytes(frag),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Derive the shared AES key from our private key + the peer's public key (b64).
 * @param {CryptoKey} privateKey
 * @param {string} peerPubB64
 * @param {string} pairingSecret
 * @returns {Promise<CryptoKey>}
 */
export async function deriveSharedKey(privateKey, peerPubB64, pairingSecret, frag = "") {
  const peerPub = await _subtle().importKey(
    "raw",
    b64decode(peerPubB64),
    { name: "X25519" },
    false,
    []
  );
  const sharedBits = await _subtle().deriveBits(
    { name: "X25519", public: peerPub },
    privateKey,
    256
  );
  return deriveKeyFromShared(new Uint8Array(sharedBits), pairingSecret, frag);
}

/**
 * AES-256-GCM seal a JS object → wire ciphertext base64(nonce||ct||tag).
 * @param {CryptoKey} aesKey
 * @param {Object} obj
 * @param {Uint8Array} [nonce] - injectable for the vector test; defaults random.
 * @returns {Promise<string>}
 */
export async function sealMessage(aesKey, obj, nonce) {
  const iv = nonce || globalThis.crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const pt = _enc.encode(JSON.stringify(obj));
  const ct = await _subtle().encrypt({ name: "AES-GCM", iv }, aesKey, pt);
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return b64encode(out);
}

/**
 * Inverse of {@link sealMessage} — decrypt wire ciphertext → JS object.
 * @param {CryptoKey} aesKey
 * @param {string} wireB64
 * @returns {Promise<Object>}
 */
export async function openMessage(aesKey, wireB64) {
  const blob = b64decode(wireB64);
  const iv = blob.slice(0, NONCE_LEN);
  const ct = blob.slice(NONCE_LEN);
  const pt = await _subtle().decrypt({ name: "AES-GCM", iv }, aesKey, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

/**
 * Stateful handshake helper used by both the desktop client and the phone
 * signer. Lifecycle: `start()` (send the returned kex) → `onKex(peerPub)` when
 * the peer's kex arrives (derives the key) → `seal()` / `open()`.
 */
export class E2ESession {
  constructor(pairingSecret, frag = "") {
    this.pairingSecret = pairingSecret || "";
    this.frag = frag || "";
    this._kp = null;
    this._key = null;
  }

  /** Generate our ephemeral keypair; returns the `kex` message to send. */
  async start() {
    this._kp = await generateKexKeyPair();
    return { type: "kex", pub: this._kp.publicKeyB64 };
  }

  /** Derive the shared key from the peer's kex public key. */
  async onKex(peerPubB64) {
    if (!this._kp) throw new Error("start() must run before onKex()");
    this._key = await deriveSharedKey(
      this._kp.privateKey,
      peerPubB64,
      this.pairingSecret,
      this.frag
    );
  }

  get isSecure() {
    return !!this._key;
  }

  /** Wrap an object in an `enc` envelope (id mirrored in cleartext). */
  async seal(obj) {
    if (!this._key) throw new Error("channel not secured (no peer kex yet)");
    const env = { type: "enc", ct: await sealMessage(this._key, obj) };
    if (obj && typeof obj === "object" && "id" in obj) env.id = obj.id;
    return env;
  }

  /** Decrypt an `enc` envelope → the inner message object. */
  async open(encMsg) {
    if (!this._key) throw new Error("channel not secured (no peer kex yet)");
    return openMessage(this._key, encMsg.ct);
  }
}

export const _E2E_SCHEME = E2E_SCHEME;
