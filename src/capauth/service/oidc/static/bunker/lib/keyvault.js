/**
 * CapAuth key-at-rest encryption (Web Crypto).
 *
 * Passphrase-derived AES-GCM envelope for the armored PGP private key, so the
 * key is NEVER stored in plaintext in chrome.storage.local. Used by the
 * `local-encrypted` signer backend.
 *
 * Envelope layout (the only thing ever persisted for the encrypted backend):
 *
 *   {
 *     v: 1,                       // envelope version
 *     kdf: "PBKDF2",
 *     hash: "SHA-256",
 *     iterations: 210000,         // OWASP 2023 floor for PBKDF2-HMAC-SHA256
 *     salt: "<base64>",           // 16 random bytes
 *     iv:   "<base64>",           // 12 random bytes (AES-GCM nonce)
 *     cipher: "AES-GCM",
 *     ciphertext: "<base64>"      // AES-GCM(armoredPrivateKey) incl. auth tag
 *   }
 *
 * The plaintext armored key is recovered only transiently in memory after a
 * correct passphrase decrypts the envelope; it is never written back to storage.
 *
 * Works in both the MV3 service worker (`crypto.subtle`) and Node's
 * `webcrypto` (tests) — we read SubtleCrypto off `globalThis.crypto`.
 *
 * @module keyvault
 */

const PBKDF2_ITERATIONS = 210_000; // OWASP 2023 minimum for PBKDF2-HMAC-SHA256
const PBKDF2_HASH = "SHA-256";
const SALT_BYTES = 16;
const IV_BYTES = 12; // AES-GCM standard nonce length
const AES_KEY_BITS = 256;
const ENVELOPE_VERSION = 1;

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Resolve the SubtleCrypto implementation (service worker or Node webcrypto). */
function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("Web Crypto (crypto.subtle) is unavailable in this context.");
  }
  return c.subtle;
}

function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** Uint8Array | ArrayBuffer -> base64 string (no chunking; keys are small). */
function toBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

/** base64 string -> Uint8Array. */
function fromBase64(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

/**
 * Derive an AES-GCM key from a passphrase via PBKDF2.
 *
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {string} hash
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(passphrase, salt, iterations, hash) {
  const baseKey = await subtle().importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return subtle().deriveKey(
    { name: "PBKDF2", salt, iterations, hash },
    baseKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt an armored private key into a passphrase-protected envelope.
 *
 * @param {string} armoredPrivateKey - The ASCII-armored PGP private key.
 * @param {string} passphrase - The user's encryption passphrase (required, non-empty).
 * @returns {Promise<Object>} The storable envelope (see module docs). Contains NO plaintext.
 */
export async function encryptPrivateKey(armoredPrivateKey, passphrase) {
  if (!armoredPrivateKey) {
    throw new Error("Cannot encrypt: no armored private key provided.");
  }
  if (!passphrase) {
    throw new Error("A non-empty passphrase is required to encrypt the key at rest.");
  }

  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS, PBKDF2_HASH);

  const ciphertext = await subtle().encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(armoredPrivateKey)
  );

  return {
    v: ENVELOPE_VERSION,
    kdf: "PBKDF2",
    hash: PBKDF2_HASH,
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt),
    iv: toBase64(iv),
    cipher: "AES-GCM",
    ciphertext: toBase64(ciphertext),
  };
}

/**
 * Decrypt an envelope back into the armored private key.
 *
 * @param {Object} envelope - An envelope produced by encryptPrivateKey().
 * @param {string} passphrase - The passphrase to derive the key from.
 * @returns {Promise<string>} The recovered ASCII-armored PGP private key.
 * @throws {Error} On a wrong passphrase (AES-GCM auth-tag failure) or malformed envelope.
 */
export async function decryptPrivateKey(envelope, passphrase) {
  if (!isEncryptedEnvelope(envelope)) {
    throw new Error("Not a valid CapAuth encrypted-key envelope.");
  }
  if (!passphrase) {
    throw new Error("A passphrase is required to decrypt the key.");
  }

  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const ciphertext = fromBase64(envelope.ciphertext);
  const iterations = envelope.iterations || PBKDF2_ITERATIONS;
  const hash = envelope.hash || PBKDF2_HASH;

  const key = await deriveKey(passphrase, salt, iterations, hash);

  let plaintextBuf;
  try {
    plaintextBuf = await subtle().decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  } catch {
    // AES-GCM authentication failed → wrong passphrase or tampered envelope.
    throw new Error("Incorrect passphrase or corrupted encrypted key.");
  }

  return dec.decode(plaintextBuf);
}

/**
 * Type guard: does this object look like an encrypted-key envelope?
 *
 * @param {*} obj
 * @returns {boolean}
 */
export function isEncryptedEnvelope(obj) {
  return !!(
    obj &&
    typeof obj === "object" &&
    obj.cipher === "AES-GCM" &&
    typeof obj.ciphertext === "string" &&
    typeof obj.salt === "string" &&
    typeof obj.iv === "string"
  );
}

export const KEYVAULT_PARAMS = Object.freeze({
  PBKDF2_ITERATIONS,
  PBKDF2_HASH,
  SALT_BYTES,
  IV_BYTES,
  AES_KEY_BITS,
  ENVELOPE_VERSION,
});
