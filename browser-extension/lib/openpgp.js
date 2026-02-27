/**
 * OpenPGP.js integration — real PGP crypto operations for CapAuth.
 *
 * Wraps openpgp.js v5 for signing challenges and verifying server
 * signatures inside the browser extension. Keys never leave this module.
 *
 * @module openpgp-integration
 */

import * as openpgp from "openpgp";

/**
 * Generate a cryptographically random nonce for the challenge-response flow.
 *
 * @param {number} [byteLength=16] - Number of random bytes.
 * @returns {string} Base64-encoded random nonce.
 */
export function generateNonce(byteLength = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Build the canonical nonce payload that both client and server sign.
 *
 * Must match the server-side `canonical_nonce_payload()` in
 * capauth/src/capauth/authentik/verifier.py exactly.
 *
 * @param {Object} params
 * @param {string} params.nonce - Server-issued nonce UUID.
 * @param {string} params.clientNonce - Base64 client nonce echo.
 * @param {string} params.timestamp - ISO 8601 UTC timestamp.
 * @param {string} params.service - Service identifier.
 * @param {string} params.expires - ISO 8601 UTC expiry.
 * @returns {string} Canonical payload string.
 */
export function buildCanonicalNoncePayload({ nonce, clientNonce, timestamp, service, expires }) {
  return [
    "CAPAUTH_NONCE_V1",
    `nonce=${nonce}`,
    `client_nonce=${clientNonce}`,
    `timestamp=${timestamp}`,
    `service=${service}`,
    `expires=${expires}`,
  ].join("\n");
}

/**
 * Build the canonical claims payload that the client signs.
 *
 * Must match the server-side `canonical_claims_payload()` in
 * capauth/src/capauth/authentik/verifier.py exactly.
 *
 * @param {Object} params
 * @param {string} params.fingerprint - Client's PGP fingerprint.
 * @param {string} params.nonce - Nonce UUID binding claims to this auth event.
 * @param {Object} params.claims - Profile claims dict.
 * @returns {string} Canonical payload string.
 */
export function buildCanonicalClaimsPayload({ fingerprint, nonce, claims }) {
  // Sorted keys, no whitespace — matches Python's json.dumps(sort_keys=True, separators=(",",":"))
  const sortedKeys = Object.keys(claims).sort();
  const sortedObj = {};
  for (const k of sortedKeys) {
    sortedObj[k] = claims[k];
  }
  const claimsCompact = JSON.stringify(sortedObj);
  return [
    "CAPAUTH_CLAIMS_V1",
    `fingerprint=${fingerprint}`,
    `nonce=${nonce}`,
    `claims=${claimsCompact}`,
  ].join("\n");
}

/**
 * Sign a message with a PGP private key.
 *
 * Produces an ASCII-armored detached signature compatible with the
 * CapAuth server's verification flow.
 *
 * @param {string} message - The plaintext message to sign.
 * @param {string} privateKeyArmored - ASCII-armored PGP private key.
 * @param {string} [passphrase=''] - Passphrase to unlock the private key.
 * @returns {Promise<string>} ASCII-armored PGP detached signature.
 */
export async function signMessage(message, privateKeyArmored, passphrase = "") {
  let privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

  if (!privateKey.isDecrypted()) {
    privateKey = await openpgp.decryptKey({ privateKey, passphrase });
  }

  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ text: message }),
    signingKeys: privateKey,
    detached: true,
  });

  return signature;
}

/**
 * Verify a PGP signature against a public key.
 *
 * @param {string} message - The original plaintext message.
 * @param {string} signatureArmored - ASCII-armored PGP detached signature.
 * @param {string} publicKeyArmored - ASCII-armored PGP public key.
 * @returns {Promise<boolean>} True if signature is valid.
 * @throws {Error} If the signature is invalid or verification fails.
 */
export async function verifySignature(message, signatureArmored, publicKeyArmored) {
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const signature = await openpgp.readSignature({ armoredSignature: signatureArmored });

  const verificationResult = await openpgp.verify({
    message: await openpgp.createMessage({ text: message }),
    signature,
    verificationKeys: publicKey,
  });

  const { verified } = verificationResult.signatures[0];
  await verified; // throws on invalid signature
  return true;
}

/**
 * Extract a fingerprint from an ASCII-armored PGP public key.
 *
 * @param {string} publicKeyArmored - ASCII-armored PGP public key.
 * @returns {Promise<string>} 40-character uppercase hex fingerprint.
 */
export async function extractFingerprint(publicKeyArmored) {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  return key.getFingerprint().toUpperCase();
}
