/**
 * SignatureVerificationStage — client-side signature pre-verification.
 *
 * After the background service worker produces a PGP signature over the
 * canonical nonce payload, this stage:
 *
 *   1. Retrieves the public key from settings (if available)
 *   2. Verifies the signature locally using the OpenPGP.js bundle
 *   3. Renders a verification result card showing pass/fail
 *   4. Sets context.localVerified = true/false
 *
 * The stage is informational — a local verification failure does NOT abort
 * the pipeline (the server-side verification is authoritative). It does
 * surface a warning so the user knows something may be wrong before the
 * request is submitted.
 *
 * Only runs when context.authMethod === 'pgp-key' and context.signature
 * is present (populated by PGPSignStage or INITIATE_AUTH flow).
 *
 * @module stages/SignatureVerificationStage
 */

import { CapAuthStage } from "./CapAuthStage.js";

// We import the openpgp bundle the same way background.js does.
// In the popup context this resolves to lib/openpgp-bundle.js.
let _openpgp = null;

async function getOpenPGP() {
  if (_openpgp) return _openpgp;
  try {
    _openpgp = await import("../lib/openpgp-bundle.js");
  } catch {
    _openpgp = null;
  }
  return _openpgp;
}

export class SignatureVerificationStage extends CapAuthStage {
  constructor() {
    super();
    this._verified = false;
    this._warning = "";
  }

  get name() {
    return "Verify Signature";
  }

  canHandle(context) {
    // Only relevant for PGP key auth with a signature to check
    return context.authMethod === "pgp-key" && !!context.signature;
  }

  async execute(context) {
    const { signature, challenge, publicKeyArmored } = context;

    // Pre-render loading state
    this._setStatus("verifying");

    if (!publicKeyArmored) {
      // No public key available — skip verification with a soft warning
      this._setStatus("skipped");
      return { ...context, localVerified: null, verificationSkipped: true };
    }

    try {
      const openpgp = await getOpenPGP();
      if (!openpgp) throw new Error("OpenPGP library not available");

      const canonicalPayload = this._buildCanonicalPayload(challenge);

      // Verify the signature using OpenPGP.js
      const message = await openpgp.createMessage({ text: canonicalPayload });
      const sig = await openpgp.readSignature({ armoredSignature: signature });
      const pubKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

      const result = await openpgp.verify({
        message,
        signature: sig,
        verificationKeys: pubKey,
      });

      const { verified } = result.signatures[0];
      await verified; // throws if invalid

      this._verified = true;
      this._setStatus("valid");
      return { ...context, localVerified: true };
    } catch (err) {
      this._verified = false;
      this._warning = err.message;
      this._setStatus("invalid", err.message);
      // Non-fatal: let the pipeline continue
      return { ...context, localVerified: false, verificationWarning: err.message };
    }
  }

  render(container, context) {
    const wrapper = this._makeWrapper(
      "Verifying Signature",
      "Checking your PGP signature locally before submitting to the service."
    );
    wrapper.id = "verify-stage-wrapper";

    const card = document.createElement("div");
    card.className = "stage-verify-card";
    card.id = "verify-stage-card";

    // Loading state initially
    card.innerHTML = `
      <div class="stage-spinner stage-spinner--small" id="verify-spinner"></div>
      <div class="stage-verify-text" id="verify-text">Verifying…</div>
    `;

    wrapper.appendChild(card);

    // Fingerprint display
    if (context.fingerprint) {
      const fp = document.createElement("div");
      fp.className = "stage-verify-fp";
      fp.innerHTML = `<span class="stage-verify-fp-label">Key</span>
        <code class="stage-verify-fp-value">${this._formatFP(context.fingerprint)}</code>`;
      wrapper.appendChild(fp);
    }

    container.appendChild(wrapper);
  }

  // ---------------------------------------------------------------------------

  _setStatus(state, detail = "") {
    const card = document.getElementById("verify-stage-card");
    if (!card) return;

    const icons = {
      verifying: `<div class="stage-spinner stage-spinner--small"></div>`,
      valid: `<span class="stage-verify-icon stage-verify-icon--ok">✓</span>`,
      invalid: `<span class="stage-verify-icon stage-verify-icon--warn">⚠</span>`,
      skipped: `<span class="stage-verify-icon stage-verify-icon--skip">—</span>`,
    };

    const labels = {
      verifying: "Verifying signature…",
      valid: "Signature valid",
      invalid: `Signature check failed — proceeding to server verify`,
      skipped: "No public key — skipping local verify",
    };

    card.className = `stage-verify-card stage-verify-card--${state}`;
    card.innerHTML = `
      ${icons[state] || ""}
      <div class="stage-verify-text">${labels[state] || state}</div>
      ${detail ? `<div class="stage-verify-detail">${detail}</div>` : ""}
    `;
  }

  _buildCanonicalPayload(challenge) {
    if (!challenge) return "";
    // Matches CapAuthClient.buildCanonicalNoncePayload in openpgp-bundle.js
    const lines = [
      `capauth:nonce:${challenge.nonce}`,
      `client_nonce:${challenge.client_nonce_echo}`,
      `timestamp:${challenge.timestamp}`,
      `service:${challenge.service}`,
      `expires:${challenge.expires}`,
    ];
    return lines.join("\n");
  }

  _formatFP(fp) {
    return fp.toUpperCase().replace(/(.{4})/g, "$1 ").trim().slice(0, 24) + "…";
  }
}
