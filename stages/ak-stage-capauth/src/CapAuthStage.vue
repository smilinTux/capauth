<template>
  <div class="capauth-stage">
    <!-- Header -->
    <div class="capauth-header">
      <svg class="capauth-shield" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
              stroke="currentColor" stroke-width="2" fill="none"/>
        <path d="M10 12l2 2 4-4" stroke="currentColor" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <h2>Sovereign Login</h2>
      <p class="capauth-subtitle">Sign in with your PGP key — no password needed</p>
    </div>

    <!-- Error banner -->
    <div v-if="error" class="capauth-error" role="alert">
      {{ error }}
    </div>

    <!-- Challenge display (while signing) -->
    <div v-if="phase === 'signing'" class="capauth-challenge">
      <div class="capauth-spinner" aria-hidden="true"></div>
      <p>Waiting for PGP signature from browser extension…</p>
      <p class="capauth-hint">Click the <strong>CapAuth</strong> extension icon and sign in.</p>
    </div>

    <!-- Success -->
    <div v-else-if="phase === 'success'" class="capauth-success">
      <svg viewBox="0 0 24 24" fill="none" class="capauth-check">
        <circle cx="12" cy="12" r="10" stroke="#10b981" stroke-width="2"/>
        <path d="M8 12l3 3 5-5" stroke="#10b981" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>Authentication successful — redirecting…</p>
    </div>

    <!-- Initial / fingerprint entry -->
    <div v-else class="capauth-form">
      <label for="capauth-fingerprint">PGP Fingerprint</label>
      <input
        id="capauth-fingerprint"
        v-model="fingerprint"
        type="text"
        placeholder="40-character PGP fingerprint"
        maxlength="40"
        autocomplete="off"
        spellcheck="false"
        :disabled="phase === 'fetching'"
        @input="normalizeFingerprint"
        @keydown.enter="startAuth"
      />
      <p class="capauth-hint">
        Your fingerprint is shown in your key manager (e.g. <code>gpg --fingerprint</code>).
      </p>

      <button
        class="capauth-btn"
        :disabled="!canSubmit || phase === 'fetching'"
        @click="startAuth"
      >
        <span v-if="phase === 'fetching'" class="capauth-spinner-sm"></span>
        <span v-else>Sign in with CapAuth</span>
      </button>

      <div class="capauth-divider">
        <span>or</span>
      </div>

      <button class="capauth-btn-secondary" @click="openQRLogin">
        QR Code Login (mobile)
      </button>
    </div>

    <p class="capauth-footer">
      Don't have the extension?
      <a :href="extensionInstallUrl" target="_blank" rel="noopener">Install CapAuth</a>
    </p>
  </div>
</template>

<script setup>
import { ref, computed } from "vue";

// ---------------------------------------------------------------------------
// Props — passed by Authentik's stage loader
// ---------------------------------------------------------------------------

const props = defineProps({
  /** The CapAuth service base URL (e.g. "https://auth.skworld.io") */
  serviceUrl: {
    type: String,
    default: "",
  },
  /** URL to redirect to after successful authentication */
  nextUrl: {
    type: String,
    default: "",
  },
  /** Chrome / Firefox extension install URLs */
  extensionInstallUrl: {
    type: String,
    default: "https://chromewebstore.google.com/detail/capauth",
  },
});

const emit = defineEmits(["authenticated", "error"]);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const fingerprint = ref("");
const phase = ref("idle"); // idle | fetching | signing | success | error
const error = ref("");

const canSubmit = computed(() => fingerprint.value.replace(/\s/g, "").length === 40);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeFingerprint() {
  // Strip whitespace and force uppercase
  fingerprint.value = fingerprint.value.replace(/\s/g, "").toUpperCase();
}

function resolvedServiceUrl() {
  return (props.serviceUrl || window.location.origin).replace(/\/$/, "");
}

// ---------------------------------------------------------------------------
// Auth flow
// ---------------------------------------------------------------------------

/**
 * Start the CapAuth challenge-response flow:
 *   1. POST /capauth/v1/challenge → get nonce
 *   2. Tell the browser extension to sign it (via postMessage)
 *   3. Extension posts back the signature
 *   4. POST /capauth/v1/verify → get JWT
 *   5. Submit JWT to Authentik stage endpoint
 */
async function startAuth() {
  if (!canSubmit.value) return;

  error.value = "";
  phase.value = "fetching";

  const fp = fingerprint.value.replace(/\s/g, "").toUpperCase();
  const serviceUrl = resolvedServiceUrl();

  try {
    // Step 1: Fetch challenge nonce
    const clientNonce = generateClientNonce();
    const challengeResp = await fetch(`${serviceUrl}/capauth/v1/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capauth_version: "1.0",
        fingerprint: fp,
        client_nonce: clientNonce,
        requested_service: new URL(serviceUrl).hostname,
      }),
    });

    if (!challengeResp.ok) {
      const data = await challengeResp.json().catch(() => ({}));
      throw new Error(data.error_description || data.error || `Challenge failed (${challengeResp.status})`);
    }

    const challenge = await challengeResp.json();
    if (challenge.client_nonce_echo !== clientNonce) {
      throw new Error("Server nonce echo mismatch — possible MITM. Aborting.");
    }

    // Step 2: Ask browser extension to sign the challenge
    phase.value = "signing";

    const signature = await requestExtensionSignature(challenge);

    // Step 3: Verify the signature server-side
    const verifyResp = await fetch(`${serviceUrl}/capauth/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capauth_version: "1.0",
        fingerprint: fp,
        nonce: challenge.nonce,
        nonce_signature: signature,
        claims: {},
        claims_signature: "",
        public_key: "",
      }),
    });

    if (!verifyResp.ok) {
      const data = await verifyResp.json().catch(() => ({}));
      throw new Error(data.error || "Signature verification failed");
    }

    const verifyData = await verifyResp.json();

    phase.value = "success";

    // Step 4: Tell Authentik the stage completed
    emit("authenticated", {
      fingerprint: fp,
      access_token: verifyData.access_token,
      oidc_claims: verifyData.oidc_claims || {},
    });

    // Submit to Authentik if nextUrl is set
    if (props.nextUrl) {
      setTimeout(() => {
        window.location.href = props.nextUrl;
      }, 800);
    }
  } catch (err) {
    phase.value = "idle";
    error.value = err.message;
    emit("error", err.message);
  }
}

/**
 * Generate a cryptographically random client nonce.
 * @returns {string} Base64-encoded 16-byte nonce.
 */
function generateClientNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Request a PGP signature from the CapAuth browser extension via postMessage.
 *
 * The extension injects a content script on CapAuth-enabled pages that
 * listens for `capauth:sign-request` events and responds with the signature.
 *
 * @param {Object} challenge - Challenge object from /capauth/v1/challenge
 * @returns {Promise<string>} ASCII-armored PGP detached signature
 */
function requestExtensionSignature(challenge) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const timeout = setTimeout(() => {
      window.removeEventListener("message", handler);
      reject(new Error("Extension did not respond in time. Is CapAuth installed and configured?"));
    }, 60_000);

    function handler(event) {
      if (
        event.source !== window ||
        event.data?.type !== "capauth:sign-response" ||
        event.data?.requestId !== requestId
      ) {
        return;
      }
      clearTimeout(timeout);
      window.removeEventListener("message", handler);

      if (event.data.error) {
        reject(new Error(event.data.error));
      } else {
        resolve(event.data.signature);
      }
    }

    window.addEventListener("message", handler);

    // Dispatch the sign request — the extension content script picks this up
    window.postMessage(
      {
        type: "capauth:sign-request",
        requestId,
        challenge,
      },
      window.location.origin
    );
  });
}

/**
 * Open the QR code login page for mobile-to-desktop authentication.
 */
function openQRLogin() {
  const serviceUrl = resolvedServiceUrl();
  const qrUrl = new URL("/capauth/v1/qr-login", serviceUrl);
  if (props.nextUrl) qrUrl.searchParams.set("redirect", props.nextUrl);
  window.open(qrUrl.toString(), "_blank", "noopener,noreferrer");
}
</script>

<style scoped>
.capauth-stage {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  max-width: 400px;
  margin: 0 auto;
  padding: 2rem;
  color: #1e293b;
}

/* Header */
.capauth-header {
  text-align: center;
  margin-bottom: 1.5rem;
}

.capauth-shield {
  width: 48px;
  height: 48px;
  color: #7c3aed;
  margin-bottom: 0.75rem;
}

.capauth-header h2 {
  margin: 0 0 0.25rem;
  font-size: 1.5rem;
  font-weight: 700;
  color: #0f172a;
}

.capauth-subtitle {
  margin: 0;
  font-size: 0.875rem;
  color: #64748b;
}

/* Error */
.capauth-error {
  background: #fef2f2;
  border: 1px solid #fecaca;
  color: #dc2626;
  border-radius: 8px;
  padding: 0.75rem 1rem;
  font-size: 0.875rem;
  margin-bottom: 1rem;
}

/* Form */
.capauth-form label {
  display: block;
  font-size: 0.875rem;
  font-weight: 600;
  color: #374151;
  margin-bottom: 0.375rem;
}

.capauth-form input[type="text"] {
  width: 100%;
  box-sizing: border-box;
  padding: 0.625rem 0.875rem;
  border: 2px solid #e2e8f0;
  border-radius: 8px;
  font-size: 0.875rem;
  font-family: "Courier New", Courier, monospace;
  letter-spacing: 0.05em;
  outline: none;
  transition: border-color 0.15s;
}

.capauth-form input[type="text"]:focus {
  border-color: #7c3aed;
  box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.1);
}

.capauth-hint {
  font-size: 0.75rem;
  color: #94a3b8;
  margin: 0.375rem 0 1rem;
}

/* Primary button */
.capauth-btn {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem 1.25rem;
  background: linear-gradient(135deg, #7c3aed, #5b21b6);
  color: #ffffff;
  border: none;
  border-radius: 8px;
  font-size: 0.9375rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
  box-shadow: 0 4px 15px rgba(124, 58, 237, 0.25);
}

.capauth-btn:hover:not(:disabled) {
  box-shadow: 0 6px 20px rgba(124, 58, 237, 0.4);
  transform: translateY(-1px);
}

.capauth-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

/* Secondary button */
.capauth-btn-secondary {
  width: 100%;
  padding: 0.625rem 1.25rem;
  background: transparent;
  color: #7c3aed;
  border: 2px solid #7c3aed;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
}

.capauth-btn-secondary:hover {
  background: rgba(124, 58, 237, 0.05);
}

/* Divider */
.capauth-divider {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 0.875rem 0;
  color: #cbd5e1;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.capauth-divider::before,
.capauth-divider::after {
  content: "";
  flex: 1;
  height: 1px;
  background: #e2e8f0;
}

/* Signing state */
.capauth-challenge {
  text-align: center;
  padding: 1.5rem 0;
}

.capauth-challenge p {
  color: #475569;
  font-size: 0.9375rem;
  margin: 0.75rem 0 0.25rem;
}

/* Success state */
.capauth-success {
  text-align: center;
  padding: 1.5rem 0;
}

.capauth-check {
  width: 48px;
  height: 48px;
  margin-bottom: 0.75rem;
}

.capauth-success p {
  color: #059669;
  font-size: 0.9375rem;
  font-weight: 600;
}

/* Spinners */
.capauth-spinner {
  width: 36px;
  height: 36px;
  border: 3px solid #e2e8f0;
  border-top-color: #7c3aed;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  margin: 0 auto;
}

.capauth-spinner-sm {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255, 255, 255, 0.4);
  border-top-color: #ffffff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Footer */
.capauth-footer {
  margin-top: 1.5rem;
  text-align: center;
  font-size: 0.8125rem;
  color: #94a3b8;
}

.capauth-footer a {
  color: #7c3aed;
  text-decoration: none;
}

.capauth-footer a:hover {
  text-decoration: underline;
}
</style>
