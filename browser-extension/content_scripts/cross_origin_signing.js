/**
 * CapAuth cross-origin signing content script.
 *
 * Allows third-party websites to request a PGP signature over a CapAuth
 * challenge via the window.postMessage API. This enables any CapAuth-enabled
 * service to trigger the extension's signing flow without needing to be on
 * the `*.capauth.io` or `*.skworld.io` allowlist.
 *
 * Protocol:
 *   1. Page sends:
 *      window.postMessage({
 *        type: 'CAPAUTH_SIGN_REQUEST',
 *        requestId: '<uuid>',       // caller-generated ID echoed in response
 *        challenge: {               // CapAuth challenge object from the service
 *          nonce: '<uuid>',
 *          client_nonce_echo: '<base64>',
 *          timestamp: '<ISO-8601>',
 *          service: '<hostname>',
 *          expires: '<ISO-8601>'
 *        },
 *        serviceUrl: 'https://...'  // base URL of the CapAuth service
 *      }, '*');
 *
 *   2. Extension shows a permission bar at the top of the page.
 *      The user must explicitly approve or deny the signing request.
 *
 *   3. On approval, the extension signs and responds:
 *      { type: 'CAPAUTH_SIGN_RESPONSE', requestId, signature: '<armored-pgp>' }
 *
 *   4. On denial or error:
 *      { type: 'CAPAUTH_SIGN_ERROR', requestId, error: '<message>' }
 *
 * Security model:
 *   - Every request triggers an explicit user approval bar (no silent signing).
 *   - The bar shows the requesting origin and the service being authenticated to.
 *   - The extension validates that the nonce format is correct (UUID).
 *   - Only one pending request is processed at a time (queue overflow is rejected).
 *   - The permission bar auto-dismisses after 60 seconds if ignored.
 *   - Approved origins can be remembered for the session (stored in memory only).
 *
 * @module content_scripts/cross_origin_signing
 */

(function () {
  "use strict";

  const NONCE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const AUTO_DISMISS_MS = 60_000;
  const MAX_QUEUE = 3;

  /** Pending signing requests waiting for user approval. */
  const pendingQueue = [];
  let currentBar = null;
  let dismissTimer = null;

  /** Origins approved for this page session (remembered in memory only). */
  const sessionApprovedOrigins = new Set();

  // ---------------------------------------------------------------------------
  // Message listener
  // ---------------------------------------------------------------------------

  window.addEventListener("message", (event) => {
    // Only accept messages from the same window (the page itself)
    if (event.source !== window) return;

    const { data } = event;
    if (!data || data.type !== "CAPAUTH_SIGN_REQUEST") return;

    const { requestId, challenge, serviceUrl } = data;
    const origin = event.origin;

    // Validate request structure
    if (!requestId || typeof requestId !== "string") return;
    if (!challenge || !challenge.nonce) {
      replyError(requestId, "Invalid challenge: missing nonce");
      return;
    }
    if (!NONCE_RE.test(challenge.nonce)) {
      replyError(requestId, "Invalid challenge: nonce is not a valid UUID");
      return;
    }
    if (!serviceUrl || !serviceUrl.startsWith("https://")) {
      replyError(requestId, "Invalid serviceUrl: must start with https://");
      return;
    }

    // Rate-limit: reject if queue is full
    if (pendingQueue.length >= MAX_QUEUE) {
      replyError(requestId, "Too many pending signing requests — please wait");
      return;
    }

    // Enqueue
    pendingQueue.push({ requestId, challenge, serviceUrl, origin });

    // If this origin is already approved for the session, sign immediately
    if (sessionApprovedOrigins.has(origin)) {
      processNext();
    } else {
      // Show user permission bar
      showPermissionBar();
    }
  });

  // ---------------------------------------------------------------------------
  // Permission bar UI
  // ---------------------------------------------------------------------------

  function showPermissionBar() {
    if (currentBar || pendingQueue.length === 0) return;

    const { requestId, challenge, serviceUrl, origin } = pendingQueue[0];

    const bar = document.createElement("div");
    bar.id = "__capauth_sign_bar__";
    bar.setAttribute("role", "alertdialog");
    bar.setAttribute("aria-label", "CapAuth signing request");

    Object.assign(bar.style, {
      position: "fixed",
      top: "0",
      left: "0",
      right: "0",
      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      gap: "12px",
      padding: "10px 16px",
      background: "#0f0f1a",
      borderBottom: "1px solid #7C3AED",
      color: "#e2e8f0",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      fontSize: "13px",
      boxShadow: "0 4px 20px rgba(124, 58, 237, 0.35)",
      boxSizing: "border-box",
    });

    // Shield icon
    const icon = document.createElement("span");
    icon.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" stroke="#7C3AED" stroke-width="2" fill="none"/>
      <path d="M10 12l2 2 4-4" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
    bar.appendChild(icon);

    // Message
    const msg = document.createElement("div");
    msg.style.flex = "1";
    msg.style.lineHeight = "1.4";

    const serviceName = (() => {
      try { return new URL(serviceUrl).hostname; } catch { return serviceUrl; }
    })();
    const requestingOrigin = origin !== "null" ? origin : "this page";

    msg.innerHTML = `
      <strong style="color:#00e5ff">CapAuth</strong>
      &nbsp;&mdash;&nbsp;
      <span>${requestingOrigin}</span>
      is requesting a signature to authenticate with
      <strong style="color:#a78bfa">${serviceName}</strong>.
    `;
    bar.appendChild(msg);

    // Remember checkbox
    const rememberLabel = document.createElement("label");
    rememberLabel.style.cssText = "display:flex;align-items:center;gap:4px;white-space:nowrap;cursor:pointer;";
    const rememberCb = document.createElement("input");
    rememberCb.type = "checkbox";
    rememberCb.id = "__capauth_remember__";
    rememberLabel.appendChild(rememberCb);
    rememberLabel.appendChild(document.createTextNode("Remember"));
    bar.appendChild(rememberLabel);

    // Approve button
    const approveBtn = document.createElement("button");
    approveBtn.textContent = "Sign In";
    Object.assign(approveBtn.style, {
      padding: "6px 14px",
      background: "linear-gradient(135deg, #7C3AED, #5b21b6)",
      color: "#fff",
      border: "none",
      borderRadius: "6px",
      fontSize: "13px",
      fontWeight: "600",
      cursor: "pointer",
      whiteSpace: "nowrap",
    });
    approveBtn.addEventListener("click", () => {
      if (rememberCb.checked) sessionApprovedOrigins.add(origin);
      dismissBar();
      processNext();
    });
    bar.appendChild(approveBtn);

    // Deny button
    const denyBtn = document.createElement("button");
    denyBtn.textContent = "Deny";
    Object.assign(denyBtn.style, {
      padding: "6px 12px",
      background: "transparent",
      color: "#94a3b8",
      border: "1px solid #334155",
      borderRadius: "6px",
      fontSize: "13px",
      cursor: "pointer",
      whiteSpace: "nowrap",
    });
    denyBtn.addEventListener("click", () => {
      replyError(requestId, "User denied the signing request");
      pendingQueue.shift();
      dismissBar();
      // Show next request if queued
      if (pendingQueue.length > 0) showPermissionBar();
    });
    bar.appendChild(denyBtn);

    // Auto-dismiss timer
    dismissTimer = setTimeout(() => {
      replyError(requestId, "Signing request timed out — no response from user");
      pendingQueue.shift();
      dismissBar();
    }, AUTO_DISMISS_MS);

    document.body.prepend(bar);
    currentBar = bar;
  }

  function dismissBar() {
    if (dismissTimer) { clearTimeout(dismissTimer); dismissTimer = null; }
    if (currentBar) { currentBar.remove(); currentBar = null; }
  }

  // ---------------------------------------------------------------------------
  // Signing
  // ---------------------------------------------------------------------------

  async function processNext() {
    if (pendingQueue.length === 0) return;

    const { requestId, challenge, serviceUrl, origin } = pendingQueue.shift();

    try {
      const result = await chrome.runtime.sendMessage({
        action: "SIGN_CHALLENGE",
        payload: { challenge },
      });

      if (result.success) {
        replySuccess(requestId, result.signature);
      } else {
        replyError(requestId, result.error || "Signing failed");
      }
    } catch (err) {
      replyError(requestId, `Extension error: ${err.message}`);
    }

    // Process next in queue (if any)
    if (pendingQueue.length > 0) {
      if (sessionApprovedOrigins.has(pendingQueue[0].origin)) {
        processNext();
      } else {
        showPermissionBar();
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Responses
  // ---------------------------------------------------------------------------

  function replySuccess(requestId, signature) {
    window.postMessage({ type: "CAPAUTH_SIGN_RESPONSE", requestId, signature }, "*");
  }

  function replyError(requestId, error) {
    window.postMessage({ type: "CAPAUTH_SIGN_ERROR", requestId, error }, "*");
  }

  // ---------------------------------------------------------------------------
  // Expose a discovery signal so pages can detect the extension
  // ---------------------------------------------------------------------------

  window.dispatchEvent(new CustomEvent("capauth:extension:ready", {
    detail: { version: "0.1.0", capabilities: ["sign", "qr"] },
  }));

})();
