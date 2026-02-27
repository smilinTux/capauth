/**
 * CapAuth popup controller — orchestrates the one-click sovereign login UI.
 *
 * All heavy lifting is delegated to the background service worker via
 * chrome.runtime.sendMessage. The popup is intentionally thin — it only
 * handles UI state and user interactions.
 *
 * Message shape follows the { action, payload } pattern from Consciousness Swipe.
 *
 * @module popup
 */

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

/**
 * Show a toast notification.
 *
 * @param {string} message - Toast message text.
 * @param {'success'|'error'|''} [type=''] - Toast type for styling.
 * @param {number} [durationMs=2500] - How long to show the toast.
 */
function showToast(message, type = "", durationMs = 2500) {
  const toast = $("toast");
  toast.textContent = message;
  toast.className = `toast show ${type}`;
  setTimeout(() => {
    toast.className = "toast";
  }, durationMs);
}

/**
 * Send a message to the background service worker and await the response.
 *
 * @param {string} action - The action identifier (e.g. "INITIATE_AUTH").
 * @param {Object} [payload={}] - Action-specific data.
 * @returns {Promise<any>} Response from the background worker.
 */
function bg(action, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action, payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

/**
 * Truncate a PGP fingerprint for display.
 * Shows first 4 and last 4 characters with ellipsis.
 *
 * @param {string} fp - Full 40-character fingerprint.
 * @returns {string} Truncated display string.
 */
function truncateFingerprint(fp) {
  if (!fp || fp.length < 16) return fp || "Not configured";
  // Format in 4-char groups: XXXX XXXX ... XXXX XXXX
  const formatted = fp.toUpperCase().replace(/(.{4})/g, "$1 ").trim();
  const groups = formatted.split(" ");
  if (groups.length <= 4) return formatted;
  return `${groups[0]} ${groups[1]} ... ${groups[groups.length - 2]} ${groups[groups.length - 1]}`;
}

// ---------------------------------------------------------------------------
// Status updates
// ---------------------------------------------------------------------------

/**
 * Check the background worker for connection status and update the UI.
 */
async function updateStatus() {
  const dot = $("status-dot");
  const text = $("status-text");

  dot.className = "dot checking";
  text.textContent = "Checking...";

  try {
    const result = await bg("CHECK_STATUS");

    if (result.configured) {
      // Update fingerprint display
      const fpDisplay = $("fingerprint-display");
      const fpText = $("fingerprint-text");
      fpText.textContent = truncateFingerprint(result.fingerprint);
      fpDisplay.classList.remove("not-configured");

      // Update service display
      if (result.serviceUrl) {
        const serviceText = $("service-text");
        const serviceDisplay = $("service-display");
        try {
          serviceText.textContent = new URL(result.serviceUrl).hostname;
          serviceDisplay.classList.add("active");
        } catch {
          serviceText.textContent = result.serviceUrl;
        }
      }

      // Enable sign-in button if private key is available
      const btn = $("btn-signin");
      if (result.hasPrivateKey) {
        btn.disabled = false;
      } else {
        btn.disabled = true;
        $("signin-label").textContent = "Import key in settings";
      }

      // Update connection status
      if (result.serviceReachable) {
        dot.className = "dot connected";
        text.textContent = "Connected";
      } else if (result.serviceUrl) {
        dot.className = "dot disconnected";
        text.textContent = "Service unreachable";
      } else {
        dot.className = "dot disconnected";
        text.textContent = "No service configured";
      }
    } else {
      // Not configured — prompt user to set up
      dot.className = "dot disconnected";
      text.textContent = "Not configured";

      const fpDisplay = $("fingerprint-display");
      fpDisplay.classList.add("not-configured");
      $("fingerprint-text").textContent = "Open settings to configure";

      $("btn-signin").disabled = true;
      $("signin-label").textContent = "Configure in settings";
    }
  } catch (err) {
    dot.className = "dot disconnected";
    text.textContent = "Error";
    showToast(`Status check failed: ${err.message}`, "error");
  }
}

// ---------------------------------------------------------------------------
// Authentication flow
// ---------------------------------------------------------------------------

/**
 * Initiate the CapAuth sign-in flow.
 *
 * Sends INITIATE_AUTH to the background worker, which handles the full
 * challenge-response cycle. Updates the UI with loading states and results.
 */
async function initiateSignIn() {
  const btn = $("btn-signin");
  const label = $("signin-label");
  const authResult = $("auth-result");

  // Set loading state
  btn.disabled = true;
  btn.classList.add("authenticating");
  label.textContent = "Authenticating...";

  try {
    const result = await bg("INITIATE_AUTH", {});

    if (result.success) {
      // Show success state
      btn.classList.remove("authenticating");
      btn.classList.add("authenticated");
      label.textContent = "Authenticated";

      // Display auth result
      authResult.style.display = "flex";
      const card = $("auth-card");
      const icon = $("auth-status-icon");
      const statusText = $("auth-status-text");
      const detail = $("auth-detail");

      card.className = "auth-card success";
      icon.className = "auth-status-icon success";

      if (result.source === "cache") {
        statusText.textContent = "Authenticated (cached)";
      } else {
        statusText.textContent = "Authenticated";
      }

      // Build detail text
      const claims = result.oidc_claims || {};
      const detailParts = [];
      if (claims.name) detailParts.push(`Name: ${claims.name}`);
      if (claims.email) detailParts.push(`Email: ${claims.email}`);
      detailParts.push(`Fingerprint: <code>${truncateFingerprint(result.fingerprint)}</code>`);
      if (result.expires_in) {
        detailParts.push(`Token expires in ${Math.floor(result.expires_in / 60)} min`);
      }
      if (result.is_new_enrollment) {
        detailParts.push("New key enrollment");
      }
      detail.innerHTML = detailParts.join("<br>");

      showToast("Sovereign login successful", "success", 3000);

      // Notify the active tab's content script about the auth success
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) {
          await chrome.tabs.sendMessage(tab.id, {
            action: "CAPAUTH_AUTH_SUCCESS",
            payload: {
              fingerprint: result.fingerprint,
              access_token: result.access_token,
              oidc_claims: result.oidc_claims,
            },
          });
        }
      } catch {
        // Content script may not be injected on this page — non-fatal
      }
    } else {
      // Show error state
      btn.classList.remove("authenticating");
      label.textContent = "Sign In with CapAuth";
      btn.disabled = false;

      authResult.style.display = "flex";
      const card = $("auth-card");
      const icon = $("auth-status-icon");
      const statusText = $("auth-status-text");
      const detail = $("auth-detail");

      card.className = "auth-card error";
      icon.className = "auth-status-icon error";
      statusText.textContent = "Authentication Failed";
      detail.textContent = result.error || "Unknown error";

      showToast(result.error || "Authentication failed", "error", 4000);
    }
  } catch (err) {
    // Network or extension error
    btn.classList.remove("authenticating");
    label.textContent = "Sign In with CapAuth";
    btn.disabled = false;

    showToast(`Error: ${err.message}`, "error", 4000);
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
  // Load status
  await updateStatus();

  // Event listeners
  $("btn-signin").addEventListener("click", initiateSignIn);

  $("btn-settings").addEventListener("click", () => {
    // Open the options page in a new tab
    chrome.runtime.openOptionsPage();
  });
}

document.addEventListener("DOMContentLoaded", init);
