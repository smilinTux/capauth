/**
 * CapAuth content script — detect CapAuth-enabled login pages and inject
 * a "Sign in with CapAuth" button.
 *
 * Detection methods (in priority order):
 *   1. `data-capauth` attribute on any element
 *   2. `<meta name="capauth-service">` tag in the document head
 *   3. `<link rel="capauth">` tag pointing to the CapAuth endpoint
 *
 * When a CapAuth-enabled page is detected, this script:
 *   - Injects a styled "Sign in with CapAuth" button near the login form
 *   - Sends INITIATE_AUTH to the background worker on click
 *   - Listens for auth results and handles redirect/auto-fill
 *
 * @module detector
 */

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * Detect if the current page has CapAuth login capability.
 *
 * @returns {Object|null} Detection result with service URL, or null if not detected.
 */
function detectCapAuth() {
  // Method 1: data-capauth attribute
  const dataAttrEl = document.querySelector("[data-capauth]");
  if (dataAttrEl) {
    const serviceUrl = dataAttrEl.getAttribute("data-capauth") || "";
    const redirectUrl = dataAttrEl.getAttribute("data-capauth-redirect") || "";
    return {
      method: "data-attribute",
      serviceUrl,
      redirectUrl,
      targetElement: dataAttrEl,
    };
  }

  // Method 2: meta tag
  const metaTag = document.querySelector('meta[name="capauth-service"]');
  if (metaTag) {
    const serviceUrl = metaTag.getAttribute("content") || "";
    const redirectMeta = document.querySelector('meta[name="capauth-redirect"]');
    const redirectUrl = redirectMeta?.getAttribute("content") || "";
    return {
      method: "meta-tag",
      serviceUrl,
      redirectUrl,
      targetElement: null,
    };
  }

  // Method 3: link tag
  const linkTag = document.querySelector('link[rel="capauth"]');
  if (linkTag) {
    const serviceUrl = linkTag.getAttribute("href") || "";
    return {
      method: "link-tag",
      serviceUrl,
      redirectUrl: "",
      targetElement: null,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Button injection
// ---------------------------------------------------------------------------

/**
 * Create the "Sign in with CapAuth" button element.
 *
 * @returns {HTMLElement} The styled button element.
 */
function createCapAuthButton() {
  const button = document.createElement("button");
  button.id = "capauth-signin-btn";
  button.type = "button";

  // Shield SVG icon
  const shieldSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle;margin-right:8px">
    <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" stroke="currentColor" stroke-width="2" fill="none"/>
    <path d="M10 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;

  button.innerHTML = `${shieldSvg}<span>Sign in with CapAuth</span>`;

  // Inline styles to avoid CSS conflicts with host page
  Object.assign(button.style, {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "10px 20px",
    margin: "8px 0",
    background: "linear-gradient(135deg, #7C3AED, #5b21b6)",
    color: "#ffffff",
    border: "none",
    borderRadius: "8px",
    fontSize: "14px",
    fontWeight: "600",
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    cursor: "pointer",
    boxShadow: "0 4px 15px rgba(124, 58, 237, 0.3)",
    transition: "all 0.15s ease",
    width: "100%",
    maxWidth: "320px",
    letterSpacing: "0.02em",
  });

  // Hover effect
  button.addEventListener("mouseenter", () => {
    button.style.boxShadow = "0 6px 20px rgba(124, 58, 237, 0.5)";
    button.style.transform = "translateY(-1px)";
  });
  button.addEventListener("mouseleave", () => {
    button.style.boxShadow = "0 4px 15px rgba(124, 58, 237, 0.3)";
    button.style.transform = "translateY(0)";
  });

  return button;
}

/**
 * Create a small status text element below the button.
 *
 * @returns {HTMLElement} Status text element.
 */
function createStatusText() {
  const status = document.createElement("div");
  status.id = "capauth-status";
  Object.assign(status.style, {
    fontSize: "11px",
    color: "#94a3b8",
    textAlign: "center",
    marginTop: "4px",
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    transition: "color 0.2s ease",
  });
  status.textContent = "Passwordless PGP authentication";
  return status;
}

/**
 * Inject the CapAuth sign-in button into the page.
 *
 * @param {Object} detection - Detection result from detectCapAuth().
 */
function injectButton(detection) {
  // Don't inject if button already exists
  if (document.getElementById("capauth-signin-btn")) return;

  const button = createCapAuthButton();
  const statusText = createStatusText();

  // Wrap in a container
  const container = document.createElement("div");
  container.id = "capauth-container";
  Object.assign(container.style, {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    margin: "12px 0",
  });
  container.appendChild(button);
  container.appendChild(statusText);

  // Determine where to inject
  if (detection.targetElement) {
    // Insert after the target element (data-capauth attribute holder)
    detection.targetElement.parentNode.insertBefore(
      container,
      detection.targetElement.nextSibling
    );
  } else {
    // Find the login form and inject before it, or append to body as fallback
    const loginForm = document.querySelector(
      'form[action*="login"], form[action*="auth"], form[action*="signin"], ' +
      'form#login-form, form.login-form, [data-testid="login-form"]'
    );

    if (loginForm) {
      loginForm.parentNode.insertBefore(container, loginForm);
    } else {
      // Fallback: look for common login containers
      const loginContainer = document.querySelector(
        '.login-container, .auth-container, .signin-container, ' +
        '#login, #auth, main, [role="main"]'
      );
      if (loginContainer) {
        loginContainer.prepend(container);
      }
      // If nothing found, don't inject — page structure is too ambiguous
    }
  }

  // Wire up click handler
  button.addEventListener("click", () => handleSignInClick(detection, button, statusText));
}

// ---------------------------------------------------------------------------
// Auth flow
// ---------------------------------------------------------------------------

/**
 * Handle click on the injected "Sign in with CapAuth" button.
 *
 * Sends the INITIATE_AUTH message to the background service worker
 * and updates the button state based on the result.
 *
 * @param {Object} detection - Detection result with serviceUrl and redirectUrl.
 * @param {HTMLElement} button - The CapAuth button element.
 * @param {HTMLElement} statusText - The status text element below the button.
 */
async function handleSignInClick(detection, button, statusText) {
  // Set loading state
  button.disabled = true;
  button.style.opacity = "0.7";
  button.querySelector("span").textContent = "Authenticating...";
  statusText.textContent = "Signing challenge with your PGP key...";
  statusText.style.color = "#f59e0b"; // Warning/amber color

  try {
    const result = await chrome.runtime.sendMessage({
      action: "INITIATE_AUTH",
      payload: {
        serviceUrl: detection.serviceUrl || window.location.origin,
      },
    });

    if (result.success) {
      // Success state
      button.querySelector("span").textContent = "Authenticated";
      button.style.background = "linear-gradient(135deg, #059669, #047857)";
      button.style.boxShadow = "0 4px 15px rgba(16, 185, 129, 0.3)";
      statusText.textContent = "Sovereign login successful";
      statusText.style.color = "#10b981";

      // If there is a redirect URL, navigate after a brief delay
      if (detection.redirectUrl) {
        statusText.textContent = "Redirecting...";
        setTimeout(() => {
          window.location.href = detection.redirectUrl;
        }, 800);
      }

      // Dispatch a custom event so the host page can react
      document.dispatchEvent(
        new CustomEvent("capauth:authenticated", {
          detail: {
            fingerprint: result.fingerprint,
            access_token: result.access_token,
            oidc_claims: result.oidc_claims || {},
          },
        })
      );
    } else {
      // Error state
      button.querySelector("span").textContent = "Sign in with CapAuth";
      button.style.opacity = "1";
      button.disabled = false;
      statusText.textContent = result.error || "Authentication failed";
      statusText.style.color = "#ef4444";

      // Reset status text after a few seconds
      setTimeout(() => {
        statusText.textContent = "Passwordless PGP authentication";
        statusText.style.color = "#94a3b8";
      }, 5000);
    }
  } catch (err) {
    // Extension communication error
    button.querySelector("span").textContent = "Sign in with CapAuth";
    button.style.opacity = "1";
    button.disabled = false;
    statusText.textContent = `Error: ${err.message}`;
    statusText.style.color = "#ef4444";

    setTimeout(() => {
      statusText.textContent = "Passwordless PGP authentication";
      statusText.style.color = "#94a3b8";
    }, 5000);
  }
}

// ---------------------------------------------------------------------------
// Listen for auth results from the popup
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const { action, payload } = message;

  if (action === "CAPAUTH_AUTH_SUCCESS") {
    // The popup authenticated — update the injected button if present
    const button = document.getElementById("capauth-signin-btn");
    const statusText = document.getElementById("capauth-status");

    if (button && statusText) {
      button.querySelector("span").textContent = "Authenticated";
      button.style.background = "linear-gradient(135deg, #059669, #047857)";
      button.style.boxShadow = "0 4px 15px rgba(16, 185, 129, 0.3)";
      button.disabled = true;
      statusText.textContent = "Sovereign login successful";
      statusText.style.color = "#10b981";
    }

    // Dispatch event for host page
    document.dispatchEvent(
      new CustomEvent("capauth:authenticated", { detail: payload })
    );

    sendResponse({ received: true });
  }

  return true;
});

// ---------------------------------------------------------------------------
// Init — run detection on page load
// ---------------------------------------------------------------------------

function init() {
  const detection = detectCapAuth();

  if (detection) {
    // CapAuth-enabled page detected — inject button
    injectButton(detection);

    // Expose detection result on window for debugging
    window.__capauth = {
      detected: true,
      method: detection.method,
      serviceUrl: detection.serviceUrl,
    };
  }
}

// Run detection
init();

// Also observe DOM changes in case the login form loads dynamically (SPA)
const observer = new MutationObserver(() => {
  // Only re-run if we haven't injected yet
  if (!document.getElementById("capauth-signin-btn")) {
    const detection = detectCapAuth();
    if (detection) {
      injectButton(detection);
      observer.disconnect(); // Stop observing once injected
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

// Stop observing after 10 seconds to avoid performance impact
setTimeout(() => observer.disconnect(), 10_000);
