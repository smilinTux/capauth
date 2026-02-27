/**
 * CapAuth options page controller.
 *
 * Manages persistent settings stored in chrome.storage.local:
 *   - PGP fingerprint
 *   - Default service URL
 *   - Private key (armored PGP)
 *   - Public key (armored PGP, for enrollment)
 *   - Auto-sign toggle
 *
 * @module options
 */

const SETTINGS_KEY = "capauth_settings";
const TOKEN_STORAGE_PREFIX = "capauth_token_";

/**
 * Default settings values.
 */
const DEFAULTS = {
  fingerprint: "",
  serviceUrl: "",
  privateKeyArmored: "",
  publicKeyArmored: "",
  autoSign: false,
};

/**
 * Load settings from chrome.storage.local and populate the form.
 */
async function loadSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = { ...DEFAULTS, ...result[SETTINGS_KEY] };

  document.getElementById("fingerprint").value = settings.fingerprint;
  document.getElementById("service-url").value = settings.serviceUrl;
  document.getElementById("private-key").value = settings.privateKeyArmored;
  document.getElementById("public-key").value = settings.publicKeyArmored;
  document.getElementById("auto-sign").checked = settings.autoSign;
}

/**
 * Save the current form values to chrome.storage.local.
 */
async function saveSettings() {
  const fingerprint = document.getElementById("fingerprint").value.trim().toUpperCase();
  const serviceUrl = document.getElementById("service-url").value.trim();
  const privateKeyArmored = document.getElementById("private-key").value.trim();
  const publicKeyArmored = document.getElementById("public-key").value.trim();
  const autoSign = document.getElementById("auto-sign").checked;

  // Basic validation
  if (fingerprint && fingerprint.length !== 40) {
    showStatus("Fingerprint must be exactly 40 hex characters", true);
    return;
  }

  if (fingerprint && !/^[A-F0-9]{40}$/.test(fingerprint)) {
    showStatus("Fingerprint must contain only hex characters (0-9, A-F)", true);
    return;
  }

  if (privateKeyArmored && !privateKeyArmored.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
    showStatus("Private key must be ASCII-armored PGP format", true);
    return;
  }

  if (publicKeyArmored && !publicKeyArmored.includes("BEGIN PGP PUBLIC KEY BLOCK")) {
    showStatus("Public key must be ASCII-armored PGP format", true);
    return;
  }

  const settings = {
    fingerprint,
    serviceUrl,
    privateKeyArmored,
    publicKeyArmored,
    autoSign,
  };

  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  showStatus("Settings saved");
}

/**
 * Clear all extension data (settings + cached tokens).
 */
async function clearAllData() {
  if (!confirm("This will clear your PGP key, fingerprint, and all cached tokens. Continue?")) {
    return;
  }

  // Clear settings
  await chrome.storage.local.remove(SETTINGS_KEY);

  // Clear all cached tokens
  const all = await chrome.storage.local.get(null);
  const tokenKeys = Object.keys(all).filter((k) => k.startsWith(TOKEN_STORAGE_PREFIX));
  if (tokenKeys.length > 0) {
    await chrome.storage.local.remove(tokenKeys);
  }

  // Reset form
  document.getElementById("fingerprint").value = "";
  document.getElementById("service-url").value = "";
  document.getElementById("private-key").value = "";
  document.getElementById("public-key").value = "";
  document.getElementById("auto-sign").checked = false;

  showStatus("All data cleared");
}

/**
 * Show a save status message.
 *
 * @param {string} message - Status message.
 * @param {boolean} [isError=false] - Whether this is an error message.
 */
function showStatus(message, isError = false) {
  const status = document.getElementById("save-status");
  status.textContent = message;
  status.style.display = "block";
  status.style.color = isError ? "#ef4444" : "#10b981";
  setTimeout(() => {
    status.style.display = "none";
  }, 3000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();

  document.getElementById("btn-save").addEventListener("click", saveSettings);
  document.getElementById("btn-clear").addEventListener("click", clearAllData);
});
