/**
 * AuthenticatorSelectionStage — choose the signing mechanism.
 *
 * Renders a selection card for the user to pick how they want to sign
 * the CapAuth challenge:
 *
 *   1. PGP Key in browser  — uses the private key stored in chrome.storage
 *   2. Hardware Key        — future YubiKey/FIDO2 support (disabled in v0.1)
 *   3. QR Scan             — mobile device signs on behalf of desktop
 *
 * Sets context.authMethod to one of: 'pgp-key' | 'hardware' | 'qr'
 *
 * Skips itself if settings indicate only one method is possible (e.g. no
 * private key and QR is the only viable path — auto-selects QR in that case).
 *
 * @module stages/AuthenticatorSelectionStage
 */

import { CapAuthStage, CapAuthStageError } from "./CapAuthStage.js";

const METHODS = [
  {
    id: "pgp-key",
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,
    label: "PGP Key in Browser",
    description: "Sign with your private key stored securely in the extension.",
    requiresKey: true,
  },
  {
    id: "hardware",
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="2" y="8" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
      <circle cx="18" cy="12" r="2" fill="currentColor"/>
      <path d="M8 8V7a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="2"/>
    </svg>`,
    label: "Hardware Key",
    description: "Sign with a YubiKey or FIDO2 security key. (Coming in v0.2)",
    disabled: true,
  },
  {
    id: "qr",
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="3" y="3" width="7" height="7" rx="1" stroke="currentColor" stroke-width="2"/>
      <rect x="14" y="3" width="7" height="7" rx="1" stroke="currentColor" stroke-width="2"/>
      <rect x="3" y="14" width="7" height="7" rx="1" stroke="currentColor" stroke-width="2"/>
      <rect x="5" y="5" width="3" height="3" fill="currentColor"/>
      <rect x="16" y="5" width="3" height="3" fill="currentColor"/>
      <rect x="5" y="16" width="3" height="3" fill="currentColor"/>
      <path d="M14 14h3v3h-3zm4 0h3v3h-3zm-4 4h3v3h-3zm4 0h3v3h-3z" fill="currentColor"/>
    </svg>`,
    label: "QR Code",
    description: "Sign on your mobile device — no key required on this computer.",
    requiresKey: false,
  },
];

export class AuthenticatorSelectionStage extends CapAuthStage {
  constructor() {
    super();
    this._resolveSelection = null;
    this._rejectSelection = null;
  }

  get name() {
    return "Select Authenticator";
  }

  /**
   * Skip selection if the context already has an authMethod set.
   */
  canHandle(context) {
    return !context.authMethod;
  }

  async execute(context) {
    // Auto-select PGP key if available and no hardware/QR needed
    if (context.hasPrivateKey && context.autoSelectKey) {
      return { ...context, authMethod: "pgp-key" };
    }

    // Auto-select QR if no private key is available
    if (!context.hasPrivateKey) {
      return { ...context, authMethod: "qr" };
    }

    // Wait for user selection (resolved by _handleSelect)
    return new Promise((resolve, reject) => {
      this._resolveSelection = resolve;
      this._rejectSelection = reject;
    });
  }

  render(container, context) {
    const wrapper = this._makeWrapper(
      "How do you want to sign in?",
      "Choose your authentication method."
    );

    const list = document.createElement("div");
    list.className = "stage-method-list";

    for (const method of METHODS) {
      const isDisabled = method.disabled ||
        (method.requiresKey && !context.hasPrivateKey);

      const card = document.createElement("button");
      card.type = "button";
      card.className = `stage-method-card${isDisabled ? " disabled" : ""}`;
      card.disabled = isDisabled;
      card.setAttribute("data-method", method.id);
      card.setAttribute("aria-label", method.label);

      card.innerHTML = `
        <span class="stage-method-icon">${method.icon}</span>
        <span class="stage-method-body">
          <span class="stage-method-label">${method.label}</span>
          <span class="stage-method-desc">${method.description}</span>
        </span>
        <span class="stage-method-arrow">›</span>
      `;

      if (!isDisabled) {
        card.addEventListener("click", () => this._handleSelect(method.id, context));
      }

      list.appendChild(card);
    }

    wrapper.appendChild(list);

    const cancelBtn = this._makeButton("Cancel", "secondary");
    cancelBtn.addEventListener("click", () => {
      this._rejectSelection?.(new CapAuthStageError("User cancelled", true));
    });
    wrapper.appendChild(cancelBtn);

    container.appendChild(wrapper);
  }

  destroy() {
    this._resolveSelection = null;
    this._rejectSelection = null;
  }

  _handleSelect(methodId, context) {
    this._resolveSelection?.({ ...context, authMethod: methodId });
  }
}
