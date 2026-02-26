/**
 * CapAuth Authentik flow stage — PGP challenge-response (fingerprint → nonce → signed response).
 *
 * Copy this file (and optional CapAuthStage.css) into Authentik's web tree:
 *   web/src/flow/stages/capauth/CapAuthStage.ts
 * Add to web/src/flow/index.entrypoint.ts:
 *   import "#flow/stages/capauth/CapAuthStage";
 *
 * Contract: challenge has need_fingerprint, fingerprint, nonce, qr_payload, etc.
 * Step 1: need_fingerprint → submit { fingerprint }.
 * Step 2: !need_fingerprint → show nonce/QR, submit { fingerprint, nonce, nonce_signature, claims?, claims_signature?, public_key? }.
 */

import "#flow/FormStatic";
import "#flow/components/ak-flow-card";

import { BaseStage } from "#flow/stages/base";

import { msg } from "@lit/localize";
import { CSSResult, html, nothing, TemplateResult } from "lit";
import { customElement, state } from "lit/decorators.js";

import PFButton from "@patternfly/patternfly/components/Button/button.css";
import PFForm from "@patternfly/patternfly/components/Form/form.css";
import PFFormControl from "@patternfly/patternfly/components/FormControl/form-control.css";
import PFLogin from "@patternfly/patternfly/components/Login/login.css";
import PFTitle from "@patternfly/patternfly/components/Title/title.css";
import PFBase from "@patternfly/patternfly/patternfly-base.css";

/** Challenge shape from CapAuthStageView (CapAuthChallenge). */
export interface CapAuthChallenge {
  need_fingerprint?: boolean;
  fingerprint?: string;
  nonce?: string;
  client_nonce_echo?: string;
  timestamp?: string;
  service?: string;
  expires?: string;
  server_signature?: string;
  presentation?: string;
  qr_payload?: string;
  component?: string;
  flowInfo?: unknown;
  pendingUser?: string;
  pendingUserAvatar?: string;
  responseErrors?: { [key: string]: unknown[] };
}

/** Parsed signed response (step 2). */
interface SignedResponsePayload {
  fingerprint?: string;
  nonce?: string;
  nonce_signature?: string;
  claims?: Record<string, unknown>;
  claims_signature?: string;
  public_key?: string;
}

@customElement("ak-stage-capauth")
export class CapAuthStage extends BaseStage<CapAuthChallenge, Record<string, unknown>> {
  static styles: CSSResult[] = [PFBase, PFLogin, PFForm, PFFormControl, PFTitle, PFButton];

  @state() private fingerprintInput = "";
  @state() private signedResponseJson = "";
  @state() private parseError = "";

  private get isLoading(): boolean {
    return Boolean(this.host?.loading);
  }

  private get needFingerprint(): boolean {
    return Boolean(this.challenge?.need_fingerprint);
  }

  private get challengeFingerprint(): string {
    return this.challenge?.fingerprint ?? "";
  }

  private get challengeNonce(): string {
    return this.challenge?.nonce ?? "";
  }

  private get qrPayload(): string {
    return this.challenge?.qr_payload ?? "";
  }

  private get presentation(): string {
    return this.challenge?.presentation ?? "";
  }

  private renderFieldErrors(field: string): TemplateResult {
    const errors = (this.challenge?.responseErrors?.[field] ?? []) as unknown[];
    if (!errors.length) {
      return nothing;
    }
    return html`
      ${errors.map((err, idx) => {
        const text = String(err);
        return html`<p class="pf-c-form__helper-text pf-m-error" data-field=${field} data-idx=${idx}>
          ${text}
        </p>`;
      })}
    `;
  }

  override render(): TemplateResult {
    if (!this.challenge) return html``;

    return html`
      <ak-flow-card>
        <div class="pf-c-login__main-body">
          ${this.renderNonFieldErrors()}
          ${this.renderUserInfo()}

          ${this.needFingerprint ? this.renderFingerprintStep() : this.renderNonceStep()}
        </div>
      </ak-flow-card>
    `;
  }

  private renderFingerprintStep(): TemplateResult {
    return html`
      <form class="pf-c-form" @submit=${this.onFingerprintSubmit}>
        <p class="pf-c-form__helper-text">
          ${msg("Enter your PGP key fingerprint (40 characters) to sign in with CapAuth.")}
        </p>
        <div class="pf-c-form__group">
          <label class="pf-c-form__label" for="capauth-fingerprint">
            <span class="pf-c-form__label-text">${msg("Fingerprint")}</span>
          </label>
          <input
            class="pf-c-form-control"
            type="text"
            id="capauth-fingerprint"
            name="fingerprint"
            .value=${this.fingerprintInput}
            @input=${this.onFingerprintInput}
            placeholder="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            maxlength="40"
            autocomplete="off"
            required
          />
          ${this.renderFieldErrors("fingerprint")}
        </div>
        <div class="pf-c-form__group pf-m-action">
          <button
            type="submit"
            class="pf-c-button pf-m-primary pf-m-block"
            ?disabled=${this.isLoading}
          >
            ${this.isLoading ? msg("Continuing…") : msg("Continue")}
          </button>
        </div>
      </form>
    `;
  }

  private renderNonceStep(): TemplateResult {
    const nonce = this.challengeNonce;
    const fingerprint = this.challengeFingerprint;
    const qr = this.qrPayload;
    const presentation = this.presentation;

    return html`
      <form class="pf-c-form" @submit=${this.onSignedResponseSubmit}>
        <p class="pf-c-form__helper-text">
          ${presentation === "extension"
            ? msg(
                "Your CapAuth browser extension may handle this challenge automatically. If not, sign it in your CapAuth client (CLI, extension, or mobile) and paste the signed response below.",
              )
            : msg(
                "Sign the challenge in your CapAuth client (CLI, extension, or mobile), then paste the signed response below.",
              )}
        </p>
        <div class="pf-c-form__group">
          <label class="pf-c-form__label">
            <span class="pf-c-form__label-text">${msg("Fingerprint")}</span>
          </label>
          <input
            class="pf-c-form-control"
            type="text"
            readonly
            .value=${fingerprint}
            style="font-family: monospace;"
          />
        </div>
        <div class="pf-c-form__group">
          <label class="pf-c-form__label">
            <span class="pf-c-form__label-text">${msg("Challenge nonce")}</span>
          </label>
          <input
            class="pf-c-form-control"
            type="text"
            readonly
            .value=${nonce}
            style="font-family: monospace; word-break: break-all;"
          />
          ${this.renderFieldErrors("nonce")}
        </div>
        ${qr
          ? html`
              <div class="pf-c-form__group">
                <label class="pf-c-form__label">
                  <span class="pf-c-form__label-text">${msg("QR payload (for mobile)")}</span>
                </label>
                <textarea
                  class="pf-c-form-control"
                  readonly
                  rows="3"
                  .value=${qr}
                  style="font-family: monospace; font-size: 0.85em;"
                ></textarea>
                <p class="pf-c-form__helper-text">${msg("Scan with CapAuth mobile app or use the nonce above in CLI.")}</p>
              </div>
            `
          : nothing}
        <div class="pf-c-form__group">
          <label class="pf-c-form__label" for="capauth-signed-response">
            <span class="pf-c-form__label-text">${msg("Signed response (JSON)")}</span>
          </label>
          <textarea
            class="pf-c-form-control"
            id="capauth-signed-response"
            name="signed_response"
            rows="8"
            .value=${this.signedResponseJson}
            @input=${this.onSignedResponseInput}
            placeholder='{"fingerprint":"...","nonce":"...","nonce_signature":"...",...}'
            style="font-family: monospace; font-size: 0.85em;"
          ></textarea>
          ${this.parseError ? html`<p class="pf-c-form__helper-text pf-m-error">${this.parseError}</p>` : nothing}
          ${this.renderFieldErrors("nonce_signature")}
          ${this.renderFieldErrors("claims")}
          ${this.renderFieldErrors("claims_signature")}
          ${this.renderFieldErrors("public_key")}
        </div>
        <div class="pf-c-form__group pf-m-action">
          <button
            type="submit"
            class="pf-c-button pf-m-primary pf-m-block"
            ?disabled=${this.isLoading}
          >
            ${this.isLoading ? msg("Verifying…") : msg("Continue")}
          </button>
        </div>
      </form>
    `;
  }

  private onFingerprintInput = (e: Event): void => {
    const input = e.target as HTMLInputElement;
    this.fingerprintInput = (input?.value ?? "").replace(/\s/g, "").toUpperCase().slice(0, 40);
  };

  private onFingerprintSubmit = (e: SubmitEvent): void => {
    e.preventDefault();
    const fp = this.fingerprintInput.trim();
    if (fp.length !== 40) return;
    void this.host?.submit({ fingerprint: fp });
  };

  private onSignedResponseInput = (e: Event): void => {
    const textarea = e.target as HTMLTextAreaElement;
    this.signedResponseJson = textarea?.value ?? "";
    this.parseError = "";
  };

  private onSignedResponseSubmit = (e: SubmitEvent): void => {
    e.preventDefault();
    this.parseError = "";
    let payload: SignedResponsePayload;
    try {
      const raw = this.signedResponseJson.trim();
      if (!raw) {
        this.parseError = "Paste the signed response JSON from your CapAuth client.";
        return;
      }
      payload = JSON.parse(raw) as SignedResponsePayload;
    } catch {
      this.parseError = "Invalid JSON. Paste the full signed response from your CapAuth client.";
      return;
    }
    const fingerprint = payload.fingerprint ?? this.challengeFingerprint;
    const nonce = payload.nonce ?? this.challengeNonce;
    if (!fingerprint || !nonce || !payload.nonce_signature) {
      this.parseError = "Signed response must include fingerprint, nonce, and nonce_signature.";
      return;
    }
    const submitPayload: Record<string, unknown> = {
      fingerprint,
      nonce,
      nonce_signature: payload.nonce_signature,
    };
    if (payload.claims != null) submitPayload.claims = payload.claims;
    if (payload.claims_signature) submitPayload.claims_signature = payload.claims_signature;
    if (payload.public_key) submitPayload.public_key = payload.public_key;
    void this.host?.submit(submitPayload);
  };
}

declare global {
  interface HTMLElementTagNameMap {
    "ak-stage-capauth": CapAuthStage;
  }
}
