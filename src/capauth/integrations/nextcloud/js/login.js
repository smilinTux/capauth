/**
 * CapAuth Nextcloud login JavaScript.
 *
 * Handles:
 *   - Step 1: fingerprint input → POST /v1/challenge
 *   - Step 2: show nonce + paste signature → POST /v1/verify
 *   - Browser extension auto-sign (listens for capauth:signed message)
 *   - QR flow: poll /v1/nonce/{id}/status after mobile signs
 *   - 2FA inline flow (challenge.php template)
 *
 * No build step required — vanilla ES2020, no imports.
 */

(function () {
    'use strict';

    const BASE_URL = OC.generateUrl('/apps/capauth/v1');
    const CSRF_HEADER = { 'requesttoken': OC.requestToken, 'Content-Type': 'application/json' };

    // ── Utility ──────────────────────────────────────────────────────────────

    function showError(el, msg) {
        el.textContent = msg;
        el.style.display = '';
    }

    function hideError(el) {
        el.style.display = 'none';
    }

    async function postJson(url, body) {
        const resp = await fetch(url, {
            method: 'POST',
            headers: CSRF_HEADER,
            body: JSON.stringify(body),
        });
        return { ok: resp.ok, status: resp.status, data: await resp.json() };
    }

    // ── Full-page login flow (/apps/capauth/login) ────────────────────────

    const fpInput  = document.getElementById('capauth-fingerprint-input');
    const fpBtn    = document.getElementById('capauth-fingerprint-btn');
    const fpError  = document.getElementById('capauth-fp-error');
    const stepFp   = document.getElementById('capauth-step-fingerprint');
    const stepChallenge = document.getElementById('capauth-step-challenge');
    const nonceDisplay  = document.getElementById('capauth-nonce-display');
    const copyBtn       = document.getElementById('capauth-copy-btn');
    const sigInput      = document.getElementById('capauth-sig-input');
    const verifyBtn     = document.getElementById('capauth-verify-btn');
    const verifyError   = document.getElementById('capauth-verify-error');
    const spinner       = document.getElementById('capauth-spinner');
    const extNotice     = document.getElementById('capauth-extension-notice');

    let currentChallenge = null;

    if (fpBtn) {
        fpBtn.addEventListener('click', requestChallenge);
    }
    if (fpInput) {
        fpInput.addEventListener('keydown', e => { if (e.key === 'Enter') requestChallenge(); });
    }

    async function requestChallenge() {
        hideError(fpError);
        const fp = fpInput.value.trim().toUpperCase();
        if (fp.length !== 40 || !/^[0-9A-F]+$/.test(fp)) {
            showError(fpError, 'Please enter a valid 40-character hex fingerprint.');
            return;
        }

        fpBtn.disabled = true;
        try {
            const { ok, data } = await postJson(`${BASE_URL}/challenge`, { fingerprint: fp });
            if (!ok) {
                showError(fpError, data.error || 'Failed to get challenge.');
                return;
            }
            currentChallenge = data;
            showChallengeStep(fp, data);
        } catch (err) {
            showError(fpError, 'Network error: ' + err.message);
        } finally {
            fpBtn.disabled = false;
        }
    }

    function buildCanonicalPayload(fp, ch) {
        return [
            'CAPAUTH_NONCE_V1',
            `nonce=${ch.nonce}`,
            `client_nonce=${ch.client_nonce_echo}`,
            `timestamp=${ch.timestamp}`,
            `service=${ch.service}`,
            `expires=${ch.expires}`,
        ].join('\n');
    }

    function showChallengeStep(fp, ch) {
        const canonical = buildCanonicalPayload(fp, ch);
        nonceDisplay.textContent = canonical;
        stepFp.style.display = 'none';
        stepChallenge.style.display = '';

        // Extension detection.
        const isExtension = document.cookie.includes('capauth_ext=1')
            || (window.__capauth_extension === true);
        if (isExtension && extNotice) {
            extNotice.style.display = '';
            // Dispatch event for extension to pick up.
            window.dispatchEvent(new CustomEvent('capauth:challenge', { detail: ch }));
        }

        // Start QR polling if applicable.
        if (ch.qr_payload) {
            startQrPolling(ch.nonce);
        }
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const text = nonceDisplay.textContent;
            navigator.clipboard.writeText(text).then(() => {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
            });
        });
    }

    if (verifyBtn) {
        verifyBtn.addEventListener('click', submitSignature);
    }

    async function submitSignature(nonceSig, claims, claimsSig, publicKey) {
        hideError(verifyError);
        const fp = fpInput ? fpInput.value.trim().toUpperCase() : '';

        const sig = nonceSig || (sigInput ? sigInput.value.trim() : '');
        if (!sig) {
            showError(verifyError, 'Please paste your PGP signature.');
            return;
        }

        if (spinner) spinner.style.display = '';
        if (verifyBtn) verifyBtn.disabled = true;

        try {
            const body = {
                fingerprint:      fp,
                nonce:            currentChallenge.nonce,
                nonce_signature:  sig,
                claims:           claims || {},
                claims_signature: claimsSig || '',
                public_key:       publicKey || '',
            };
            const { ok, data } = await postJson(`${BASE_URL}/verify`, body);
            if (ok && data.status === 'ok') {
                // Redirect to Nextcloud home (or redirect_url if set).
                const redirect = new URLSearchParams(window.location.search).get('redirect_url') || '/';
                window.location.href = redirect;
            } else {
                showError(verifyError, data.error || 'Authentication failed.');
            }
        } catch (err) {
            showError(verifyError, 'Network error: ' + err.message);
        } finally {
            if (spinner) spinner.style.display = 'none';
            if (verifyBtn) verifyBtn.disabled = false;
        }
    }

    // ── Browser extension integration ────────────────────────────────────

    window.addEventListener('capauth:signed', function (e) {
        const detail = e.detail;
        submitSignature(
            detail.nonce_signature,
            detail.claims,
            detail.claims_signature,
            detail.public_key,
        );
    });

    // ── QR polling ───────────────────────────────────────────────────────

    function startQrPolling(nonceId) {
        const POLL_INTERVAL = 2000;
        const MAX_POLLS = 30; // 60s
        let polls = 0;

        const interval = setInterval(async () => {
            polls++;
            if (polls > MAX_POLLS) {
                clearInterval(interval);
                showError(verifyError, 'QR code expired. Please refresh and try again.');
                return;
            }
            try {
                const resp = await fetch(`${BASE_URL}/nonce/${nonceId}/status`);
                const data = await resp.json();
                if (data.status === 'consumed') {
                    clearInterval(interval);
                    // QR flow complete — reload to pick up session.
                    window.location.reload();
                } else if (data.status === 'expired') {
                    clearInterval(interval);
                    showError(verifyError, 'QR code expired.');
                }
            } catch { /* network hiccup – keep polling */ }
        }, POLL_INTERVAL);
    }

    // ── 2FA inline challenge template (challenge.php) ─────────────────────

    const challengeSubmitBtn = document.getElementById('capauth-submit-sig');
    const challengeSigPaste  = document.getElementById('capauth-sig-paste');
    const challengeError     = document.getElementById('capauth-2fa-error');
    const challengeNonce     = document.getElementById('capauth-nonce');
    const challengeFp        = document.getElementById('capauth-fingerprint');
    const challengeProviderId = document.getElementById('capauth-provider-id');

    if (challengeSubmitBtn) {
        challengeSubmitBtn.addEventListener('click', async function () {
            hideError(challengeError);
            const sig = challengeSigPaste.value.trim();
            if (!sig) {
                showError(challengeError, 'Paste your PGP signature to continue.');
                return;
            }

            challengeSubmitBtn.disabled = true;
            try {
                // In 2FA mode Nextcloud expects the signed response via the 2FA
                // challenge verification endpoint. We post the raw JSON blob as
                // the "challenge" field which CapAuthProvider::verifyChallenge()
                // parses.
                const payload = JSON.stringify({
                    fingerprint:     challengeFp.value,
                    nonce:           challengeNonce.value,
                    nonce_signature: sig,
                });

                // Nextcloud 2FA verification endpoint:
                // POST /login/challenge/{provider_id}
                const url = OC.generateUrl(`/login/challenge/${challengeProviderId.value}`);
                const resp = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'requesttoken': OC.requestToken },
                    body: new URLSearchParams({ challenge: payload }),
                });

                if (resp.ok || resp.redirected) {
                    window.location.href = resp.url || '/';
                } else {
                    const data = await resp.json().catch(() => ({}));
                    showError(challengeError, data.message || 'Verification failed.');
                }
            } catch (err) {
                showError(challengeError, 'Network error: ' + err.message);
            } finally {
                challengeSubmitBtn.disabled = false;
            }
        });

        // Extension auto-sign for 2FA flow.
        window.addEventListener('capauth:signed', function (e) {
            const detail = e.detail;
            if (challengeSigPaste) {
                challengeSigPaste.value = detail.nonce_signature || '';
            }
        });
    }

    // ── 2FA fingerprint-request template (request-fingerprint.php) ───────

    const fpRequestBtn   = document.getElementById('capauth-2fa-fp-btn');
    const fpRequestInput = document.getElementById('capauth-2fa-fingerprint');
    const fpRequestError = document.getElementById('capauth-2fa-fp-error');

    if (fpRequestBtn) {
        fpRequestBtn.addEventListener('click', async function () {
            hideError(fpRequestError);
            const fp = fpRequestInput.value.trim().toUpperCase();
            if (fp.length !== 40 || !/^[0-9A-F]+$/.test(fp)) {
                showError(fpRequestError, 'Enter a valid 40-character fingerprint.');
                return;
            }
            // Reload the page with fingerprint as query param so the provider
            // can issue a challenge on the next GET.
            const url = new URL(window.location.href);
            url.searchParams.set('fingerprint', fp);
            window.location.href = url.toString();
        });

        if (fpRequestInput) {
            fpRequestInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') fpRequestBtn.click();
            });
        }
    }

    // ── Copy challenge button (2FA template) ─────────────────────────────

    const copyChallengeBtn = document.getElementById('capauth-copy-challenge');
    const challengePayloadEl = document.getElementById('capauth-challenge-payload');

    if (copyChallengeBtn && challengePayloadEl) {
        copyChallengeBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(challengePayloadEl.textContent).then(() => {
                copyChallengeBtn.textContent = 'Copied!';
                setTimeout(() => { copyChallengeBtn.textContent = 'Copy'; }, 2000);
            });
        });
    }
})();
