# CapAuth — Chrome Web Store & Firefox AMO Submission

## Extension Name
CapAuth - Sovereign Login

## Short Description (132 chars max)
One-click passwordless login using your PGP key. No passwords, no tracking — just sovereign authentication.

## Full Description

**CapAuth** brings passwordless, PGP-based authentication to your browser. Instead of typing passwords, you sign a cryptographic challenge with your PGP key — the same key you use for encrypted email and file signing.

### How it works
1. Visit any CapAuth-enabled service (Nextcloud, Gitea, Authentik, custom apps)
2. Click the CapAuth button on the login page — or use the popup
3. Your PGP key signs a one-time challenge nonce
4. The service verifies the signature and issues a JWT session token

**Your private key never leaves your browser.**

### Features
- **One-click sovereign login** — no passwords to type or remember
- **PGP-native** — uses OpenPGP.js for all crypto operations
- **OIDC-compatible** — services receive a standard JWT with profile claims
- **Token caching** — avoids re-signing for repeated visits within the token TTL
- **Auto-detection** — injects a "Sign in with CapAuth" button on compatible pages
- **QR login** — scan a QR code from your phone for desktop browser auth
- **Firefox + Chrome** — works on both browsers

### Privacy
CapAuth sends only your PGP fingerprint and a signed nonce to the service. No analytics, no telemetry, no third-party requests. All storage is local (`chrome.storage.local`).

### Permissions
- **activeTab**: Inject the sign-in button on the current tab
- **storage**: Store your fingerprint and cached tokens locally
- **scripting**: Detect CapAuth-enabled login pages
- **alarms**: Clean up expired token cache every 5 minutes
- **Host permissions** (*.capauth.io, *.skworld.io): Communicate with CapAuth verification endpoints

### Source code
https://github.com/smilintux/skworld/tree/main/capauth/browser-extension

---

## Category
Productivity / Privacy & Security

## Language
English

## Version
0.1.0

## Homepage URL
https://capauth.io

---

## Chrome Web Store Checklist
- [ ] `dist/capauth-chrome-0.1.0.zip` — extension package
- [ ] Screenshots (1280x800 or 640x400): at least 1, up to 5
- [ ] Store icon: 128x128 PNG (icons/icon128.png)
- [ ] Promotional tile (optional): 440x280 PNG
- [ ] Privacy policy URL: https://capauth.io/privacy

## Firefox AMO Checklist
- [ ] `dist/capauth-firefox-0.1.0.zip` — extension package
- [ ] Source code zip (required for review): `npm run build` reproducible
- [ ] Screenshots: at least 1
- [ ] Developer comments for reviewers (see REVIEWER_NOTES.md)

---

## Reviewer Notes (Firefox AMO)

The extension uses `openpgp` (OpenPGP.js v5) bundled into `lib/openpgp-bundle.js`
via esbuild. The build is reproducible:

```bash
cd capauth/browser-extension
npm install
npm run build:firefox
# Output: dist/capauth-firefox-0.1.0.zip
```

The `lib/openpgp-bundle.js` file is a bundled copy of the published
`openpgp` npm package (MIT license). No obfuscation is applied.

The background script (`background.js`) is a plain ES module service worker.
It uses no eval, no remote code execution, and no dynamic imports beyond
the bundled openpgp module.
