# Releasing the CapAuth Browser Extension

This doc covers how to build, package, and publish the CapAuth browser extension
for Chrome (Manifest V3) and Firefox.

---

## Prerequisites

```bash
cd browser-extension
npm ci          # install deps from the lockfile
```

Node 18+ required. No `vsce` — this is a browser extension, not a VSCode extension.
Chrome uses `.zip`, Firefox uses `.xpi`.

---

## Version bump

1. Edit `manifest.json` — update `"version"` field.
2. Edit `package.json` — update `"version"` to match.
3. Commit: `git commit -m "chore: bump extension to vX.Y.Z"`
4. Tag: `git tag browser-extension/vX.Y.Z`

Keep `manifest.json` and `package.json` in sync — they must have the same version.

---

## Building

### Chrome (Manifest V3)

```bash
npm run build
# Output: dist/chrome/
```

### Firefox (Manifest V2 shim)

```bash
npm run build:firefox
# Output: dist/firefox/
```

### Icons (only needed when adding new icon sizes)

```bash
npm run build:icons
```

---

## Packaging

### Chrome — create a zip

```bash
cd dist/chrome
zip -r ../../capauth-extension-vX.Y.Z.zip .
```

Upload the zip to the [Chrome Web Store developer dashboard](https://chrome.google.com/webstore/devconsole).

### Firefox — create an xpi

```bash
cd dist/firefox
zip -r ../../capauth-extension-vX.Y.Z.xpi .
```

Upload the xpi to [Firefox Add-on Developer Hub](https://addons.mozilla.org/en-US/developers/).

---

## Checklist before publishing

- [ ] `manifest.json` and `package.json` versions match
- [ ] `npm run build` completes without errors
- [ ] Manual smoke test: load unpacked extension, log into a CapAuth-protected service
- [ ] Firefox build tested in about:debugging
- [ ] CHANGELOG or commit message documents what changed
- [ ] Git tag pushed: `git push origin browser-extension/vX.Y.Z`

---

## Unpacked load for testing

**Chrome:** `chrome://extensions` → Enable Developer mode → Load unpacked → select `dist/chrome/`

**Firefox:** `about:debugging` → This Firefox → Load Temporary Add-on → select `dist/firefox/manifest.json`
