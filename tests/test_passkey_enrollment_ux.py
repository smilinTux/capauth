"""Focused source checks for the guided passkey enrollment workflow."""

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_bunker_guides_browser_identity_setup() -> None:
    """The linked setup path stays short and allows a bounded login return."""
    page = (ROOT / "phone-signer" / "index.html").read_text()
    assert "Load your existing identity" in page
    assert "Choose your identity file" in page
    assert "CapAuth encrypted backup" in page
    assert "jarvis-private.asc" in page
    assert "Enter the browser vault passphrase again" in page
    assert "Continue to passkey setup" in page
    assert "Advanced: unlock for remote signing" in page
    assert "Manage identity on this device" in page
    assert "Download encrypted backup" in page
    assert "Replace identity" in page
    assert "Remove from this browser" in page
    assert "never exports an unencrypted private key" in page

    controller = (ROOT / "phone-signer" / "app.js").read_text()
    assert 'new URLSearchParams(location.search).get("mode") === "setup"' in controller
    assert '$("pair-card").classList.add("hidden")' in controller
    assert '$("continue-passkey").classList.remove("hidden")' in controller
    assert "vaultPass !== vaultConfirm" in controller
    assert 'const RETURN_KEY = "capauth_bunker_return"' in controller
    assert "target.origin !== location.origin" in controller
    assert 'target.pathname !== "/oidc/authorize"' in controller
    assert "raw.length > 2048" in controller
    assert "/[\\u0000-\\u001F\\u007F]/" in controller
    assert "target.username" in controller
    assert "target.password" in controller
    assert "target.hash" in controller
    assert "location.assign(returnTo)" in controller
    assert "isEncryptedEnvelope(parsed)" in controller
    assert "encryptedEnvelope: parsed" in controller
    assert "backup.version !== 1" in controller
    assert "isEncryptedEnvelope(backup.encryptedEnvelope)" in controller
    assert "Encrypted identity restored" in controller
    assert 'confirm("Remove this encrypted identity from this browser?' in controller
    assert "confirm(\"Replace this browser's encrypted identity?" in controller
