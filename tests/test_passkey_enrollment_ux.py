"""Focused source checks for the guided passkey enrollment workflow."""

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_bunker_guides_browser_identity_setup() -> None:
    """The linked setup path stays short and allows a bounded login return."""
    page = (ROOT / "phone-signer" / "index.html").read_text()
    assert "Load your existing identity" in page
    assert "Choose your armored PGP private key file" in page
    assert "jarvis-private.asc" in page
    assert "Enter the browser vault passphrase again" in page
    assert "Continue to passkey setup" in page
    assert "Advanced: unlock for remote signing" in page

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
