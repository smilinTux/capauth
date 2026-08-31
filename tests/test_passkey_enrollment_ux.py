"""Focused source checks for the guided passkey enrollment workflow."""

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_bunker_guides_browser_identity_setup() -> None:
    """The linked setup path stays short and returns to passkey enrollment."""
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
    assert "requestedNext" not in controller
    assert "safeNext" not in controller


def test_bunker_masks_every_secret_and_supports_explicit_reveal() -> None:
    page = (ROOT / "phone-signer" / "index.html").read_text()
    for field in ("pgp-pass", "vault-pass", "vault-pass-confirm", "xfer-pin", "unlock-pass"):
        assert f'id="{field}" type="password"' in page
        assert f'data-secret-target="{field}"' in page
    assert page.count('spellcheck="false" autocapitalize="none"') >= 5
    assert page.count('aria-pressed="false">Show</button>') >= 5

    controller = (ROOT / "phone-signer" / "app.js").read_text()
    assert "function requestMaskedSecret" in controller
    assert "function setSecretVisibility" in controller
    assert 'input.type = showing ? "text" : "password"' in controller
    assert 'prompt("This key has a PGP passphrase' not in controller
    assert 'prompt("Enter the Transfer PIN' not in controller
    assert 'register("sw.js?v=4")' in controller

    worker = (ROOT / "phone-signer" / "sw.js").read_text()
    assert 'const CACHE = "capauth-bunker-v6"' in worker
