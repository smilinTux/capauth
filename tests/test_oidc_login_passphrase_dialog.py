"""The browser-vault passphrase must never be collected with window.prompt().

prompt() cannot mask input, so the vault passphrase used to echo in clear text.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from capauth.service.oidc.provider import _BUNKER_LOGIN_JS


def _code_only(js: str) -> str:
    return "\n".join(line for line in js.splitlines() if not line.lstrip().startswith("//"))


def test_no_window_prompt_collects_the_passphrase():
    assert not re.search(r"(?<![\w.])prompt\s*\(", _code_only(_BUNKER_LOGIN_JS))


def test_passphrase_dialog_is_masked_and_modal():
    code = _code_only(_BUNKER_LOGIN_JS)
    assert 'input.type = "password"' in code
    assert "showModal()" in code
    assert code.count("await unlockStoredKey(env)") == 2  # sign-in and passkey proof
    assert "innerHTML" not in code


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_login_module_parses(tmp_path):
    module = tmp_path / "bunker_login.mjs"
    module.write_text(_BUNKER_LOGIN_JS, encoding="utf-8")
    result = subprocess.run(["node", "--check", str(module)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
