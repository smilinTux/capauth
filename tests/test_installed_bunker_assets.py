"""Clean-wheel checks for the installed Bunker setup page."""

from __future__ import annotations

import hashlib
import os
import site
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WHEEL_ENV = "CAPAUTH_TEST_WHEEL"
ASSETS = (
    "app.js",
    "index.html",
    "manifest.webmanifest",
    "sw.js",
    "icons/icon-192.png",
    "icons/icon-512.png",
    "lib/bunker-e2e.js",
    "lib/bunker-signer.js",
    "lib/canonical.js",
    "lib/keyqr.js",
    "lib/keyvault.js",
    "vendor/openpgp.min.js",
    "vendor/qrcode-generator.js",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wheel() -> Path:
    raw = os.environ.get(WHEEL_ENV)
    if not raw:
        pytest.skip(f"{WHEEL_ENV} is required for clean-wheel checks")
    wheel = Path(raw).resolve()
    assert wheel.is_file()
    return wheel


def test_wheel_contains_one_byte_exact_phone_signer_tree() -> None:
    wheel = _wheel()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        for relative in ASSETS:
            matches = [name for name in names if name.endswith(f"/phone-signer/{relative}")]
            assert len(matches) == 1
            assert _sha256(archive.read(matches[0])) == _sha256(
                (ROOT / "phone-signer" / relative).read_bytes()
            )
        assert not any("capauth/service/oidc/static/bunker/" in name for name in names)


def test_clean_wheel_serves_every_asset_and_rejects_traversal(tmp_path: Path) -> None:
    wheel = _wheel()
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / "bin" / "python"

    parent_site = next(path for path in site.getsitepackages() if Path(path).is_dir())
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    child_site = environment / "lib" / version / "site-packages"
    (child_site / "capauth-test-dependencies.pth").write_text(f"{parent_site}\n")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
        check=True,
        capture_output=True,
        text=True,
    )

    script = f"""
import asyncio
from pathlib import Path
from fastapi import HTTPException
from fastapi.testclient import TestClient
import capauth
import capauth.service.app as service

assert Path(capauth.__file__).resolve().is_relative_to(Path({str(environment)!r}))
service._PHONE_SIGNER_DIR = Path('/source-tree-is-absent')
client = TestClient(service.app)
for asset in {ASSETS!r}:
    response = client.get('/bunker/' + asset)
    assert response.status_code == 200, (asset, response.status_code)
    assert response.content
page = client.get('/bunker/?mode=setup')
assert page.status_code == 200
assert b'Load your existing identity' in page.content
for asset in ('../outside.txt', '../../../pyproject.toml'):
    try:
        asyncio.run(service.phone_signer_asset(asset))
    except HTTPException as error:
        assert error.status_code == 403
    else:
        raise AssertionError(asset)
"""
    subprocess.run(
        [str(python), "-I", "-c", script],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
