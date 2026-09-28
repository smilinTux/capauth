"""The service image must build from a plain checkout (no .git in the build
context: .dockerignore excludes it). setuptools-scm cannot find a version
there, so the Dockerfile has to hand it one before `pip install`."""

from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def test_version_is_pinned_before_pip_install():
    lines = [ln.strip() for ln in DOCKERFILE.read_text().splitlines()]
    install = next(i for i, ln in enumerate(lines) if ln.startswith("RUN pip install") and "-e" in ln)
    before = lines[:install]
    assert any(ln.startswith("ARG CAPAUTH_VERSION") for ln in before)
    assert "ENV SETUPTOOLS_SCM_PRETEND_VERSION=${CAPAUTH_VERSION}" in before
