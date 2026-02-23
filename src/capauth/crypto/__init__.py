"""Crypto backend abstraction for CapAuth.

Provides a factory function to get the right backend based on
user preference: PGPy (default, pure-Python) or GnuPG (optional,
wraps system gpg2 for hardware key support).
"""

from __future__ import annotations

from ..models import CryptoBackendType
from .base import CryptoBackend, KeyBundle
from .pgpy_backend import PGPyBackend

__all__ = ["get_backend", "CryptoBackend", "KeyBundle"]


def get_backend(backend_type: CryptoBackendType = CryptoBackendType.PGPY) -> CryptoBackend:
    """Factory: return the requested crypto backend.

    Args:
        backend_type: Which backend to use. Defaults to PGPy.

    Returns:
        CryptoBackend: A ready-to-use backend instance.

    Raises:
        BackendError: If the requested backend is unavailable.
    """
    if backend_type == CryptoBackendType.GNUPG:
        from .gnupg_backend import GnuPGBackend

        backend = GnuPGBackend()
        if not backend.available():
            from ..exceptions import BackendError

            raise BackendError(
                "GnuPG backend unavailable. Install: pip install capauth[gnupg] "
                "and ensure gpg2 is on PATH."
            )
        return backend

    return PGPyBackend()
