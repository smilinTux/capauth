"""GnuPG (system gpg2) crypto backend for CapAuth.

Optional backend for power users who want hardware key support,
existing GPG keyring integration, or battle-tested system crypto.
Requires ``pip install capauth[gnupg]`` and system gpg2.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from ..exceptions import BackendError, KeyGenerationError
from ..models import Algorithm
from .base import CryptoBackend, KeyBundle


class GnuPGBackend(CryptoBackend):
    """System GnuPG backend wrapping python-gnupg.

    Uses an isolated GNUPGHOME by default so CapAuth keys don't
    pollute the user's main keyring. Pass ``gnupg_home`` to
    share a keyring with the system.
    """

    def __init__(self, gnupg_home: Optional[str] = None) -> None:
        """Initialize the GnuPG backend.

        Args:
            gnupg_home: Path to GNUPGHOME. Uses a temp dir if None.
        """
        self._gnupg_home = gnupg_home
        self._gpg: Optional[object] = None

    def _get_gpg(self) -> object:
        """Lazy-initialize the GPG wrapper.

        Returns:
            gnupg.GPG: Configured GPG instance.

        Raises:
            BackendError: If python-gnupg is not installed.
        """
        if self._gpg is not None:
            return self._gpg  # type: ignore[return-value]

        try:
            import gnupg
        except ImportError as exc:
            raise BackendError(
                "python-gnupg not installed. Run: pip install capauth[gnupg]"
            ) from exc

        home = self._gnupg_home or tempfile.mkdtemp(prefix="capauth_gpg_")
        self._gpg = gnupg.GPG(gnupghome=home)
        return self._gpg  # type: ignore[return-value]

    def available(self) -> bool:
        """Check if python-gnupg and system gpg2 are available.

        Returns:
            bool: True if both the library and binary are usable.
        """
        try:
            gpg = self._get_gpg()
            return gpg.encoding is not None
        except Exception:
            return False

    def generate_keypair(
        self,
        name: str,
        email: str,
        passphrase: str,
        algorithm: Algorithm = Algorithm.RSA4096,
    ) -> KeyBundle:
        """Generate a PGP keypair via system gpg2.

        Args:
            name: Display name for the UID.
            email: Email address for the UID.
            passphrase: Passphrase to protect the private key.
            algorithm: Ed25519 or RSA-4096.

        Returns:
            KeyBundle: Generated key material.

        Raises:
            KeyGenerationError: On gpg failure.
        """
        gpg = self._get_gpg()

        if algorithm == Algorithm.ED25519:
            key_type = "eddsa"
            key_curve = "ed25519"
            key_length = 0
        else:
            key_type = "RSA"
            key_curve = None
            key_length = 4096

        try:
            input_data = gpg.gen_key_input(
                key_type=key_type,
                key_length=key_length if key_length else None,
                key_curve=key_curve,
                name_real=name,
                name_email=email,
                passphrase=passphrase,
            )
            result = gpg.gen_key(input_data)

            if not result.ok:
                raise KeyGenerationError(f"gpg key generation failed: {result.stderr}")

            fingerprint = str(result)
            public_armor = gpg.export_keys(fingerprint, armor=True)
            private_armor = gpg.export_keys(
                fingerprint, secret=True, armor=True, passphrase=passphrase
            )

            if not public_armor or not private_armor:
                raise KeyGenerationError("gpg export returned empty key armor")

            return KeyBundle(
                fingerprint=fingerprint,
                public_armor=public_armor,
                private_armor=private_armor,
                algorithm=algorithm,
            )
        except KeyGenerationError:
            raise
        except Exception as exc:
            raise KeyGenerationError(f"gpg key generation failed: {exc}") from exc

    def sign(
        self,
        data: bytes,
        private_key_armor: str,
        passphrase: str,
    ) -> str:
        """Sign data using system gpg2.

        Imports the private key into an isolated keyring, signs,
        then the keyring is discarded (if using temp home).

        Args:
            data: Raw bytes to sign.
            private_key_armor: ASCII-armored private key.
            passphrase: Passphrase to unlock the key.

        Returns:
            str: ASCII-armored detached signature.

        Raises:
            BackendError: On signing failure.
        """
        gpg = self._get_gpg()

        try:
            import_result = gpg.import_keys(private_key_armor)
            if not import_result.ok:
                raise BackendError(f"Failed to import private key: {import_result.stderr}")

            fingerprint = import_result.fingerprints[0]
            sig = gpg.sign(
                data, keyid=fingerprint, passphrase=passphrase, detach=True, binary=False
            )

            if not sig or not sig.data:
                raise BackendError(f"gpg signing failed: {sig.stderr}")

            return str(sig)
        except BackendError:
            raise
        except Exception as exc:
            raise BackendError(f"gpg signing failed: {exc}") from exc

    def verify(
        self,
        data: bytes,
        signature_armor: str,
        public_key_armor: str,
    ) -> bool:
        """Verify a detached signature using system gpg2.

        Args:
            data: Original bytes that were signed.
            signature_armor: ASCII-armored signature.
            public_key_armor: ASCII-armored public key.

        Returns:
            bool: True if valid.
        """
        gpg = self._get_gpg()

        try:
            gpg.import_keys(public_key_armor)

            with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sig_file:
                sig_file.write(signature_armor.encode())
                sig_path = sig_file.name

            with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as data_file:
                data_file.write(data)
                data_path = data_file.name

            verified = gpg.verify_data(sig_path, data)

            Path(sig_path).unlink(missing_ok=True)
            Path(data_path).unlink(missing_ok=True)

            return bool(verified.valid)
        except Exception:
            return False

    def fingerprint_from_armor(self, key_armor: str) -> str:
        """Extract fingerprint from key armor via gpg import.

        Args:
            key_armor: ASCII-armored key.

        Returns:
            str: 40-character hex fingerprint.

        Raises:
            BackendError: If parsing fails.
        """
        gpg = self._get_gpg()

        try:
            result = gpg.import_keys(key_armor)
            if result.fingerprints:
                return result.fingerprints[0]
            raise BackendError("No fingerprint found in key armor")
        except BackendError:
            raise
        except Exception as exc:
            raise BackendError(f"Failed to parse key armor: {exc}") from exc
