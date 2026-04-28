"""File-based peer discovery for shared filesystems.

Discovers peers by reading presence files from a shared directory.
Works over Syncthing, NFS, SSHFS, Nextcloud sync — any shared
filesystem. The sneakernet approach to peer discovery.

Each peer writes a JSON presence file to the shared directory.
Other peers read those files to discover who's available.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .. import resolve_capauth_home
from .base import DiscoveryBackend, PeerInfo

logger = logging.getLogger("capauth.discovery.file")

PRESENCE_SUFFIX = ".capauth.json"
DEFAULT_DIR = resolve_capauth_home() / "mesh" / "peers"
STALE_SECONDS = 300


class FileDiscovery(DiscoveryBackend):
    """Discover peers via presence files in a shared directory.

    Each peer writes a ``<fingerprint>.capauth.json`` file to the
    shared directory. Peers scan the directory to discover others.
    Stale presence files (older than ``stale_seconds``) are ignored.
    """

    def __init__(
        self,
        shared_dir: Optional[Path] = None,
        stale_seconds: int = STALE_SECONDS,
    ) -> None:
        self._dir = Path(shared_dir).expanduser() if shared_dir else DEFAULT_DIR
        self._stale_seconds = stale_seconds
        self._running = False

    @property
    def name(self) -> str:
        return "file"

    def available(self) -> bool:
        """Always available — just needs a filesystem."""
        return True

    def start(self) -> None:
        """Ensure the shared directory exists."""
        self._dir.mkdir(parents=True, exist_ok=True)
        self._running = True
        logger.info("File discovery started at %s", self._dir)

    def stop(self) -> None:
        """Nothing to clean up for file-based discovery."""
        self._running = False

    def announce(self, peer: PeerInfo) -> bool:
        """Write a presence file for ourselves.

        Args:
            peer: Our PeerInfo to announce.

        Returns:
            True if the file was written successfully.
        """
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            path = self._dir / f"{peer.fingerprint[:16]}{PRESENCE_SUFFIX}"
            data = peer.model_dump(mode="json")
            data["last_seen"] = datetime.now(timezone.utc).isoformat()
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            logger.debug("Wrote presence file %s", path.name)
            return True
        except Exception as exc:
            logger.warning("Failed to write presence file: %s", exc)
            return False

    def discover(self, timeout_ms: int = 5000) -> list[PeerInfo]:
        """Read presence files to discover peers.

        Args:
            timeout_ms: Ignored for file-based discovery.

        Returns:
            List of non-stale PeerInfo objects.
        """
        if not self._dir.exists():
            return []

        peers: list[PeerInfo] = []
        now = time.time()

        for f in self._dir.glob(f"*{PRESENCE_SUFFIX}"):
            try:
                age = now - f.stat().st_mtime
                if age > self._stale_seconds:
                    continue

                data = json.loads(f.read_text(encoding="utf-8"))
                peer = PeerInfo.model_validate(data)
                peer.discovery_method = "file"
                peers.append(peer)
            except (json.JSONDecodeError, Exception) as exc:
                logger.debug("Skipping %s: %s", f.name, exc)

        return peers
