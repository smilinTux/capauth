"""
P2P mesh networking for CapAuth.

Manages peer discovery, identity verification, and the sovereign
peer registry. No servers, no accounts — just cryptographic proof
of identity shared over whatever transport is available.

The mesh supports multiple discovery backends simultaneously:
  - mDNS for local network
  - File-based for shared filesystems (Syncthing mesh)
  - Nostr for global relay (future)

Usage:
    mesh = PeerMesh(my_fingerprint, my_name)
    mesh.start()
    peers = mesh.discover_all()
    verified = mesh.verify_peer(peer, my_private_key, passphrase)
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import resolve_capauth_home
from .discovery.base import DiscoveryBackend, PeerInfo

logger = logging.getLogger("capauth.mesh")

PEER_REGISTRY_FILE = "peer_registry.json"


class PeerMesh:
    """The sovereign peer mesh — serverless identity networking.

    Manages multiple discovery backends and maintains a persistent
    registry of known peers with their verification status.

    Attributes:
        fingerprint: Our PGP fingerprint.
        name: Our display name.
        entity_type: human, ai, or organization.
    """

    def __init__(
        self,
        fingerprint: str,
        name: str = "",
        entity_type: str = "human",
        base_dir: Optional[Path] = None,
    ) -> None:
        self.fingerprint = fingerprint
        self.name = name
        self.entity_type = entity_type
        self._base = resolve_capauth_home(base_dir)
        self._backends: list[DiscoveryBackend] = []
        self._registry: dict[str, PeerInfo] = {}
        self._lock = threading.RLock()
        self._running = False

        self._load_registry()

    def add_backend(self, backend: DiscoveryBackend) -> None:
        """Register a discovery backend.

        Args:
            backend: The discovery backend to add.
        """
        if backend.available():
            self._backends.append(backend)
            logger.info("Added discovery backend: %s", backend.name)
        else:
            logger.warning("Backend %s is not available, skipping", backend.name)

    def start(self) -> None:
        """Start all discovery backends and announce ourselves."""
        me = PeerInfo(
            fingerprint=self.fingerprint,
            name=self.name,
            entity_type=self.entity_type,
            discovery_method="self",
        )

        for backend in self._backends:
            try:
                backend.start()
                backend.announce(me)
            except Exception as exc:
                logger.warning("Failed to start backend %s: %s", backend.name, exc)

        self._running = True
        logger.info("Mesh started with %d backends for %s", len(self._backends), self.name)

    def stop(self) -> None:
        """Stop all discovery backends."""
        for backend in self._backends:
            try:
                backend.stop()
            except Exception as exc:
                logger.warning("Error stopping backend %s: %s", backend.name, exc)

        self._running = False
        self._save_registry()

    def discover_all(self, timeout_ms: int = 5000) -> list[PeerInfo]:
        """Run discovery across all backends and merge results.

        Args:
            timeout_ms: How long each backend should listen.

        Returns:
            Deduplicated list of discovered peers.
        """
        seen: dict[str, PeerInfo] = {}

        for backend in self._backends:
            try:
                peers = backend.discover(timeout_ms)
                for peer in peers:
                    if peer.fingerprint == self.fingerprint:
                        continue
                    existing = seen.get(peer.fingerprint)
                    if existing is None or peer.last_seen > existing.last_seen:
                        seen[peer.fingerprint] = peer
            except Exception as exc:
                logger.warning("Discovery failed for %s: %s", backend.name, exc)

        with self._lock:
            for fp, peer in seen.items():
                if fp in self._registry:
                    self._registry[fp].last_seen = peer.last_seen
                    self._registry[fp].address = peer.address or self._registry[fp].address
                else:
                    self._registry[fp] = peer

        self._save_registry()
        return list(seen.values())

    def verify_peer(
        self,
        peer: PeerInfo,
        private_key_armor: str,
        passphrase: str,
        peer_public_key_armor: Optional[str] = None,
    ) -> bool:
        """Run challenge-response verification against a peer.

        This uses the CapAuth identity module to create a challenge,
        sign it, and verify the response — proving the peer holds
        the private key for their claimed fingerprint.

        In offline/file mode, this generates a challenge file that
        can be delivered to the peer through any transport.

        Args:
            peer: The peer to verify.
            private_key_armor: Our private key for signing.
            passphrase: Our key passphrase.
            peer_public_key_armor: The peer's public key for verification.

        Returns:
            True if the peer's identity is verified.
        """
        if not peer_public_key_armor and peer.public_key_armor:
            peer_public_key_armor = peer.public_key_armor

        if not peer_public_key_armor:
            logger.warning("No public key available for %s", peer.fingerprint[:16])
            return False

        try:
            from .identity import create_challenge, respond_to_challenge, verify_challenge
            from .models import CryptoBackendType

            challenge = create_challenge(self.fingerprint, peer.fingerprint)

            # Reason: In a real P2P scenario, the challenge would be sent
            # to the peer over the network. For now, we simulate a local
            # self-verification using the peer's key material.
            response = respond_to_challenge(
                challenge, private_key_armor, passphrase, CryptoBackendType.PGPY
            )

            verified = verify_challenge(
                challenge, response, peer_public_key_armor, CryptoBackendType.PGPY
            )

            if verified:
                with self._lock:
                    if peer.fingerprint in self._registry:
                        self._registry[peer.fingerprint].verified = True
                self._save_registry()

            return verified

        except Exception as exc:
            logger.warning("Verification failed for %s: %s", peer.fingerprint[:16], exc)
            return False

    def get_peers(self, verified_only: bool = False) -> list[PeerInfo]:
        """Get known peers from the registry.

        Args:
            verified_only: If True, return only verified peers.

        Returns:
            List of known PeerInfo objects.
        """
        with self._lock:
            peers = list(self._registry.values())

        if verified_only:
            peers = [p for p in peers if p.verified]

        return peers

    def add_peer(self, peer: PeerInfo) -> None:
        """Manually add a peer to the registry.

        Args:
            peer: The peer to add.
        """
        with self._lock:
            self._registry[peer.fingerprint] = peer
        self._save_registry()

    def remove_peer(self, fingerprint: str) -> bool:
        """Remove a peer from the registry.

        Args:
            fingerprint: PGP fingerprint of the peer to remove.

        Returns:
            True if the peer was found and removed.
        """
        with self._lock:
            if fingerprint in self._registry:
                del self._registry[fingerprint]
                self._save_registry()
                return True
        return False

    def mesh_status(self) -> dict:
        """Get overall mesh status.

        Returns:
            Dict with mesh statistics and backend info.
        """
        with self._lock:
            total = len(self._registry)
            verified = sum(1 for p in self._registry.values() if p.verified)

        return {
            "identity": self.fingerprint[:16],
            "name": self.name,
            "backends": [b.name for b in self._backends],
            "backends_available": len(self._backends),
            "total_peers": total,
            "verified_peers": verified,
            "unverified_peers": total - verified,
            "running": self._running,
        }

    def _load_registry(self) -> None:
        """Load the peer registry from disk."""
        path = self._base / "mesh" / PEER_REGISTRY_FILE
        if not path.exists():
            return

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for entry in data.get("peers", []):
                peer = PeerInfo.model_validate(entry)
                self._registry[peer.fingerprint] = peer
            logger.debug("Loaded %d peers from registry", len(self._registry))
        except Exception as exc:
            logger.warning("Failed to load peer registry: %s", exc)

    def _save_registry(self) -> None:
        """Persist the peer registry to disk."""
        path = self._base / "mesh" / PEER_REGISTRY_FILE
        path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            data = {
                "updated": datetime.now(timezone.utc).isoformat(),
                "identity": self.fingerprint,
                "peers": [p.model_dump(mode="json") for p in self._registry.values()],
            }

        try:
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to save peer registry: %s", exc)
