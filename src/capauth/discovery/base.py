"""Abstract base for peer discovery backends.

Every discovery mechanism — mDNS, file-based, Nostr relay — implements
this interface so the mesh layer can discover peers without caring
about the underlying transport.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("capauth.discovery")


class PeerInfo(BaseModel):
    """Information about a discovered peer.

    Attributes:
        fingerprint: The peer's PGP fingerprint.
        name: The peer's display name.
        entity_type: human, ai, or organization.
        address: Network address (IP:port, relay URL, file path, etc.).
        discovery_method: How we found this peer (mdns, file, nostr).
        last_seen: When the peer was last detected.
        verified: Whether identity has been cryptographically verified.
        public_key_armor: The peer's public key, if available.
    """

    fingerprint: str
    name: str = ""
    entity_type: str = "unknown"
    address: str = ""
    discovery_method: str = "manual"
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False
    public_key_armor: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class DiscoveryBackend(ABC):
    """Abstract interface for peer discovery mechanisms."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short name of this discovery backend (e.g. 'mdns', 'file', 'nostr')."""

    @abstractmethod
    def start(self) -> None:
        """Start the discovery service.

        This may launch background threads for listening.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop the discovery service and clean up."""

    @abstractmethod
    def announce(self, peer: PeerInfo) -> bool:
        """Announce our presence so other peers can discover us.

        Args:
            peer: Our own PeerInfo to broadcast.

        Returns:
            True if announcement succeeded.
        """

    @abstractmethod
    def discover(self, timeout_ms: int = 5000) -> list[PeerInfo]:
        """Discover peers on the network.

        Args:
            timeout_ms: How long to listen for responses.

        Returns:
            List of discovered peers.
        """

    @abstractmethod
    def available(self) -> bool:
        """Check if this backend's dependencies are present.

        Returns:
            True if the backend can be used.
        """
