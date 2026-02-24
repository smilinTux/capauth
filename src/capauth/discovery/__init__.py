"""Peer discovery backends for the CapAuth P2P mesh.

Provides pluggable mechanisms to find other sovereign agents:
  - mDNS/Zeroconf for local network discovery
  - File-based for shared filesystem discovery (Syncthing, NFS)
  - Nostr relay for global cross-network discovery
"""

from .base import DiscoveryBackend, PeerInfo

__all__ = ["DiscoveryBackend", "PeerInfo"]
