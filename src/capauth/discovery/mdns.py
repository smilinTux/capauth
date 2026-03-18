"""mDNS/Zeroconf peer discovery for local network mesh.

Announces and discovers CapAuth peers on the local network using
multicast DNS. No server, no configuration — just plug in and
find your peers.

Service type: _capauth._tcp.local.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Optional

from .base import DiscoveryBackend, PeerInfo

logger = logging.getLogger("capauth.discovery.mdns")

SERVICE_TYPE = "_capauth._tcp.local."
DEFAULT_PORT = 7778


class MDNSDiscovery(DiscoveryBackend):
    """Discover peers via mDNS/Zeroconf on the local network.

    Registers a ``_capauth._tcp`` service with the peer's fingerprint
    and name in the TXT record. Other CapAuth instances on the same
    LAN will see it automatically.
    """

    _zc: Optional[object] = None
    _info: Optional[object] = None
    _browser: Optional[object] = None
    _lock: threading.Lock
    _peers: dict[str, PeerInfo]

    def __init__(self, port: int = DEFAULT_PORT) -> None:
        self._port = port
        self._lock = threading.Lock()
        self._peers = {}
        self._running = False

    @property
    def name(self) -> str:
        return "mdns"

    def available(self) -> bool:
        """Check if zeroconf is installed."""
        try:
            import zeroconf  # noqa: F401

            return True
        except ImportError:
            return False

    def start(self) -> None:
        """Start the mDNS service browser."""
        if self._running:
            return

        try:
            from zeroconf import ServiceBrowser, Zeroconf

            self._zc = Zeroconf()
            self._browser = ServiceBrowser(self._zc, SERVICE_TYPE, self)
            self._running = True
            logger.info("mDNS discovery started (listening for %s)", SERVICE_TYPE)
        except Exception as exc:
            logger.warning("Failed to start mDNS discovery: %s", exc)

    def stop(self) -> None:
        """Stop the mDNS service and unregister."""
        if not self._running:
            return

        try:
            from zeroconf import Zeroconf

            if self._info and self._zc:
                self._zc.unregister_service(self._info)
            if self._zc:
                self._zc.close()
        except Exception as exc:
            logger.warning("Error stopping mDNS: %s", exc)
        finally:
            self._running = False
            self._zc = None
            self._info = None
            self._browser = None

    def announce(self, peer: PeerInfo) -> bool:
        """Register our presence on the local network.

        Args:
            peer: Our PeerInfo to announce.

        Returns:
            True if registration succeeded.
        """
        if not self.available():
            return False

        try:
            from zeroconf import ServiceInfo

            hostname = socket.gethostname()
            service_name = f"{peer.fingerprint[:16]}.{SERVICE_TYPE}"

            properties = {
                b"fingerprint": peer.fingerprint.encode(),
                b"name": peer.name.encode(),
                b"entity_type": peer.entity_type.encode(),
            }
            if peer.public_key_armor:
                # Reason: TXT records have a 255-byte limit per value,
                # so we only store a truncated key hint, not the full armor.
                properties[b"pubkey_hint"] = peer.public_key_armor[:200].encode()

            addr = socket.inet_aton(self._get_local_ip())

            self._info = ServiceInfo(
                SERVICE_TYPE,
                service_name,
                addresses=[addr],
                port=self._port,
                properties=properties,
                server=f"{hostname}.local.",
            )

            if not self._zc:
                from zeroconf import Zeroconf

                self._zc = Zeroconf()

            self._zc.register_service(self._info)
            logger.info("Announced %s on mDNS", peer.name)
            return True

        except Exception as exc:
            logger.warning("Failed to announce via mDNS: %s", exc)
            return False

    def discover(self, timeout_ms: int = 5000) -> list[PeerInfo]:
        """Return all peers discovered so far.

        Args:
            timeout_ms: Additional time to wait for late responses.

        Returns:
            List of discovered PeerInfo objects.
        """
        if not self._running:
            self.start()
            time.sleep(timeout_ms / 1000.0)

        with self._lock:
            return list(self._peers.values())

    def add_service(self, zc: object, type_: str, name: str) -> None:
        """Zeroconf callback: new service found.

        Args:
            zc: The Zeroconf instance.
            type_: Service type string.
            name: Full service name.
        """
        try:
            info = zc.get_service_info(type_, name)  # type: ignore[attr-defined]
            if info is None:
                return

            props = {
                k.decode() if isinstance(k, bytes) else k: v.decode()
                if isinstance(v, bytes)
                else v
                for k, v in (info.properties or {}).items()
            }

            fingerprint = props.get("fingerprint", "")
            if not fingerprint:
                return

            addresses = info.parsed_addresses()
            addr = f"{addresses[0]}:{info.port}" if addresses else ""

            peer = PeerInfo(
                fingerprint=fingerprint,
                name=props.get("name", ""),
                entity_type=props.get("entity_type", "unknown"),
                address=addr,
                discovery_method="mdns",
            )

            with self._lock:
                self._peers[fingerprint] = peer
                logger.info("Discovered peer %s at %s via mDNS", peer.name, addr)

        except Exception as exc:
            logger.debug("Error processing mDNS service %s: %s", name, exc)

    def remove_service(self, zc: object, type_: str, name: str) -> None:
        """Zeroconf callback: service removed."""
        logger.debug("mDNS service removed: %s", name)

    def update_service(self, zc: object, type_: str, name: str) -> None:
        """Zeroconf callback: service updated."""
        self.add_service(zc, type_, name)

    @staticmethod
    def _get_local_ip() -> str:
        """Get the local IP address for mDNS advertisement."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
