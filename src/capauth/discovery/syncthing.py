"""Syncthing-based peer auto-discovery for CapAuth.

Queries the Syncthing REST API for connected/configured devices, then
cross-references with SKCapstone agent files to find matching CapAuth peers.

Agents that advertise both ``syncthing_device_id`` and ``capauth_fingerprint``
in their coordination JSON are automatically added to the peer trust list.

Agent JSON schema extensions (optional fields):

    {
        "syncthing_device_id": "XXXXXXX-XXXXXXX-...",
        "capauth_fingerprint": "ABCDEF01...",
        "capauth_name": "lumina",          // optional, falls back to agent field
        "capauth_entity_type": "ai"        // optional, defaults to "unknown"
    }

Configuration:
    - API URL: default http://127.0.0.1:8384, override with SYNCTHING_URL env
      or the ``api_url`` constructor arg (auto-detected from config.xml if not set)
    - API key: read from ~/.config/syncthing/config.xml or SYNCTHING_API_KEY env
    - Agent dir: default ~/.skcapstone/coordination/agents/, override with
      ``agents_dir`` constructor arg
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

from .base import DiscoveryBackend, PeerInfo

logger = logging.getLogger("capauth.discovery.syncthing")

_SYNCTHING_CONFIG_PATH = Path.home() / ".config" / "syncthing" / "config.xml"
_DEFAULT_AGENTS_DIR = Path.home() / ".skcapstone" / "coordination" / "agents"
_DEFAULT_API_URL = "http://127.0.0.1:8384"


def _read_syncthing_config(config_path: Path) -> tuple[str, str]:
    """Parse Syncthing config.xml for the GUI address and API key.

    Args:
        config_path: Path to Syncthing's config.xml.

    Returns:
        Tuple of (api_url, api_key). Returns defaults on parse failure.
    """
    api_url = _DEFAULT_API_URL
    api_key = ""

    if not config_path.exists():
        return api_url, api_key

    try:
        tree = ElementTree.parse(config_path)  # noqa: S314 — local file only
        root = tree.getroot()
        gui = root.find("gui")
        if gui is not None:
            addr_el = gui.find("address")
            if addr_el is not None and addr_el.text:
                addr = addr_el.text.strip()
                scheme = "https" if gui.get("tls") == "true" else "http"
                api_url = f"{scheme}://{addr}"
            key_el = gui.find("apikey")
            if key_el is not None and key_el.text:
                api_key = key_el.text.strip()
    except Exception as exc:
        logger.debug("Could not parse Syncthing config: %s", exc)

    return api_url, api_key


def _syncthing_get(url: str, api_key: str, timeout: int = 5) -> Optional[dict | list]:
    """Make a GET request to the Syncthing REST API.

    Args:
        url: Full URL to request.
        api_key: Syncthing API key.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON response, or None on any error.
    """
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        logger.debug("Syncthing API request failed (%s): %s", url, exc)
        return None


def _load_agent_files(agents_dir: Path) -> list[dict]:
    """Read all agent JSON files from the coordination directory.

    Args:
        agents_dir: Directory containing <agent>.json files.

    Returns:
        List of parsed agent dicts (silently skips unreadable files).
    """
    agents: list[dict] = []
    if not agents_dir.exists():
        logger.debug("Agents dir not found: %s", agents_dir)
        return agents

    for f in agents_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                agents.append(data)
        except Exception as exc:
            logger.debug("Skipping %s: %s", f.name, exc)

    return agents


def _normalize_device_id(device_id: str) -> str:
    """Normalise a Syncthing device ID to uppercase with dashes.

    Args:
        device_id: Raw device ID string.

    Returns:
        Normalised device ID.
    """
    return device_id.strip().upper()


class SyncthingDiscovery(DiscoveryBackend):
    """Discover CapAuth peers via Syncthing device cross-reference.

    Queries the Syncthing REST API for known devices, then cross-references
    against SKCapstone agent files that carry a ``syncthing_device_id`` field.
    Agents with a matching device ID and a ``capauth_fingerprint`` are returned
    as trusted peers.

    Args:
        api_url: Syncthing GUI URL (e.g. ``http://127.0.0.1:8080``).
            Auto-detected from config.xml if not provided.
        api_key: Syncthing API key. Auto-detected from config.xml if not set,
            can also be overridden by the ``SYNCTHING_API_KEY`` env variable.
        agents_dir: Directory containing agent coordination JSON files.
            Defaults to ``~/.skcapstone/coordination/agents/``.
        connected_only: If True, only include currently connected Syncthing
            devices. If False, include all configured devices.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        agents_dir: Optional[Path] = None,
        connected_only: bool = False,
    ) -> None:
        cfg_url, cfg_key = _read_syncthing_config(_SYNCTHING_CONFIG_PATH)

        self._api_url = (api_url or os.environ.get("SYNCTHING_URL") or cfg_url).rstrip("/")
        self._api_key = api_key or os.environ.get("SYNCTHING_API_KEY") or cfg_key
        self._agents_dir = agents_dir or _DEFAULT_AGENTS_DIR
        self._connected_only = connected_only
        self._running = False

    @property
    def name(self) -> str:
        return "syncthing"

    def available(self) -> bool:
        """Check if Syncthing is reachable and API key is configured.

        Returns:
            True if the Syncthing API responds to a ping.
        """
        if not self._api_key:
            logger.debug("No Syncthing API key configured")
            return False

        result = _syncthing_get(f"{self._api_url}/rest/system/ping", self._api_key, timeout=2)
        return isinstance(result, dict) and result.get("ping") == "pong"

    def start(self) -> None:
        """No background threads needed for Syncthing discovery."""
        self._running = True
        logger.info("Syncthing discovery started (API: %s)", self._api_url)

    def stop(self) -> None:
        """No resources to release."""
        self._running = False

    def announce(self, peer: PeerInfo) -> bool:
        """Syncthing handles its own device advertisements — no-op.

        Args:
            peer: Unused.

        Returns:
            False — announcement is not applicable for this backend.
        """
        return False

    def get_syncthing_device_ids(self) -> set[str]:
        """Fetch the set of Syncthing device IDs known to this instance.

        Uses ``/rest/system/connections`` to get currently-connected devices,
        falling back to ``/rest/config/devices`` for all configured devices.

        Returns:
            Set of normalised device ID strings. Empty set on failure.
        """
        device_ids: set[str] = set()

        # Always fetch connections — includes connected status
        conns = _syncthing_get(f"{self._api_url}/rest/system/connections", self._api_key)
        if isinstance(conns, dict):
            for device_id, info in conns.get("connections", {}).items():
                if self._connected_only and not info.get("connected", False):
                    continue
                device_ids.add(_normalize_device_id(device_id))

        if not self._connected_only and not device_ids:
            # Fallback: read all configured devices
            devices = _syncthing_get(f"{self._api_url}/rest/config/devices", self._api_key)
            if isinstance(devices, list):
                for d in devices:
                    did = d.get("deviceID", "")
                    if did:
                        device_ids.add(_normalize_device_id(did))

        logger.debug("Syncthing: found %d device IDs", len(device_ids))
        return device_ids

    def discover(self, timeout_ms: int = 5000) -> list[PeerInfo]:
        """Discover CapAuth peers by cross-referencing Syncthing devices.

        Algorithm:
        1. Fetch all (or connected-only) device IDs from Syncthing.
        2. Scan agent JSON files for ``syncthing_device_id`` entries.
        3. Match device IDs between the two sets.
        4. For each match, return a ``PeerInfo`` built from the agent's
           ``capauth_fingerprint`` (required) and optional name fields.

        Args:
            timeout_ms: Unused (HTTP timeout is fixed at 5 s).

        Returns:
            List of discovered ``PeerInfo`` objects.
        """
        device_ids = self.get_syncthing_device_ids()
        if not device_ids:
            logger.debug("No Syncthing devices found; skipping agent cross-reference")
            return []

        agents = _load_agent_files(self._agents_dir)
        peers: list[PeerInfo] = []
        seen_fps: set[str] = set()

        for agent in agents:
            raw_did = agent.get("syncthing_device_id", "")
            if not raw_did:
                continue

            normalized = _normalize_device_id(str(raw_did))
            if normalized not in device_ids:
                continue

            fingerprint = agent.get("capauth_fingerprint", "")
            if not fingerprint:
                logger.debug(
                    "Agent %s has syncthing_device_id but no capauth_fingerprint — skipping",
                    agent.get("agent", "<unknown>"),
                )
                continue

            # Deduplicate by fingerprint
            if fingerprint in seen_fps:
                continue
            seen_fps.add(fingerprint)

            name = agent.get("capauth_name") or agent.get("agent") or ""
            entity_type = agent.get("capauth_entity_type") or "unknown"
            host = agent.get("host", "")

            peer = PeerInfo(
                fingerprint=fingerprint,
                name=name,
                entity_type=entity_type,
                address=host,
                discovery_method="syncthing",
                metadata={
                    "syncthing_device_id": normalized,
                    "agent": agent.get("agent", ""),
                    "host": host,
                },
            )
            peers.append(peer)
            logger.info(
                "Syncthing discovery: found peer %s (%s) via device %s",
                name,
                fingerprint[:16],
                normalized[:7],
            )

        return peers
