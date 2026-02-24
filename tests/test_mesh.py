"""Tests for the CapAuth P2P mesh networking module.

Covers peer discovery (file-based and mDNS), mesh management,
peer registry, and CLI commands.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from capauth.discovery.base import DiscoveryBackend, PeerInfo
from capauth.discovery.file_discovery import FileDiscovery
from capauth.mesh import PeerMesh


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def mesh_home(tmp_path):
    """Create a temporary capauth home for mesh tests."""
    (tmp_path / "identity").mkdir()
    (tmp_path / "mesh").mkdir()
    (tmp_path / "mesh" / "peers").mkdir()
    return tmp_path


@pytest.fixture
def peer_alice():
    """A sample peer: Alice (human)."""
    return PeerInfo(
        fingerprint="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
        name="Alice",
        entity_type="human",
        address="192.168.1.10:7778",
        discovery_method="mdns",
    )


@pytest.fixture
def peer_opus():
    """A sample peer: Opus (AI agent)."""
    return PeerInfo(
        fingerprint="FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000",
        name="Opus",
        entity_type="ai",
        address="file:///shared/opus",
        discovery_method="file",
    )


@pytest.fixture
def my_fingerprint():
    return "1234ABCD5678EFGH9012IJKL3456MNOP7890QRST"


class MockBackend(DiscoveryBackend):
    """A mock discovery backend for testing."""

    def __init__(self, peers: list[PeerInfo] = None):
        self._peers = peers or []
        self._started = False
        self._announced = False

    @property
    def name(self) -> str:
        return "mock"

    def start(self) -> None:
        self._started = True

    def stop(self) -> None:
        self._started = False

    def announce(self, peer: PeerInfo) -> bool:
        self._announced = True
        return True

    def discover(self, timeout_ms: int = 5000) -> list[PeerInfo]:
        return self._peers

    def available(self) -> bool:
        return True


# ── PeerInfo model tests ──────────────────────────────────────────


class TestPeerInfo:
    """Tests for the PeerInfo model."""

    def test_defaults(self, peer_alice):
        assert peer_alice.fingerprint.startswith("AAAA")
        assert peer_alice.name == "Alice"
        assert not peer_alice.verified

    def test_serialization(self, peer_alice):
        data = json.loads(peer_alice.model_dump_json())
        loaded = PeerInfo.model_validate(data)
        assert loaded.fingerprint == peer_alice.fingerprint

    def test_metadata_field(self):
        peer = PeerInfo(
            fingerprint="TEST" * 10,
            metadata={"version": "0.1.0"},
        )
        assert peer.metadata["version"] == "0.1.0"


# ── File discovery tests ──────────────────────────────────────────


class TestFileDiscovery:
    """Tests for file-based peer discovery."""

    def test_name(self):
        fd = FileDiscovery()
        assert fd.name == "file"

    def test_always_available(self):
        fd = FileDiscovery()
        assert fd.available() is True

    def test_announce_creates_file(self, mesh_home, peer_alice):
        shared = mesh_home / "mesh" / "peers"
        fd = FileDiscovery(shared_dir=shared)
        fd.start()
        result = fd.announce(peer_alice)
        assert result is True
        files = list(shared.glob("*.capauth.json"))
        assert len(files) == 1

    def test_discover_finds_announced(self, mesh_home, peer_alice, peer_opus):
        shared = mesh_home / "mesh" / "peers"
        fd = FileDiscovery(shared_dir=shared)
        fd.start()
        fd.announce(peer_alice)
        fd.announce(peer_opus)

        peers = fd.discover()
        assert len(peers) == 2
        names = {p.name for p in peers}
        assert "Alice" in names
        assert "Opus" in names

    def test_stale_files_ignored(self, mesh_home, peer_alice):
        shared = mesh_home / "mesh" / "peers"
        fd = FileDiscovery(shared_dir=shared, stale_seconds=1)
        fd.start()
        fd.announce(peer_alice)

        import os

        f = list(shared.glob("*.capauth.json"))[0]
        old_time = time.time() - 10
        os.utime(f, (old_time, old_time))

        peers = fd.discover()
        assert len(peers) == 0

    def test_discover_empty_dir(self, mesh_home):
        shared = mesh_home / "mesh" / "empty_peers"
        shared.mkdir(parents=True)
        fd = FileDiscovery(shared_dir=shared)
        fd.start()
        peers = fd.discover()
        assert peers == []

    def test_malformed_file_skipped(self, mesh_home):
        shared = mesh_home / "mesh" / "peers"
        (shared / "bad.capauth.json").write_text("not json", encoding="utf-8")
        fd = FileDiscovery(shared_dir=shared)
        fd.start()
        peers = fd.discover()
        assert peers == []


# ── PeerMesh tests ────────────────────────────────────────────────


class TestPeerMesh:
    """Tests for the PeerMesh coordinator."""

    def test_init(self, my_fingerprint, mesh_home):
        m = PeerMesh(
            fingerprint=my_fingerprint,
            name="TestAgent",
            base_dir=mesh_home,
        )
        assert m.fingerprint == my_fingerprint
        assert m.name == "TestAgent"

    def test_add_backend(self, my_fingerprint, mesh_home):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        backend = MockBackend()
        m.add_backend(backend)
        assert len(m._backends) == 1

    def test_unavailable_backend_skipped(self, my_fingerprint, mesh_home):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        backend = MockBackend()
        backend.available = lambda: False  # type: ignore[assignment]
        m.add_backend(backend)
        assert len(m._backends) == 0

    def test_start_and_stop(self, my_fingerprint, mesh_home):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        backend = MockBackend()
        m.add_backend(backend)
        m.start()
        assert backend._started
        assert backend._announced
        m.stop()
        assert not backend._started

    def test_discover_all(self, my_fingerprint, mesh_home, peer_alice, peer_opus):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        m.add_backend(MockBackend([peer_alice, peer_opus]))

        peers = m.discover_all()
        assert len(peers) == 2

    def test_discover_deduplicates(self, my_fingerprint, mesh_home, peer_alice):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        m.add_backend(MockBackend([peer_alice]))
        m.add_backend(MockBackend([peer_alice]))

        peers = m.discover_all()
        assert len(peers) == 1

    def test_discover_excludes_self(self, my_fingerprint, mesh_home):
        self_peer = PeerInfo(fingerprint=my_fingerprint, name="Me")
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        m.add_backend(MockBackend([self_peer]))

        peers = m.discover_all()
        assert len(peers) == 0

    def test_add_and_get_peers(self, my_fingerprint, mesh_home, peer_alice):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        m.add_peer(peer_alice)
        peers = m.get_peers()
        assert len(peers) == 1
        assert peers[0].name == "Alice"

    def test_get_verified_only(self, my_fingerprint, mesh_home, peer_alice, peer_opus):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        peer_alice.verified = True
        m.add_peer(peer_alice)
        m.add_peer(peer_opus)

        all_peers = m.get_peers()
        assert len(all_peers) == 2

        verified = m.get_peers(verified_only=True)
        assert len(verified) == 1
        assert verified[0].name == "Alice"

    def test_remove_peer(self, my_fingerprint, mesh_home, peer_alice):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        m.add_peer(peer_alice)
        assert m.remove_peer(peer_alice.fingerprint) is True
        assert len(m.get_peers()) == 0

    def test_remove_nonexistent_peer(self, my_fingerprint, mesh_home):
        m = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        assert m.remove_peer("NONEXISTENT") is False

    def test_mesh_status(self, my_fingerprint, mesh_home, peer_alice):
        m = PeerMesh(
            fingerprint=my_fingerprint, name="TestAgent", base_dir=mesh_home
        )
        m.add_backend(MockBackend())
        m.add_peer(peer_alice)

        status = m.mesh_status()
        assert status["name"] == "TestAgent"
        assert status["total_peers"] == 1
        assert status["backends_available"] == 1

    def test_registry_persistence(self, my_fingerprint, mesh_home, peer_alice):
        m1 = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        m1.add_peer(peer_alice)

        m2 = PeerMesh(fingerprint=my_fingerprint, base_dir=mesh_home)
        peers = m2.get_peers()
        assert len(peers) == 1
        assert peers[0].name == "Alice"


# ── mDNS discovery tests ─────────────────────────────────────────


class TestMDNSDiscovery:
    """Tests for mDNS discovery backend."""

    def test_available_with_zeroconf(self):
        from capauth.discovery.mdns import MDNSDiscovery

        mdns = MDNSDiscovery()
        assert mdns.available() is True

    def test_name(self):
        from capauth.discovery.mdns import MDNSDiscovery

        mdns = MDNSDiscovery()
        assert mdns.name == "mdns"

    def test_discover_empty_without_start(self):
        from capauth.discovery.mdns import MDNSDiscovery

        mdns = MDNSDiscovery()
        # Reason: Don't call discover() which starts real Zeroconf;
        # just verify the internal peer dict starts empty.
        assert mdns._peers == {}

    def test_add_service_populates_peers(self):
        from capauth.discovery.mdns import MDNSDiscovery

        mdns = MDNSDiscovery()
        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.properties = {
            b"fingerprint": b"AAAA1111BBBB2222",
            b"name": b"TestPeer",
            b"entity_type": b"human",
        }
        mock_info.parsed_addresses.return_value = ["192.168.1.10"]
        mock_info.port = 7778
        mock_zc.get_service_info.return_value = mock_info

        mdns.add_service(mock_zc, "_capauth._tcp.local.", "test._capauth._tcp.local.")
        assert len(mdns._peers) == 1
        peer = list(mdns._peers.values())[0]
        assert peer.name == "TestPeer"


# ── CLI tests ─────────────────────────────────────────────────────


class TestMeshCLI:
    """Tests for mesh CLI commands."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def mock_profile(self):
        profile = MagicMock()
        profile.entity.name = "Chef"
        profile.entity.entity_type.value = "human"
        profile.key_info.fingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        return profile

    def test_mesh_status_json(self, runner, mock_profile, mesh_home):
        from capauth.cli import main

        with patch("capauth.profile.load_profile", return_value=mock_profile):
            result = runner.invoke(
                main,
                ["--home", str(mesh_home), "mesh", "status", "--json-out"],
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "total_peers" in data

    def test_mesh_peers_empty(self, runner, mock_profile, mesh_home):
        from capauth.cli import main

        with patch("capauth.profile.load_profile", return_value=mock_profile):
            result = runner.invoke(
                main,
                ["--home", str(mesh_home), "mesh", "peers"],
            )
        assert result.exit_code == 0
        assert "No known peers" in result.output
