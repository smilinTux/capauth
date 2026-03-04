"""Tests for Syncthing-based peer auto-discovery.

Covers:
  - SyncthingDiscovery.available() with mocked HTTP
  - Device ID fetching from connections and config endpoints
  - Agent file cross-referencing
  - CLI: capauth discover
  - CLI: capauth peers list --auto
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from capauth.cli import main
from capauth.discovery.syncthing import (
    SyncthingDiscovery,
    _load_agent_files,
    _normalize_device_id,
    _read_syncthing_config,
)


# ── Fixtures ──────────────────────────────────────────────────────


DEVICE_A = "77W3WEK-V2PULIY-7SFXCLD-A7AACUW-VFU3XNI-KAXQFHZ-ENJFTIN-UJNJ4AR"
DEVICE_B = "CIHSBZ4-PS46AUX-VPE37BR-YGQDTUK-K3GESSD-4PVYZ63-M33WRKV-6V6P5AC"
FP_LUMINA = "AABBCCDD11223344AABBCCDD11223344AABBCCDD"
FP_JARVIS = "DEADBEEF00112233DEADBEEF00112233DEADBEEF"


@pytest.fixture
def agents_dir(tmp_path):
    """Create a temporary agents directory with sample agent JSON files."""
    d = tmp_path / "agents"
    d.mkdir()

    # Agent with both fields — should be discovered
    (d / "lumina.json").write_text(
        json.dumps(
            {
                "agent": "lumina",
                "host": "lumina-norap2027",
                "syncthing_device_id": DEVICE_A,
                "capauth_fingerprint": FP_LUMINA,
                "capauth_entity_type": "ai",
            }
        ),
        encoding="utf-8",
    )

    # Agent with device ID but no CapAuth fingerprint — should be skipped
    (d / "nofp.json").write_text(
        json.dumps(
            {
                "agent": "nofp",
                "syncthing_device_id": DEVICE_B,
            }
        ),
        encoding="utf-8",
    )

    # Agent with no Syncthing fields — should be skipped
    (d / "jarvis.json").write_text(
        json.dumps(
            {
                "agent": "jarvis",
                "capauth_fingerprint": FP_JARVIS,
            }
        ),
        encoding="utf-8",
    )

    # Malformed JSON — should be skipped gracefully
    (d / "bad.json").write_text("not valid json", encoding="utf-8")

    return d


@pytest.fixture
def syncthing_connections_response():
    """Fake /rest/system/connections response with DEVICE_A connected."""
    return {
        "connections": {
            DEVICE_A: {
                "connected": True,
                "address": "192.168.1.5:22000",
                "clientVersion": "v1.26.1",
            },
            DEVICE_B: {
                "connected": False,
                "address": "",
                "clientVersion": "",
            },
        }
    }


@pytest.fixture
def syncthing_config_devices_response():
    """Fake /rest/config/devices response."""
    return [
        {"deviceID": DEVICE_A, "name": "lumina-norap2027"},
        {"deviceID": DEVICE_B, "name": "sksync.skstack01"},
    ]


# ── Unit tests: helpers ────────────────────────────────────────────


def test_normalize_device_id():
    lower = "77w3wek-v2puliy-7sfxcld-a7aacuw-vfu3xni-kaxqfhz-enjftin-ujnj4ar"
    assert _normalize_device_id(lower) == DEVICE_A


def test_normalize_device_id_strips_whitespace():
    assert _normalize_device_id(f"  {DEVICE_A}  ") == DEVICE_A


def test_load_agent_files_returns_valid(agents_dir):
    agents = _load_agent_files(agents_dir)
    names = {a["agent"] for a in agents}
    assert "lumina" in names
    assert "jarvis" in names
    assert len(agents) == 3  # lumina, nofp, jarvis (bad.json skipped)


def test_load_agent_files_missing_dir(tmp_path):
    result = _load_agent_files(tmp_path / "nonexistent")
    assert result == []


def test_read_syncthing_config_missing(tmp_path):
    url, key = _read_syncthing_config(tmp_path / "config.xml")
    assert url == "http://127.0.0.1:8384"
    assert key == ""


def test_read_syncthing_config_parses(tmp_path):
    cfg = tmp_path / "config.xml"
    cfg.write_text(
        """<configuration>
            <gui enabled="true" tls="false">
                <address>127.0.0.1:8080</address>
                <apikey>testkey123</apikey>
            </gui>
        </configuration>""",
        encoding="utf-8",
    )
    url, key = _read_syncthing_config(cfg)
    assert url == "http://127.0.0.1:8080"
    assert key == "testkey123"


def test_read_syncthing_config_tls(tmp_path):
    cfg = tmp_path / "config.xml"
    cfg.write_text(
        """<configuration>
            <gui enabled="true" tls="true">
                <address>0.0.0.0:8443</address>
                <apikey>tlskey</apikey>
            </gui>
        </configuration>""",
        encoding="utf-8",
    )
    url, key = _read_syncthing_config(cfg)
    assert url.startswith("https://")
    assert key == "tlskey"


# ── Unit tests: SyncthingDiscovery ────────────────────────────────


def _make_discovery(agents_dir, connected_only=False):
    return SyncthingDiscovery(
        api_url="http://localhost:8384",
        api_key="testkey",
        agents_dir=agents_dir,
        connected_only=connected_only,
    )


def test_available_returns_true_on_pong(agents_dir):
    with patch(
        "capauth.discovery.syncthing._syncthing_get",
        return_value={"ping": "pong"},
    ):
        st = _make_discovery(agents_dir)
        assert st.available() is True


def test_available_returns_false_on_none(agents_dir):
    with patch("capauth.discovery.syncthing._syncthing_get", return_value=None):
        st = _make_discovery(agents_dir)
        assert st.available() is False


def test_available_returns_false_no_api_key(agents_dir):
    st = SyncthingDiscovery(
        api_url="http://localhost:8384",
        api_key="",
        agents_dir=agents_dir,
    )
    assert st.available() is False


def test_get_device_ids_from_connections(
    agents_dir, syncthing_connections_response
):
    st = _make_discovery(agents_dir, connected_only=False)
    with patch(
        "capauth.discovery.syncthing._syncthing_get",
        return_value=syncthing_connections_response,
    ):
        ids = st.get_syncthing_device_ids()

    assert DEVICE_A in ids
    assert DEVICE_B in ids  # not connected_only, so all included


def test_get_device_ids_connected_only(
    agents_dir, syncthing_connections_response
):
    st = _make_discovery(agents_dir, connected_only=True)
    with patch(
        "capauth.discovery.syncthing._syncthing_get",
        return_value=syncthing_connections_response,
    ):
        ids = st.get_syncthing_device_ids()

    assert DEVICE_A in ids
    assert DEVICE_B not in ids  # not connected


def test_discover_returns_matching_peers(
    agents_dir, syncthing_connections_response
):
    st = _make_discovery(agents_dir)
    with patch(
        "capauth.discovery.syncthing._syncthing_get",
        return_value=syncthing_connections_response,
    ):
        peers = st.discover()

    assert len(peers) == 1
    p = peers[0]
    assert p.fingerprint == FP_LUMINA
    assert p.name == "lumina"
    assert p.entity_type == "ai"
    assert p.discovery_method == "syncthing"
    assert p.metadata["syncthing_device_id"] == DEVICE_A


def test_discover_skips_missing_fingerprint(
    agents_dir, syncthing_connections_response
):
    """Agent nofp has syncthing_device_id but no capauth_fingerprint — skip."""
    st = _make_discovery(agents_dir)
    with patch(
        "capauth.discovery.syncthing._syncthing_get",
        return_value=syncthing_connections_response,
    ):
        peers = st.discover()

    fps = {p.fingerprint for p in peers}
    assert FP_JARVIS not in fps
    # Only lumina matches (has both fields and matching device)
    assert len(peers) == 1


def test_discover_returns_empty_when_no_syncthing_devices(agents_dir):
    st = _make_discovery(agents_dir)
    with patch(
        "capauth.discovery.syncthing._syncthing_get",
        return_value={"connections": {}},
    ):
        peers = st.discover()

    assert peers == []


def test_discover_deduplicates_fingerprints(tmp_path):
    """Two agent files with same fingerprint and same device ID → 1 peer."""
    d = tmp_path / "agents"
    d.mkdir()
    for i in range(2):
        (d / f"agent{i}.json").write_text(
            json.dumps(
                {
                    "agent": f"agent{i}",
                    "syncthing_device_id": DEVICE_A,
                    "capauth_fingerprint": FP_LUMINA,
                }
            ),
            encoding="utf-8",
        )

    st = SyncthingDiscovery(api_url="http://localhost:8384", api_key="k", agents_dir=d)
    fake_conns = {"connections": {DEVICE_A: {"connected": True}}}
    with patch("capauth.discovery.syncthing._syncthing_get", return_value=fake_conns):
        peers = st.discover()

    assert len(peers) == 1


def test_announce_is_noop(agents_dir):
    from capauth.discovery.base import PeerInfo

    st = _make_discovery(agents_dir)
    p = PeerInfo(fingerprint="ABCD1234", name="test")
    assert st.announce(p) is False


def test_name_property(agents_dir):
    assert _make_discovery(agents_dir).name == "syncthing"


# ── CLI tests ─────────────────────────────────────────────────────


@pytest.fixture
def cli_home(tmp_path):
    """Minimal capauth home directory layout for CLI tests."""
    (tmp_path / "identity").mkdir()
    (tmp_path / "mesh").mkdir()
    return tmp_path


def _make_profile_mock():
    profile = MagicMock()
    profile.key_info.fingerprint = "DEADBEEF" * 5
    profile.entity.name = "Test User"
    profile.entity.entity_type.value = "human"
    return profile


def test_cli_discover_no_syncthing(cli_home, agents_dir):
    """capauth discover when Syncthing is unreachable exits non-zero."""
    runner = CliRunner()
    with patch("capauth.discovery.syncthing._syncthing_get", return_value=None):
        result = runner.invoke(
            main,
            ["--home", str(cli_home), "discover"],
        )
    assert result.exit_code != 0
    assert "not reachable" in result.output.lower() or "Syncthing" in result.output


def test_cli_discover_no_peers_found(cli_home, agents_dir):
    """capauth discover when no agents match shows helpful message."""
    runner = CliRunner()
    with (
        patch(
            "capauth.discovery.syncthing._syncthing_get",
            return_value={"ping": "pong"},
        ),
        patch.object(
            SyncthingDiscovery,
            "get_syncthing_device_ids",
            return_value=set(),
        ),
    ):
        result = runner.invoke(
            main,
            ["--home", str(cli_home), "discover", "--agents-dir", str(agents_dir)],
        )

    assert result.exit_code == 0
    assert "No peers" in result.output


def test_cli_discover_json_output(cli_home, agents_dir, syncthing_connections_response):
    """capauth discover --json-out returns valid JSON list."""
    runner = CliRunner()

    def fake_get(url, key, **kwargs):
        if "ping" in url:
            return {"ping": "pong"}
        return syncthing_connections_response

    with patch("capauth.discovery.syncthing._syncthing_get", side_effect=fake_get):
        result = runner.invoke(
            main,
            [
                "--home",
                str(cli_home),
                "discover",
                "--agents-dir",
                str(agents_dir),
                "--json-out",
            ],
        )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    # lumina should be in there
    assert any(p["fingerprint"] == FP_LUMINA for p in data)


def test_cli_discover_add_peers(cli_home, agents_dir, syncthing_connections_response):
    """capauth discover --add-peers registers peers in the mesh."""
    runner = CliRunner()

    def fake_get(url, key, **kwargs):
        if "ping" in url:
            return {"ping": "pong"}
        return syncthing_connections_response

    with (
        patch("capauth.discovery.syncthing._syncthing_get", side_effect=fake_get),
        patch("capauth.profile.load_profile", return_value=_make_profile_mock()),
    ):
        result = runner.invoke(
            main,
            [
                "--home",
                str(cli_home),
                "discover",
                "--agents-dir",
                str(agents_dir),
                "--add-peers",
            ],
        )

    assert result.exit_code == 0
    assert "Added" in result.output


def test_cli_peers_list_no_auto(cli_home):
    """capauth peers list with no peers and no --auto shows 'No known peers'."""
    runner = CliRunner()
    with patch("capauth.profile.load_profile", return_value=_make_profile_mock()):
        result = runner.invoke(
            main,
            ["--home", str(cli_home), "peers", "list"],
        )
    assert result.exit_code == 0
    assert "No known peers" in result.output


def test_cli_peers_list_auto_syncthing_unavailable(cli_home):
    """capauth peers list --auto when Syncthing is down: graceful skip."""
    runner = CliRunner()
    with (
        patch("capauth.profile.load_profile", return_value=_make_profile_mock()),
        patch("capauth.discovery.syncthing._syncthing_get", return_value=None),
    ):
        result = runner.invoke(
            main,
            ["--home", str(cli_home), "peers", "list", "--auto"],
        )

    assert result.exit_code == 0
    assert "not reachable" in result.output.lower() or "skipping" in result.output.lower()


def test_cli_peers_list_auto_discovers_peers(
    cli_home, agents_dir, syncthing_connections_response
):
    """capauth peers list --auto adds discovered peers before listing."""
    runner = CliRunner()

    def fake_get(url, key, **kwargs):
        if "ping" in url:
            return {"ping": "pong"}
        return syncthing_connections_response

    with (
        patch("capauth.profile.load_profile", return_value=_make_profile_mock()),
        patch("capauth.discovery.syncthing._syncthing_get", side_effect=fake_get),
        patch(
            "capauth.discovery.syncthing._load_agent_files",
            return_value=[
                {
                    "agent": "lumina",
                    "syncthing_device_id": DEVICE_A,
                    "capauth_fingerprint": FP_LUMINA,
                    "capauth_entity_type": "ai",
                    "host": "lumina-host",
                }
            ],
        ),
    ):
        result = runner.invoke(
            main,
            [
                "--home",
                str(cli_home),
                "peers",
                "list",
                "--auto",
            ],
        )

    assert result.exit_code == 0
    assert "lumina" in result.output or FP_LUMINA[:16] in result.output
