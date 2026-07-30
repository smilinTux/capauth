"""Storage for the pairing kernel (spec 3.4 part 3).

Two stores, one injectable root (``base_dir``, defaults to ``~/.skcapstone``):

* **Peer registry** under ``<base_dir>/peers/<name>.json``. The M2 rule is
  absolute: the existing **v1 record shape stays VERBATIM**. Approved-device /
  mode metadata rides a single **versioned sidecar** key (``pairing``), never a
  rewrite of any existing field. Loading a v1 peer, approving a device, and
  reloading it leaves every original key byte-identical and adds only the
  sidecar. skchat's ``trusted_operators`` SQLite becomes a local read cache of
  these records, no longer a source of truth.
* **Pending enrollments** under ``<base_dir>/pairing/enrollments/<id>.json``.
  This is NEW kernel state (not the peer registry), so it uses a clean JSON
  format keyed by ``enrollment_id``.

``base_dir`` is a constructor argument so tests use ``tmp_path`` and never touch
the real registry.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .records import DeviceRecord, Enrollment, EnrollmentMode

#: The sidecar version stamped on every ``pairing`` block. Bump only on a
#: breaking change to the sidecar shape; the surrounding v1 peer record is
#: never versioned by us (it is owned by the peer-registry format).
SIDECAR_VERSION = 1

#: The single key the pairing kernel adds to a v1 peer record.
SIDECAR_KEY = "pairing"

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def default_base_dir() -> Path:
    """The real storage root (``~/.skcapstone``). Tests inject their own."""
    return Path.home() / ".skcapstone"


def fingerprint_for(pubkey: str) -> str:
    """Derive a stable fingerprint for a presented public key.

    Prefers capauth's own crypto backend (``fingerprint_from_armor``) so a real
    ASCII-armored key yields its true PGP fingerprint. Falls back to a
    deterministic SHA-256-derived 40-char hex when no key material can be parsed
    (e.g. an opaque token in a hermetic test), so the kernel never depends on a
    live keyring just to compute an id. Fail-safe: any backend error falls back
    to the hash.
    """
    key = (pubkey or "").strip()
    if not key:
        return ""
    if "BEGIN PGP" in key:
        try:  # real armored key: use the canonical fingerprint
            from capauth.crypto import get_backend

            fp = get_backend().fingerprint_from_armor(key)
            if fp:
                return fp.upper()
        except Exception:  # noqa: BLE001 -- fall back to the hash, never crash
            pass
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:40].upper()


def _slug(value: str) -> str:
    """A filesystem-safe peer-file stem derived from a subject/identity."""
    v = (value or "").strip().lower()
    # Prefer the local part of an address-like identity (agent@op.realm).
    if "@" in v:
        v = v.split("@", 1)[0]
    v = v.split(":")[-1]  # strip a capauth: scheme prefix
    v = _SLUG_RE.sub("-", v).strip("-")
    return v or "device"


class PairingStore:
    """Filesystem-backed pairing storage with an injectable root."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = Path(base_dir).expanduser() if base_dir else default_base_dir()

    # -- paths ----------------------------------------------------------------
    @property
    def peers_dir(self) -> Path:
        return self.base_dir / "peers"

    @property
    def enrollments_dir(self) -> Path:
        return self.base_dir / "pairing" / "enrollments"

    def _peer_path(self, stem: str) -> Path:
        return self.peers_dir / f"{stem}.json"

    # -- pending enrollments (clean kernel format) ----------------------------
    def save_enrollment(self, enrollment: Enrollment) -> None:
        self.enrollments_dir.mkdir(parents=True, exist_ok=True)
        path = self.enrollments_dir / f"{enrollment.enrollment_id}.json"
        path.write_text(enrollment.model_dump_json(indent=2), encoding="utf-8")

    def load_enrollment(self, enrollment_id: str) -> Optional[Enrollment]:
        path = self.enrollments_dir / f"{enrollment_id}.json"
        if not path.exists():
            return None
        try:
            return Enrollment.model_validate_json(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError):
            return None

    def delete_enrollment(self, enrollment_id: str) -> None:
        (self.enrollments_dir / f"{enrollment_id}.json").unlink(missing_ok=True)

    # -- peer registry (v1 shape VERBATIM + versioned sidecar) ----------------
    def _load_peer_raw(self, path: Path) -> Optional[dict]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_peer_raw(self, path: Path, record: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    def _find_peer_path_for_subject(self, subject: str) -> Optional[Path]:
        """Locate an existing peer file that already describes ``subject``.

        Matches by filename stem (``<slug>.json``) or by any of the identity
        fields a v1 peer record carries. Returns None when no existing peer
        matches (a brand-new device gets a fresh file).
        """
        if not self.peers_dir.exists():
            return None
        stem_path = self._peer_path(_slug(subject))
        if stem_path.exists():
            return stem_path
        wanted = subject.strip().lower()
        for path in sorted(self.peers_dir.glob("*.json")):
            rec = self._load_peer_raw(path)
            if not isinstance(rec, dict):
                continue
            for field in ("identity", "capauth_uri", "handle", "fqid", "email"):
                val = rec.get(field)
                if isinstance(val, str) and val.strip().lower() == wanted:
                    return path
        return None

    def _device_entry(self, device: DeviceRecord) -> dict:
        """One device's entry inside the sidecar's ``devices`` list.

        The device's OWN key material (``pubkey``/``fingerprint``) lives here,
        never overwriting the peer record's identity ``public_key``/
        ``fingerprint`` fields (a subject may pair several devices, each with a
        distinct key, all under one identity).
        """
        return {
            "device_id": device.device_id,
            "enrollment_id": device.enrollment_id,
            "pubkey": device.pubkey,
            "fingerprint": device.fingerprint,
            "mode": device.mode.value,
            "scopes": list(device.scopes),
            "approved_by": device.approved_by,
            "approved_at": device.approved_at.isoformat(),
            "revoked": device.revoked,
            "revoked_reason": device.revoked_reason,
            "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
        }

    def _minimal_v1_peer(self, device: DeviceRecord) -> dict:
        """A minimal but v1-shaped peer record for a brand-new paired device.

        Uses the exact field names the shipped peer registry uses, so a device
        record and an agent record are the same shape. Only added key: the
        ``pairing`` sidecar.
        """
        now = datetime.now(timezone.utc).isoformat()
        return {
            "name": device.subject,
            "identity": device.subject,
            "fingerprint": device.fingerprint,
            "public_key": device.pubkey,
            "entity_type": "device",
            "handle": device.subject,
            "email": None,
            "capabilities": list(device.scopes),
            "contact_uris": [],
            "trust_level": device.mode.value,
            "added_at": now,
            "last_seen": None,
            "source": "capauth.pairing",
            "agent_type": "device",
            "notes": "",
            "transport_addresses": {},
            "capauth_uri": device.subject,
            "fqid": None,
        }

    def upsert_device(self, device: DeviceRecord) -> Path:
        """Persist ``device`` into the peer registry as a versioned sidecar.

        If a peer file already describes the subject, its v1 fields are left
        BYTE-VERBATIM and only the ``pairing`` sidecar is added/updated.
        Otherwise a fresh minimal v1 peer record is created. The sidecar holds a
        ``devices`` LIST, so a subject may pair several devices without clobber:
        the matching ``device_id`` entry is replaced, else appended. Returns the
        file path written.
        """
        path = self._find_peer_path_for_subject(device.subject)
        if path is None:
            path = self._peer_path(_slug(device.subject))
            record = self._load_peer_raw(path) if path.exists() else None
            if not isinstance(record, dict):
                record = self._minimal_v1_peer(device)
        else:
            record = self._load_peer_raw(path) or {}

        sidecar = record.get(SIDECAR_KEY)
        if not isinstance(sidecar, dict):
            sidecar = {"version": SIDECAR_VERSION, "devices": []}
        devices = sidecar.get("devices")
        if not isinstance(devices, list):
            devices = []
        entry = self._device_entry(device)
        for i, existing in enumerate(devices):
            if isinstance(existing, dict) and existing.get("device_id") == device.device_id:
                devices[i] = entry
                break
        else:
            devices.append(entry)
        sidecar["version"] = SIDECAR_VERSION
        sidecar["devices"] = devices
        # Additive only: attach/replace the sidecar, touch nothing else.
        record[SIDECAR_KEY] = sidecar
        self._write_peer_raw(path, record)
        return path

    def _device_from_entry(self, subject: str, entry: dict) -> Optional[DeviceRecord]:
        try:
            return DeviceRecord(
                device_id=entry["device_id"],
                subject=subject,
                pubkey=entry.get("pubkey", ""),
                fingerprint=entry.get("fingerprint", ""),
                mode=EnrollmentMode(entry["mode"]),
                scopes=list(entry.get("scopes", [])),
                approved_by=entry.get("approved_by", ""),
                approved_at=entry["approved_at"],
                enrollment_id=entry.get("enrollment_id"),
                revoked=bool(entry.get("revoked", False)),
                revoked_reason=entry.get("revoked_reason"),
                revoked_at=entry.get("revoked_at"),
            )
        except (KeyError, ValueError):
            return None

    @staticmethod
    def _subject_of(record: dict) -> str:
        return record.get("identity") or record.get("name") or record.get("capauth_uri") or ""

    def iter_devices(self) -> list[tuple[Path, DeviceRecord]]:
        """Every paired device across all peer files, as ``(path, device)``."""
        out: list[tuple[Path, DeviceRecord]] = []
        if not self.peers_dir.exists():
            return out
        for path in sorted(self.peers_dir.glob("*.json")):
            rec = self._load_peer_raw(path)
            if not isinstance(rec, dict):
                continue
            sidecar = rec.get(SIDECAR_KEY)
            if not isinstance(sidecar, dict):
                continue
            subject = self._subject_of(rec)
            for entry in sidecar.get("devices", []):
                if not isinstance(entry, dict):
                    continue
                device = self._device_from_entry(subject, entry)
                if device is not None:
                    out.append((path, device))
        return out

    def find_device(self, device_id: str) -> Optional[tuple[Path, dict, DeviceRecord]]:
        """Locate the peer file + device record whose sidecar entry matches ``device_id``."""
        if not self.peers_dir.exists():
            return None
        for path in sorted(self.peers_dir.glob("*.json")):
            rec = self._load_peer_raw(path)
            if not isinstance(rec, dict):
                continue
            sidecar = rec.get(SIDECAR_KEY)
            if not isinstance(sidecar, dict):
                continue
            subject = self._subject_of(rec)
            for entry in sidecar.get("devices", []):
                if isinstance(entry, dict) and entry.get("device_id") == device_id:
                    device = self._device_from_entry(subject, entry)
                    if device is not None:
                        return path, rec, device
        return None


__all__ = [
    "PairingStore",
    "SIDECAR_VERSION",
    "SIDECAR_KEY",
    "default_base_dir",
    "fingerprint_for",
]
