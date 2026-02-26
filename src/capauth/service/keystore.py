"""SQLite-backed key registry for the CapAuth Verification Service.

Replaces the Django ORM CapAuthKeyRegistry from the Authentik stage
with a standalone store that works without any web framework.

Schema is intentionally minimal — fingerprint IS the identity.
No names, no emails, no PII stored server-side.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

DEFAULT_DB_PATH = Path("~/.capauth/service/keys.db").expanduser()


class EnrolledKey(BaseModel):
    """A PGP public key enrolled for authentication."""

    fingerprint: str = Field(description="40-char uppercase PGP fingerprint")
    public_key_armor: str = Field(description="ASCII-armored PGP public key")
    enrolled_at: str = Field(description="ISO 8601 enrollment timestamp")
    last_auth: Optional[str] = Field(default=None, description="Last successful auth")
    approved: bool = Field(default=True)
    linked_to: Optional[str] = Field(default=None, description="Primary fingerprint for multi-device")

    @property
    def effective_fingerprint(self) -> str:
        """Primary fingerprint for linked keys."""
        return self.linked_to or self.fingerprint


class KeyStore:
    """SQLite-backed key store for enrolled PGP keys.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False is safe here because KeyStore is a singleton
        # and all mutations use explicit commits with no concurrent writes in tests.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Create the keys table if it doesn't exist."""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS enrolled_keys (
                fingerprint TEXT PRIMARY KEY,
                public_key_armor TEXT NOT NULL,
                enrolled_at TEXT NOT NULL,
                last_auth TEXT,
                approved INTEGER DEFAULT 1,
                linked_to TEXT
            )
        """)
        self._conn.commit()

    def get(self, fingerprint: str) -> Optional[EnrolledKey]:
        """Look up an enrolled key by fingerprint.

        Args:
            fingerprint: 40-char PGP fingerprint.

        Returns:
            EnrolledKey or None if not enrolled.
        """
        row = self._conn.execute(
            "SELECT * FROM enrolled_keys WHERE fingerprint = ?",
            (fingerprint.upper(),),
        ).fetchone()
        if row is None:
            return None
        return EnrolledKey(
            fingerprint=row["fingerprint"],
            public_key_armor=row["public_key_armor"],
            enrolled_at=row["enrolled_at"],
            last_auth=row["last_auth"],
            approved=bool(row["approved"]),
            linked_to=row["linked_to"],
        )

    def enroll(
        self,
        fingerprint: str,
        public_key_armor: str,
        approved: bool = True,
    ) -> EnrolledKey:
        """Enroll a new PGP key.

        Args:
            fingerprint: 40-char PGP fingerprint.
            public_key_armor: ASCII-armored public key.
            approved: Whether the key is pre-approved.

        Returns:
            EnrolledKey: The enrolled key record.
        """
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT OR REPLACE INTO enrolled_keys
               (fingerprint, public_key_armor, enrolled_at, approved)
               VALUES (?, ?, ?, ?)""",
            (fingerprint.upper(), public_key_armor, now, int(approved)),
        )
        self._conn.commit()
        return EnrolledKey(
            fingerprint=fingerprint.upper(),
            public_key_armor=public_key_armor,
            enrolled_at=now,
            approved=approved,
        )

    def update_last_auth(self, fingerprint: str) -> None:
        """Record a successful authentication timestamp.

        Args:
            fingerprint: The fingerprint that authenticated.
        """
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE enrolled_keys SET last_auth = ? WHERE fingerprint = ?",
            (now, fingerprint.upper()),
        )
        self._conn.commit()

    def approve(self, fingerprint: str) -> bool:
        """Approve a pending key enrollment.

        Args:
            fingerprint: The fingerprint to approve.

        Returns:
            bool: True if the key was found and approved.
        """
        cursor = self._conn.execute(
            "UPDATE enrolled_keys SET approved = 1 WHERE fingerprint = ?",
            (fingerprint.upper(),),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def revoke(self, fingerprint: str) -> bool:
        """Remove an enrolled key.

        Args:
            fingerprint: The fingerprint to revoke.

        Returns:
            bool: True if the key was found and removed.
        """
        cursor = self._conn.execute(
            "DELETE FROM enrolled_keys WHERE fingerprint = ?",
            (fingerprint.upper(),),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_keys(self, approved_only: bool = False) -> list[EnrolledKey]:
        """List all enrolled keys.

        Args:
            approved_only: If True, only return approved keys.

        Returns:
            list[EnrolledKey]: All matching enrolled keys.
        """
        query = "SELECT * FROM enrolled_keys"
        if approved_only:
            query += " WHERE approved = 1"
        query += " ORDER BY enrolled_at DESC"

        rows = self._conn.execute(query).fetchall()
        return [
            EnrolledKey(
                fingerprint=r["fingerprint"],
                public_key_armor=r["public_key_armor"],
                enrolled_at=r["enrolled_at"],
                last_auth=r["last_auth"],
                approved=bool(r["approved"]),
                linked_to=r["linked_to"],
            )
            for r in rows
        ]

    def count(self) -> int:
        """Count enrolled keys."""
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM enrolled_keys").fetchone()
        return row["cnt"]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
