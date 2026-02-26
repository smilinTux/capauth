"""Tests for the CapAuth nonce store (replay protection)."""

from __future__ import annotations

import time

import pytest

from capauth.authentik.nonce_store import consume, issue, peek


class TestIssue:
    def test_issue_returns_valid_nonce(self):
        """Issued nonce has all required fields and is not used."""
        record = issue("ABCD1234" * 5)
        assert "nonce" in record
        assert "fingerprint" in record
        assert "issued_at" in record
        assert "expires_at" in record
        assert record["used"] is False

    def test_issue_different_nonces_each_time(self):
        """Each call generates a unique nonce UUID."""
        fp = "AAAA0000" * 5
        n1 = issue(fp)
        n2 = issue(fp)
        assert n1["nonce"] != n2["nonce"]

    def test_peek_returns_issued_nonce(self):
        """peek() returns the stored record without consuming it."""
        fp = "BBBB1111" * 5
        record = issue(fp)
        peeked = peek(record["nonce"])
        assert peeked is not None
        assert peeked["nonce"] == record["nonce"]


class TestConsume:
    def test_consume_valid_nonce_succeeds(self):
        """A fresh, valid nonce is consumed successfully."""
        fp = "CCCC2222" * 5
        record = issue(fp)
        success, err = consume(record["nonce"], fp)
        assert success is True
        assert err == ""

    def test_consume_marks_nonce_used(self):
        """A consumed nonce is rejected on second attempt."""
        fp = "DDDD3333" * 5
        record = issue(fp)
        consume(record["nonce"], fp)
        # Second attempt must fail
        success, err = consume(record["nonce"], fp)
        assert success is False
        assert err == "invalid_nonce"

    def test_consume_wrong_fingerprint_rejected(self):
        """A nonce consumed by a different fingerprint is rejected."""
        fp_a = "EEEE4444" * 5
        fp_b = "FFFF5555" * 5
        record = issue(fp_a)
        success, err = consume(record["nonce"], fp_b)
        assert success is False
        assert err == "invalid_nonce"

    def test_consume_nonexistent_nonce_rejected(self):
        """Consuming a nonce that was never issued returns invalid_nonce."""
        success, err = consume("00000000-0000-0000-0000-000000000000", "A" * 40)
        assert success is False
        assert err == "invalid_nonce"

    def test_expired_nonce_rejected(self, monkeypatch):
        """A nonce past its expiry window is rejected as expired."""
        from capauth.authentik import nonce_store
        from datetime import datetime, timedelta, timezone

        fp = "GGGG6666" * 5
        record = issue(fp)

        # Patch _now() to return a time well past the 60-second window
        def future_now():
            return datetime.now(timezone.utc) + timedelta(seconds=120)

        monkeypatch.setattr(nonce_store, "_now", future_now)

        success, err = consume(record["nonce"], fp)
        assert success is False
        assert err == "expired_nonce"
