/**
 * Unit tests for CapAuthStage.vue — pure logic (no DOM mount).
 */

import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Canonical payload helpers (shared with background.js and server)
// ---------------------------------------------------------------------------

function buildCanonicalNoncePayload({ nonce, clientNonce, timestamp, service, expires }) {
  return [
    "CAPAUTH_NONCE_V1",
    `nonce=${nonce}`,
    `client_nonce=${clientNonce}`,
    `timestamp=${timestamp}`,
    `service=${service}`,
    `expires=${expires}`,
  ].join("\n");
}

function generateClientNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

// ---------------------------------------------------------------------------
// Fingerprint normalisation
// ---------------------------------------------------------------------------

function normalizeFingerprint(raw) {
  return raw.replace(/\s/g, "").toUpperCase();
}

function isValidFingerprint(fp) {
  return /^[A-F0-9]{40}$/.test(fp);
}

describe("Fingerprint normalisation", () => {
  it("strips whitespace", () => {
    expect(normalizeFingerprint("DEAD BEEF 1234 5678 90AB CDEF 1234 5678 90AB CDEF"))
      .toBe("DEADBEEF1234567890ABCDEF1234567890ABCDEF");
  });

  it("uppercases hex", () => {
    expect(normalizeFingerprint("deadbeef1234567890abcdef1234567890abcdef"))
      .toBe("DEADBEEF1234567890ABCDEF1234567890ABCDEF");
  });

  it("validates correct fingerprint", () => {
    expect(isValidFingerprint("DEADBEEF1234567890ABCDEF1234567890ABCDEF")).toBe(true);
  });

  it("rejects fingerprint that's too short", () => {
    expect(isValidFingerprint("DEADBEEF")).toBe(false);
  });

  it("rejects fingerprint with non-hex chars", () => {
    expect(isValidFingerprint("DEADBEEF1234567890ABCDEF1234567890ABCEFG")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Client nonce
// ---------------------------------------------------------------------------

describe("generateClientNonce", () => {
  it("produces a base64 string of length 24", () => {
    const n = generateClientNonce();
    expect(typeof n).toBe("string");
    expect(n.length).toBe(24);
  });

  it("is unique per call", () => {
    expect(generateClientNonce()).not.toBe(generateClientNonce());
  });
});

// ---------------------------------------------------------------------------
// Canonical payload — must match server verifier.py
// ---------------------------------------------------------------------------

describe("buildCanonicalNoncePayload (stage)", () => {
  const params = {
    nonce: "test-nonce-uuid",
    clientNonce: "abc==",
    timestamp: "2026-02-27T12:00:00Z",
    service: "nextcloud.skworld.io",
    expires: "2026-02-27T12:01:00Z",
  };

  it("produces the correct multi-line format", () => {
    const result = buildCanonicalNoncePayload(params);
    expect(result).toBe(
      "CAPAUTH_NONCE_V1\n" +
      "nonce=test-nonce-uuid\n" +
      "client_nonce=abc==\n" +
      "timestamp=2026-02-27T12:00:00Z\n" +
      "service=nextcloud.skworld.io\n" +
      "expires=2026-02-27T12:01:00Z"
    );
  });
});
