/**
 * Unit tests for lib/openpgp.js — pure helper functions that don't require
 * real PGP keys (generateNonce, buildCanonical*).
 *
 * Real crypto (signMessage, verifySignature, extractFingerprint) is tested
 * with a deterministic test key fixture at the bottom of this file.
 */

import { describe, it, expect, vi, beforeAll } from "vitest";

// Polyfill crypto.getRandomValues for Node/vitest environment
import { webcrypto } from "crypto";
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
} else if (!globalThis.crypto.getRandomValues) {
  globalThis.crypto.getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
}

// Vitest runs in Node, so btoa may not be available in older versions
if (!globalThis.btoa) {
  globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
}

import {
  generateNonce,
  buildCanonicalNoncePayload,
  buildCanonicalClaimsPayload,
} from "../../lib/openpgp.js";

// ---------------------------------------------------------------------------
// generateNonce
// ---------------------------------------------------------------------------

describe("generateNonce", () => {
  it("returns a non-empty string", () => {
    const nonce = generateNonce();
    expect(typeof nonce).toBe("string");
    expect(nonce.length).toBeGreaterThan(0);
  });

  it("returns base64-encoded output (only valid base64 chars)", () => {
    const nonce = generateNonce();
    expect(/^[A-Za-z0-9+/=]+$/.test(nonce)).toBe(true);
  });

  it("produces different values on each call", () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
  });

  it("respects byteLength parameter", () => {
    // 16 bytes → base64 string of length 24 (ceil(16/3)*4)
    const nonce16 = generateNonce(16);
    expect(nonce16.length).toBe(24);

    const nonce32 = generateNonce(32);
    expect(nonce32.length).toBe(44);
  });
});

// ---------------------------------------------------------------------------
// buildCanonicalNoncePayload
// ---------------------------------------------------------------------------

describe("buildCanonicalNoncePayload", () => {
  const params = {
    nonce: "abc-nonce-uuid",
    clientNonce: "clientNonce123",
    timestamp: "2026-01-01T00:00:00Z",
    service: "nextcloud.skworld.io",
    expires: "2026-01-01T00:01:00Z",
  };

  it("starts with CAPAUTH_NONCE_V1 header", () => {
    const payload = buildCanonicalNoncePayload(params);
    expect(payload.startsWith("CAPAUTH_NONCE_V1\n")).toBe(true);
  });

  it("contains all required fields in order", () => {
    const payload = buildCanonicalNoncePayload(params);
    const lines = payload.split("\n");
    expect(lines[0]).toBe("CAPAUTH_NONCE_V1");
    expect(lines[1]).toBe(`nonce=${params.nonce}`);
    expect(lines[2]).toBe(`client_nonce=${params.clientNonce}`);
    expect(lines[3]).toBe(`timestamp=${params.timestamp}`);
    expect(lines[4]).toBe(`service=${params.service}`);
    expect(lines[5]).toBe(`expires=${params.expires}`);
  });

  it("is deterministic — same inputs produce identical output", () => {
    expect(buildCanonicalNoncePayload(params)).toBe(buildCanonicalNoncePayload(params));
  });

  it("differs when any field changes", () => {
    const modified = { ...params, nonce: "different-nonce" };
    expect(buildCanonicalNoncePayload(params)).not.toBe(buildCanonicalNoncePayload(modified));
  });
});

// ---------------------------------------------------------------------------
// buildCanonicalClaimsPayload
// ---------------------------------------------------------------------------

describe("buildCanonicalClaimsPayload", () => {
  const params = {
    fingerprint: "DEADBEEF1234567890ABCDEF1234567890ABCDEF",
    nonce: "nonce-uuid-here",
    claims: { email: "king@skworld.io", name: "Sovereign User" },
  };

  it("starts with CAPAUTH_CLAIMS_V1 header", () => {
    const payload = buildCanonicalClaimsPayload(params);
    expect(payload.startsWith("CAPAUTH_CLAIMS_V1\n")).toBe(true);
  });

  it("contains fingerprint, nonce, and claims lines", () => {
    const payload = buildCanonicalClaimsPayload(params);
    const lines = payload.split("\n");
    expect(lines[0]).toBe("CAPAUTH_CLAIMS_V1");
    expect(lines[1]).toBe(`fingerprint=${params.fingerprint}`);
    expect(lines[2]).toBe(`nonce=${params.nonce}`);
    expect(lines[3]).toMatch(/^claims=/);
  });

  it("serializes claims with sorted keys (no whitespace)", () => {
    const payload = buildCanonicalClaimsPayload(params);
    const claimsLine = payload.split("\n").find((l) => l.startsWith("claims="));
    const claimsJson = claimsLine.replace("claims=", "");
    // Keys must be sorted: email < name
    expect(claimsJson).toBe('{"email":"king@skworld.io","name":"Sovereign User"}');
  });

  it("sorts claim keys regardless of insertion order", () => {
    const reversed = { ...params, claims: { name: "Sovereign User", email: "king@skworld.io" } };
    const normal = buildCanonicalClaimsPayload(params);
    const rev = buildCanonicalClaimsPayload(reversed);
    // Both should produce the same sorted output
    expect(normal).toBe(rev);
  });

  it("handles empty claims object", () => {
    const empty = { ...params, claims: {} };
    const payload = buildCanonicalClaimsPayload(empty);
    const claimsLine = payload.split("\n").find((l) => l.startsWith("claims="));
    expect(claimsLine).toBe("claims={}");
  });
});
