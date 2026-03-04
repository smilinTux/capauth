/**
 * Unit tests for background.js logic — focused on the pure functions:
 * nonce tracking/expiry, token cache TTL, and canonical payload helpers.
 *
 * The full chrome.* API surface is mocked. We test the handler logic in
 * isolation without a real browser environment.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Chrome API stub
// ---------------------------------------------------------------------------

const mockStorage = {};

globalThis.chrome = {
  storage: {
    local: {
      get: vi.fn(async (key) => {
        if (key === null) return { ...mockStorage };
        if (typeof key === "string") {
          return { [key]: mockStorage[key] };
        }
        const result = {};
        for (const k of (Array.isArray(key) ? key : [key])) {
          result[k] = mockStorage[k];
        }
        return result;
      }),
      set: vi.fn(async (obj) => {
        Object.assign(mockStorage, obj);
      }),
      remove: vi.fn(async (keys) => {
        const ks = Array.isArray(keys) ? keys : [keys];
        for (const k of ks) delete mockStorage[k];
      }),
    },
  },
  runtime: {
    onMessage: { addListener: vi.fn() },
    lastError: null,
    sendMessage: vi.fn(),
    openOptionsPage: vi.fn(),
  },
  tabs: {
    query: vi.fn(async () => [{ id: 1 }]),
    create: vi.fn(),
    sendMessage: vi.fn(),
  },
  alarms: {
    create: vi.fn(),
    onAlarm: { addListener: vi.fn() },
  },
};

// ---------------------------------------------------------------------------
// Import canonical helpers directly from openpgp.js (shared logic)
// ---------------------------------------------------------------------------

import {
  buildCanonicalNoncePayload,
  buildCanonicalClaimsPayload,
} from "../../lib/openpgp.js";

import { webcrypto } from "crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");

// ---------------------------------------------------------------------------
// Nonce TTL logic (extracted inline — mirrors background.js)
// ---------------------------------------------------------------------------

function makePendingNonces() {
  const map = new Map();

  function track(id, data, ttlMs = 60_000) {
    if (map.has(id)) clearTimeout(map.get(id).timeoutId);
    const timeoutId = setTimeout(() => map.delete(id), ttlMs);
    map.set(id, { challenge: data, created: Date.now(), timeoutId });
  }

  function consume(id) {
    const entry = map.get(id);
    if (!entry) return null;
    clearTimeout(entry.timeoutId);
    map.delete(id);
    return entry.challenge;
  }

  return { map, track, consume };
}

describe("Nonce TTL management", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("stores a nonce and returns it via consume", () => {
    const { track, consume } = makePendingNonces();
    track("nonce-1", { nonce: "nonce-1", service: "test.io" });
    const result = consume("nonce-1");
    expect(result).toEqual({ nonce: "nonce-1", service: "test.io" });
  });

  it("returns null for unknown nonce", () => {
    const { consume } = makePendingNonces();
    expect(consume("unknown")).toBeNull();
  });

  it("returns null after consume (one-shot)", () => {
    const { track, consume } = makePendingNonces();
    track("nonce-x", { nonce: "nonce-x" });
    consume("nonce-x");
    expect(consume("nonce-x")).toBeNull();
  });

  it("auto-expires nonces after TTL", () => {
    const { map, track } = makePendingNonces();
    track("expire-me", { nonce: "expire-me" }, 100);
    expect(map.has("expire-me")).toBe(true);
    vi.advanceTimersByTime(101);
    expect(map.has("expire-me")).toBe(false);
  });

  it("re-tracking a nonce resets its TTL", () => {
    const { map, track } = makePendingNonces();
    track("renew", { nonce: "renew" }, 100);
    vi.advanceTimersByTime(50);
    // Re-track with a fresh TTL
    track("renew", { nonce: "renew", refreshed: true }, 100);
    vi.advanceTimersByTime(51);
    // Should still be alive (total elapsed = 101ms but TTL reset at t=50)
    expect(map.has("renew")).toBe(true);
    vi.advanceTimersByTime(50);
    // Now fully expired
    expect(map.has("renew")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Token expiry helpers
// ---------------------------------------------------------------------------

describe("Token cache expiry check", () => {
  function isExpired(cached) {
    const cachedAt = new Date(cached.cached_at).getTime();
    const expiresIn = (cached.expires_in || 3600) * 1000;
    return Date.now() > cachedAt + expiresIn;
  }

  it("fresh token is not expired", () => {
    const cached = { cached_at: new Date().toISOString(), expires_in: 3600 };
    expect(isExpired(cached)).toBe(false);
  });

  it("old token is expired", () => {
    // cached 2 hours ago, expires_in = 3600s
    const past = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    const cached = { cached_at: past, expires_in: 3600 };
    expect(isExpired(cached)).toBe(true);
  });

  it("uses 3600s default if expires_in missing", () => {
    const past = new Date(Date.now() - 3601 * 1000).toISOString();
    const cached = { cached_at: past };
    expect(isExpired(cached)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Canonical payload round-trips (shared with server validation)
// ---------------------------------------------------------------------------

describe("Canonical payload determinism", () => {
  it("nonce payload is stable across calls", () => {
    const params = {
      nonce: "550e8400-e29b-41d4-a716-446655440000",
      clientNonce: "abc123==",
      timestamp: "2026-02-27T12:00:00Z",
      service: "nextcloud.skworld.io",
      expires: "2026-02-27T12:01:00Z",
    };
    expect(buildCanonicalNoncePayload(params)).toBe(buildCanonicalNoncePayload(params));
  });

  it("claims payload sorts keys deterministically", () => {
    const p1 = buildCanonicalClaimsPayload({
      fingerprint: "AAAA",
      nonce: "n1",
      claims: { z: 1, a: 2, m: 3 },
    });
    const p2 = buildCanonicalClaimsPayload({
      fingerprint: "AAAA",
      nonce: "n1",
      claims: { m: 3, z: 1, a: 2 },
    });
    expect(p1).toBe(p2);
    expect(p1).toContain('"a":2,"m":3,"z":1');
  });
});
