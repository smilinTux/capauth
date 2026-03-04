/**
 * Unit tests for content_scripts/detector.js — detection logic.
 *
 * We extract the pure detection functions and test them in a minimal
 * jsdom-like environment provided by vitest's happy-dom.
 */

import { describe, it, expect, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Inline the detection logic (extracted from detector.js for testability)
// Without a real DOM we can't import the module directly since it auto-runs.
// ---------------------------------------------------------------------------

function detectCapAuth(doc) {
  // Method 1: data-capauth attribute
  const dataAttrEl = doc.querySelector("[data-capauth]");
  if (dataAttrEl) {
    return {
      method: "data-attribute",
      serviceUrl: dataAttrEl.getAttribute("data-capauth") || "",
      redirectUrl: dataAttrEl.getAttribute("data-capauth-redirect") || "",
      targetElement: dataAttrEl,
    };
  }

  // Method 2: meta tag
  const metaTag = doc.querySelector('meta[name="capauth-service"]');
  if (metaTag) {
    const serviceUrl = metaTag.getAttribute("content") || "";
    const redirectMeta = doc.querySelector('meta[name="capauth-redirect"]');
    return {
      method: "meta-tag",
      serviceUrl,
      redirectUrl: redirectMeta?.getAttribute("content") || "",
      targetElement: null,
    };
  }

  // Method 3: link tag
  const linkTag = doc.querySelector('link[rel="capauth"]');
  if (linkTag) {
    return {
      method: "link-tag",
      serviceUrl: linkTag.getAttribute("href") || "",
      redirectUrl: "",
      targetElement: null,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Minimal DOM builder (no jsdom dependency needed)
// ---------------------------------------------------------------------------

function makeDoc(html) {
  // Use vitest's globalThis.document (happy-dom / jsdom environment)
  const parser = new DOMParser();
  return parser.parseFromString(`<!DOCTYPE html><html><head></head><body>${html}</body></html>`, "text/html");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("detectCapAuth", () => {
  it("returns null on a plain page with no CapAuth markers", () => {
    const doc = makeDoc("<div><form><input type='password'></form></div>");
    expect(detectCapAuth(doc)).toBeNull();
  });

  it("detects via data-capauth attribute", () => {
    const doc = makeDoc(
      `<div data-capauth="https://auth.skworld.io" data-capauth-redirect="https://app.skworld.io/dashboard"></div>`
    );
    const result = detectCapAuth(doc);
    expect(result).not.toBeNull();
    expect(result.method).toBe("data-attribute");
    expect(result.serviceUrl).toBe("https://auth.skworld.io");
    expect(result.redirectUrl).toBe("https://app.skworld.io/dashboard");
  });

  it("data-capauth with empty redirect defaults to empty string", () => {
    const doc = makeDoc(`<div data-capauth="https://auth.skworld.io"></div>`);
    const result = detectCapAuth(doc);
    expect(result.redirectUrl).toBe("");
  });

  it("detects via meta tag", () => {
    const doc = makeDoc(
      `<meta name="capauth-service" content="https://nextcloud.skworld.io">` +
      `<meta name="capauth-redirect" content="https://nextcloud.skworld.io/home">`
    );
    const result = detectCapAuth(doc);
    expect(result).not.toBeNull();
    expect(result.method).toBe("meta-tag");
    expect(result.serviceUrl).toBe("https://nextcloud.skworld.io");
    expect(result.redirectUrl).toBe("https://nextcloud.skworld.io/home");
    expect(result.targetElement).toBeNull();
  });

  it("meta-tag without redirect gives empty redirectUrl", () => {
    const doc = makeDoc(`<meta name="capauth-service" content="https://s.io">`);
    const result = detectCapAuth(doc);
    expect(result.redirectUrl).toBe("");
  });

  it("detects via link rel=capauth", () => {
    const doc = makeDoc(`<link rel="capauth" href="https://auth.skworld.io/capauth/v1">`);
    const result = detectCapAuth(doc);
    expect(result).not.toBeNull();
    expect(result.method).toBe("link-tag");
    expect(result.serviceUrl).toBe("https://auth.skworld.io/capauth/v1");
    expect(result.redirectUrl).toBe("");
  });

  it("data-attribute takes priority over meta tag", () => {
    const doc = makeDoc(
      `<meta name="capauth-service" content="https://meta.io">` +
      `<div data-capauth="https://data.io"></div>`
    );
    const result = detectCapAuth(doc);
    expect(result.method).toBe("data-attribute");
    expect(result.serviceUrl).toBe("https://data.io");
  });

  it("meta-tag takes priority over link tag", () => {
    const doc = makeDoc(
      `<link rel="capauth" href="https://link.io">` +
      `<meta name="capauth-service" content="https://meta.io">`
    );
    const result = detectCapAuth(doc);
    expect(result.method).toBe("meta-tag");
    expect(result.serviceUrl).toBe("https://meta.io");
  });
});
