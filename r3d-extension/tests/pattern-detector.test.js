import { describe, it, expect, beforeAll, beforeEach } from "vitest";

let PatternDetector;

beforeAll(async () => {
  await import("../lib/pattern-detector.js");
  PatternDetector = globalThis.__R3D.PatternDetector;
});

function makeRequest(overrides = {}) {
  return {
    url: "https://app.com/api/data",
    method: "GET",
    status: 200,
    requestHeaders: {},
    responseHeaders: {},
    responseContentType: "application/json",
    responseSize: 100,
    ts: Date.now(),
    ...overrides,
  };
}

describe("Pattern detect functions", () => {
  it("bulk-user-enumeration detects 3+ user IDs on same pattern", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "bulk-user-enumeration");
    const ctx = {
      requests: [
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439011", status: 200 }),
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439012", status: 200 }),
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439013", status: 200 }),
      ],
    };
    expect(pattern.detect(ctx)).not.toBeNull();
  });

  it("bulk-user-enumeration returns null for <3 IDs", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "bulk-user-enumeration");
    const ctx = {
      requests: [
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439011", status: 200 }),
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439012", status: 200 }),
      ],
    };
    expect(pattern.detect(ctx)).toBeNull();
  });

  it("admin-endpoint-accessible detects 2+ admin hits", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "admin-endpoint-accessible");
    const ctx = {
      requests: [
        makeRequest({ url: "https://app.com/admin/users", status: 200 }),
        makeRequest({ url: "https://app.com/admin/settings", status: 200 }),
      ],
    };
    expect(pattern.detect(ctx)).not.toBeNull();
  });

  it("sensitive-data-over-get detects tokens in URL", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "sensitive-data-over-get");
    const ctx = {
      requests: [makeRequest({ url: "https://app.com/auth?token=abc123" })],
    };
    expect(pattern.detect(ctx)).not.toBeNull();
  });

  it("error-information-leak detects 3+ 5xx errors", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "error-information-leak");
    const ctx = {
      requests: [
        makeRequest({ url: "https://app.com/a", status: 500 }),
        makeRequest({ url: "https://app.com/b", status: 502 }),
        makeRequest({ url: "https://app.com/c", status: 503 }),
      ],
    };
    expect(pattern.detect(ctx)).not.toBeNull();
  });

  it("mixed-auth-methods detects 2+ auth methods on same domain", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "mixed-auth-methods");
    const ctx = {
      requests: [
        makeRequest({
          url: "https://app.com/a",
          requestHeaders: { Authorization: "Bearer tok" },
        }),
        makeRequest({
          url: "https://app.com/b",
          requestHeaders: { Cookie: "auth_token=abc" },
        }),
      ],
    };
    expect(pattern.detect(ctx)).not.toBeNull();
  });

  it("horizontal-priv-esc detects 2+ user IDs on sensitive paths", () => {
    const pattern = PatternDetector.PATTERNS.find((p) => p.id === "horizontal-priv-esc");
    const ctx = {
      requests: [
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439011/entitlements", status: 200 }),
        makeRequest({ url: "https://app.com/users/507f1f77bcf86cd799439012/entitlements", status: 200 }),
      ],
    };
    expect(pattern.detect(ctx)).not.toBeNull();
  });
});

describe("PatternEngine", () => {
  let engine;

  beforeEach(() => {
    engine = new PatternDetector.PatternEngine();
  });

  it("addRequest buffers entries", () => {
    engine.addRequest(makeRequest());
    engine.addRequest(makeRequest());
    expect(engine._requestBuffer).toHaveLength(2);
  });

  it("trims buffer at 2000", () => {
    for (let i = 0; i < 2100; i++) {
      engine.addRequest(makeRequest({ url: `https://app.com/${i}` }));
    }
    expect(engine._requestBuffer.length).toBeLessThanOrEqual(1600);
  });

  it("analyze returns findings for detected patterns", () => {
    const adminRequests = Array.from({ length: 3 }, (_, i) =>
      makeRequest({ url: `https://app.com/admin/endpoint${i}`, status: 200 }),
    );
    for (const r of adminRequests) engine.addRequest(r);
    engine._lastAnalysis = 0;
    const findings = engine.analyze();
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("analyze respects interval throttle", () => {
    engine.addRequest(makeRequest({ url: "https://app.com/admin/x", status: 200 }));
    engine.addRequest(makeRequest({ url: "https://app.com/admin/y", status: 200 }));
    engine._lastAnalysis = Date.now();
    const findings = engine.analyze();
    expect(findings).toHaveLength(0);
  });

  it("getDetectedPatterns returns detected pattern metadata", () => {
    for (let i = 0; i < 3; i++) {
      engine.addRequest(makeRequest({ url: `https://app.com/admin/ep${i}`, status: 200 }));
    }
    engine._lastAnalysis = 0;
    engine.analyze();
    const detected = engine.getDetectedPatterns();
    expect(detected.length).toBeGreaterThanOrEqual(1);
    expect(detected[0]).toHaveProperty("id");
    expect(detected[0]).toHaveProperty("name");
  });

  it("clear resets engine state", () => {
    engine.addRequest(makeRequest());
    engine.clear();
    expect(engine._requestBuffer).toHaveLength(0);
    expect(engine.getDetectedPatterns()).toHaveLength(0);
  });
});
