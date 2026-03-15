import { describe, it, expect, beforeAll, beforeEach } from "vitest";

let IDORDetector;

beforeAll(async () => {
  await import("../lib/idor-detector.js");
  IDORDetector = globalThis.__R3D.IDORDetector;
});

describe("ID_PATTERNS", () => {
  it("matches ObjectId", () => {
    const match = IDORDetector.ID_PATTERNS.find((p) => p.regex.test("507f1f77bcf86cd799439011"));
    expect(match).toBeDefined();
    expect(match.type).toBe("ObjectId");
  });

  it("matches UUID", () => {
    const match = IDORDetector.ID_PATTERNS.find((p) => p.regex.test("550e8400-e29b-41d4-a716-446655440000"));
    expect(match).toBeDefined();
    expect(match.type).toBe("UUID");
  });

  it("matches numeric ID", () => {
    const match = IDORDetector.ID_PATTERNS.find((p) => p.regex.test("12345"));
    expect(match).toBeDefined();
    expect(match.type).toBe("NumericId");
  });

  it("does not match short numbers", () => {
    const match = IDORDetector.ID_PATTERNS.find((p) => p.regex.test("5"));
    expect(match).toBeUndefined();
  });

  it("does not match regular words", () => {
    const match = IDORDetector.ID_PATTERNS.find((p) => p.regex.test("users"));
    expect(match).toBeUndefined();
  });
});

describe("SENSITIVE_SUBPATHS", () => {
  it("includes critical paths", () => {
    for (const p of ["entitlements", "credentials", "profile", "settings", "permissions"]) {
      expect(IDORDetector.SENSITIVE_SUBPATHS.has(p)).toBe(true);
    }
  });
});

describe("EndpointCatalog", () => {
  let catalog;

  beforeEach(() => {
    catalog = new IDORDetector.EndpointCatalog();
  });

  it("ignores URLs without ID segments", () => {
    const findings = catalog.addRequest({
      url: "https://app.com/api/health",
      method: "GET",
      status: 200,
      ts: Date.now(),
    });
    expect(findings).toHaveLength(0);
    expect(catalog.getEndpoints()).toHaveLength(0);
  });

  it("catalogs endpoints with ObjectId segments", () => {
    catalog.addRequest({
      url: "https://app.com/users/507f1f77bcf86cd799439011/profile",
      method: "GET",
      status: 200,
      ts: Date.now(),
    });
    const eps = catalog.getEndpoints();
    expect(eps).toHaveLength(1);
    expect(eps[0].pattern).toContain("{ObjectId}");
  });

  it("detects IDOR when accessing another user's data", () => {
    catalog.setCurrentUserId("aaa111bbb222ccc333ddd444");
    const findings = catalog.addRequest({
      url: "https://app.com/users/507f1f77bcf86cd799439011/profile",
      method: "GET",
      status: 200,
      ts: Date.now(),
    });
    expect(findings.some((f) => f.title.includes("IDOR"))).toBe(true);
  });

  it("no IDOR for own user ID", () => {
    catalog.setCurrentUserId("507f1f77bcf86cd799439011");
    const findings = catalog.addRequest({
      url: "https://app.com/users/507f1f77bcf86cd799439011/profile",
      method: "GET",
      status: 200,
      ts: Date.now(),
    });
    const idorFindings = findings.filter((f) => f.title.includes("IDOR"));
    expect(idorFindings).toHaveLength(0);
  });

  it("detects admin endpoint access", () => {
    const findings = catalog.addRequest({
      url: "https://app.com/admin/users/12345",
      method: "GET",
      status: 200,
      ts: Date.now(),
    });
    expect(findings.some((f) => f.title.includes("Admin"))).toBe(true);
  });

  it("detects sequential IDs", () => {
    for (const id of [100, 101]) {
      catalog.addRequest({
        url: `https://app.com/items/${id}`,
        method: "GET",
        status: 200,
        ts: Date.now(),
      });
    }
    const eps = catalog.getEndpoints();
    const seqFindings = eps.flatMap((e) => e.findings).filter((f) => f.title.includes("Sequential"));
    expect(seqFindings.length).toBeGreaterThanOrEqual(1);
  });

  it("buildReplayRequest swaps ID", () => {
    catalog.addRequest({
      url: "https://app.com/users/507f1f77bcf86cd799439011",
      method: "GET",
      status: 200,
      ts: Date.now(),
    });
    const ep = catalog.getEndpoints()[0];
    const replay = catalog.buildReplayRequest(ep.pattern, "aaa111bbb222ccc333ddd444");
    expect(replay).not.toBeNull();
    expect(replay.url).toContain("aaa111bbb222ccc333ddd444");
    expect(replay.newId).toBe("aaa111bbb222ccc333ddd444");
  });

  it("buildReplayRequest returns null for unknown pattern", () => {
    expect(catalog.buildReplayRequest("nonexistent", "id")).toBeNull();
  });
});
