import { describe, it, expect, beforeAll, beforeEach } from "vitest";

let RBACAnalyzer;

beforeAll(async () => {
  await import("../lib/rbac-analyzer.js");
  RBACAnalyzer = globalThis.__R3D.RBACAnalyzer;
});

function makeEntry(overrides = {}) {
  return {
    url: "https://app.com/api/data",
    method: "GET",
    status: 200,
    requestHeaders: {},
    ts: Date.now(),
    ...overrides,
  };
}

describe("PermissionMatrix", () => {
  let matrix;

  beforeEach(() => {
    matrix = new RBACAnalyzer.PermissionMatrix();
  });

  describe("_normalizePattern", () => {
    it("replaces ObjectIds with {id}", () => {
      const result = matrix._normalizePattern("https://app.com/users/507f1f77bcf86cd799439011/profile");
      expect(result).toContain("{id}");
      expect(result).not.toContain("507f1f77bcf86cd799439011");
    });

    it("replaces UUIDs with {id}", () => {
      const result = matrix._normalizePattern("https://app.com/items/550e8400-e29b-41d4-a716-446655440000");
      expect(result).toContain("{id}");
    });

    it("replaces numeric IDs with {id}", () => {
      const result = matrix._normalizePattern("https://app.com/items/12345");
      expect(result).toContain("{id}");
    });

    it("leaves non-ID segments alone", () => {
      const result = matrix._normalizePattern("https://app.com/api/users/profile");
      expect(result).toBe("/api/users/profile");
    });
  });

  describe("_classifyElevation", () => {
    it("detects admin paths", () => {
      const result = matrix._classifyElevation("https://app.com/admin/users");
      expect(result.some((e) => e.label === "admin")).toBe(true);
    });

    it("detects internal paths", () => {
      const result = matrix._classifyElevation("https://app.com/internal/config");
      expect(result.some((e) => e.label === "internal")).toBe(true);
    });

    it("detects metrics endpoint", () => {
      const result = matrix._classifyElevation("https://app.com/metrics");
      expect(result.some((e) => e.label === "metrics")).toBe(true);
    });

    it("returns empty for normal paths", () => {
      const result = matrix._classifyElevation("https://app.com/api/users");
      expect(result).toHaveLength(0);
    });
  });

  describe("_detectCSRFProtection", () => {
    it("returns true when CSRF header present", () => {
      expect(matrix._detectCSRFProtection({ requestHeaders: { "X-CSRF-Token": "abc" } })).toBe(true);
    });

    it("returns true for XSRF header", () => {
      expect(matrix._detectCSRFProtection({ requestHeaders: { "X-XSRF-Token": "abc" } })).toBe(true);
    });

    it("returns false when no CSRF headers", () => {
      expect(matrix._detectCSRFProtection({ requestHeaders: { "Content-Type": "application/json" } })).toBe(false);
    });

    it("returns false when no headers at all", () => {
      expect(matrix._detectCSRFProtection({})).toBe(false);
    });
  });

  describe("addRequest", () => {
    it("detects elevated endpoint returning 200", () => {
      const findings = matrix.addRequest(makeEntry({
        url: "https://app.com/admin/users",
        status: 200,
      }));
      expect(findings.some((f) => f.title.includes("Elevated endpoint"))).toBe(true);
    });

    it("no elevation finding for normal endpoints", () => {
      const findings = matrix.addRequest(makeEntry({
        url: "https://app.com/api/data",
        status: 200,
      }));
      const elevFindings = findings.filter((f) => f.title.includes("Elevated"));
      expect(elevFindings).toHaveLength(0);
    });

    it("detects write without CSRF", () => {
      const findings = matrix.addRequest(makeEntry({
        url: "https://app.com/api/update",
        method: "POST",
        status: 200,
        requestHeaders: { "Content-Type": "application/json" },
      }));
      expect(findings.some((f) => f.title.includes("CSRF"))).toBe(true);
    });

    it("no CSRF finding when CSRF header present", () => {
      const findings = matrix.addRequest(makeEntry({
        url: "https://app.com/api/update",
        method: "POST",
        status: 200,
        requestHeaders: { "X-CSRF-Token": "tok123" },
      }));
      const csrfFindings = findings.filter((f) => f.title.includes("CSRF"));
      expect(csrfFindings).toHaveLength(0);
    });

    it("tracks access patterns", () => {
      matrix.addRequest(makeEntry({ status: 200 }));
      matrix.addRequest(makeEntry({ url: "https://app.com/secret", status: 403 }));
      const patterns = matrix.getAccessPatterns();
      expect(patterns.allowed.length).toBe(1);
      expect(patterns.denied.length).toBe(1);
    });
  });

  describe("analyzePrivilegeGaps", () => {
    it("detects elevated access without admin groups", () => {
      matrix.setJWTClaims({ groups: ["users", "readers"], roles: [] });
      matrix.addRequest(makeEntry({ url: "https://app.com/admin/settings", status: 200 }));
      const findings = matrix.analyzePrivilegeGaps();
      expect(findings.some((f) => f.severity === "CRITICAL")).toBe(true);
    });

    it("no finding when admin group present", () => {
      matrix.setJWTClaims({ groups: ["admin", "users"] });
      matrix.addRequest(makeEntry({ url: "https://app.com/admin/settings", status: 200 }));
      const findings = matrix.analyzePrivilegeGaps();
      expect(findings).toHaveLength(0);
    });

    it("no finding without JWT claims", () => {
      matrix.addRequest(makeEntry({ url: "https://app.com/admin/settings", status: 200 }));
      const findings = matrix.analyzePrivilegeGaps();
      expect(findings).toHaveLength(0);
    });
  });

  describe("getSurfaceReport", () => {
    it("aggregates endpoint statistics", () => {
      matrix.addRequest(makeEntry({ method: "GET", status: 200 }));
      matrix.addRequest(makeEntry({ url: "https://app.com/admin/x", method: "POST", status: 200, requestHeaders: { "X-CSRF-Token": "x" } }));
      matrix.addRequest(makeEntry({ url: "https://app.com/denied", method: "GET", status: 403 }));
      const report = matrix.getSurfaceReport();
      expect(report.totalEndpoints).toBe(3);
      expect(report.elevated.length).toBeGreaterThanOrEqual(1);
      expect(report.writeEndpoints.length).toBeGreaterThanOrEqual(1);
      expect(report.byMethod.GET).toBeGreaterThanOrEqual(1);
    });
  });
});

describe("ELEVATED_PATH_PATTERNS", () => {
  it("has patterns for key elevated paths", () => {
    const labels = RBACAnalyzer.ELEVATED_PATH_PATTERNS.map((p) => p.label);
    expect(labels).toContain("admin");
    expect(labels).toContain("internal");
    expect(labels).toContain("debug");
    expect(labels).toContain("metrics");
  });
});
