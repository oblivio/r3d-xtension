import { describe, it, expect, beforeAll } from "vitest";

let HeaderAuditor;

beforeAll(async () => {
  await import("../lib/header-auditor.js");
  HeaderAuditor = globalThis.__R3D.HeaderAuditor;
});

function makeScorecard() {
  return new HeaderAuditor.DomainScorecard();
}

// ── DomainScorecard.auditResponse ───────────────────────────────────

describe("HeaderAuditor.DomainScorecard", () => {
  it("flags missing CSP on HTML response", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/page", {
      "content-type": "text/html",
    });
    expect(findings.some((f) => f.title.includes("content-security-policy"))).toBe(true);
  });

  it("skips document-only headers on non-HTML responses", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/api/data", {
      "content-type": "application/json",
    });
    const cspFindings = findings.filter((f) =>
      f.evidence?.header === "content-security-policy"
    );
    expect(cspFindings).toHaveLength(0);
  });

  it("flags weak CSP with unsafe-inline", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/page", {
      "content-type": "text/html",
      "content-security-policy": "default-src 'self' 'unsafe-inline'",
    });
    expect(findings.some((f) => f.detail.includes("unsafe-inline"))).toBe(true);
  });

  it("flags critical CSP bypass (unsafe-inline + localhost)", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/page", {
      "content-type": "text/html",
      "content-security-policy": "default-src 'self' 'unsafe-inline'; connect-src http://localhost:3000",
    });
    expect(findings.some((f) => f.severity === "CRITICAL")).toBe(true);
  });

  it("passes strong CSP", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/page", {
      "content-type": "text/html",
      "content-security-policy": "default-src 'self'; script-src 'nonce-abc'",
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()",
    });
    const headerFindings = findings.filter((f) => f.module === "headers" && f.evidence?.header);
    expect(headerFindings).toHaveLength(0);
  });

  it("flags missing HSTS", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/page", {
      "content-type": "text/html",
    });
    expect(findings.some((f) => f.title.includes("strict-transport-security"))).toBe(true);
  });

  it("flags HSTS with short max-age", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/page", {
      "content-type": "text/html",
      "strict-transport-security": "max-age=3600",
    });
    expect(findings.some((f) => f.detail.includes("max-age"))).toBe(true);
  });

  it("flags missing X-Content-Type-Options", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/api", {
      "content-type": "application/json",
    });
    expect(findings.some((f) => f.title.includes("x-content-type-options"))).toBe(true);
  });

  it("flags server info disclosure", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/api", {
      "content-type": "application/json",
      server: "Apache/2.4.51",
      "x-powered-by": "Express",
    });
    expect(findings.filter((f) => f.title.includes("Server info")).length).toBeGreaterThanOrEqual(2);
  });

  it("flags CORS wildcard with credentials", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app.com/api", {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    });
    expect(findings.some((f) => f.title.includes("CORS") && f.severity === "CRITICAL")).toBe(true);
  });

  it("flags CORS origin reflection", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse(
      "https://app.com/api",
      {
        "content-type": "application/json",
        "access-control-allow-origin": "https://evil.com",
        "access-control-allow-credentials": "true",
      },
      { Origin: "https://evil.com" },
    );
    expect(findings.some((f) => f.title.includes("origin reflection"))).toBe(true);
  });

  it("flags CORS null origin with credentials", () => {
    const sc = makeScorecard();
    const findings = sc.auditResponse("https://app2.com/api", {
      "content-type": "application/json",
      "access-control-allow-origin": "null",
      "access-control-allow-credentials": "true",
    });
    expect(findings.some((f) => f.title.includes("null origin"))).toBe(true);
  });

  it("tracks domain scores", () => {
    const sc = makeScorecard();
    sc.auditResponse("https://good.com/page", {
      "content-type": "text/html",
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=63072000; includeSubDomains",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin",
      "permissions-policy": "camera=()",
    });
    const scores = sc.getDomainScores();
    expect(scores.length).toBeGreaterThanOrEqual(1);
    const goodDomain = scores.find((s) => s.domain === "good.com");
    expect(goodDomain).toBeDefined();
    expect(goodDomain.score).toBeGreaterThan(0);
  });

  it("limits audits per domain to 3", () => {
    const sc = makeScorecard();
    const headers = { "content-type": "text/html" };
    for (let i = 0; i < 5; i++) {
      sc.auditResponse("https://limited.com/page", headers);
    }
    // 4th and 5th calls should return empty
    const findings = sc.auditResponse("https://limited.com/page", headers);
    expect(findings).toHaveLength(0);
  });
});
