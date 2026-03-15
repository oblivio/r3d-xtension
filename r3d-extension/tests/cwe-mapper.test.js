import { describe, it, expect, beforeAll } from "vitest";

let CWEMapper;

beforeAll(async () => {
  await import("../lib/cwe-mapper.js");
  CWEMapper = globalThis.__R3D.CWEMapper;
});

describe("CWEMapper.classify", () => {
  it("maps IDOR finding to CWE-639", () => {
    const r = CWEMapper.classify("idor", "IDOR in user profile endpoint");
    expect(r.cwe).toBe("CWE-639");
    expect(r.owasp).toBe("A01:2021");
    expect(r.compliance).toContain("GDPR");
  });

  it("maps XSS finding to CWE-79", () => {
    const r = CWEMapper.classify("content", "XSS via innerHTML injection");
    expect(r.cwe).toBe("CWE-79");
    expect(r.owasp).toBe("A03:2021");
  });

  it("maps JWT symmetric signing to CWE-327", () => {
    const r = CWEMapper.classify("jwt", "JWT uses HS256 symmetric signing");
    expect(r.cwe).toBe("CWE-327");
    expect(r.owasp).toBe("A02:2021");
  });

  it("maps CSP header issue to CWE-16", () => {
    const r = CWEMapper.classify("headers", "CSP allows unsafe-inline");
    expect(r.cwe).toBe("CWE-16");
    expect(r.owasp).toBe("A05:2021");
  });

  it("maps SSRF finding to CWE-918", () => {
    const r = CWEMapper.classify("advanced", "SSRF parameter detected");
    expect(r.cwe).toBe("CWE-918");
    expect(r.owasp).toBe("A10:2021");
  });

  it("maps cookie HttpOnly issue to CWE-1004", () => {
    const r = CWEMapper.classify("cookies", "Missing HttpOnly on session cookie");
    expect(r.cwe).toBe("CWE-1004");
  });

  it("maps CSRF to CWE-352", () => {
    const r = CWEMapper.classify("rbac", "Cross-site request forgery possible");
    expect(r.cwe).toBe("CWE-352");
  });

  it("falls back to keyword match across all modules", () => {
    const r = CWEMapper.classify("unknown_module", "SSN exposed in response");
    expect(r.cwe).toBe("CWE-359");
  });

  it("returns null cwe for unrecognized finding", () => {
    const r = CWEMapper.classify("foo", "completely unrelated title xyz123");
    expect(r.cwe).toBeNull();
    expect(r.owasp).toBeNull();
    expect(r.compliance).toEqual([]);
  });

  it("includes confidence from module defaults", () => {
    const r = CWEMapper.classify("idor", "IDOR in API");
    expect(r.confidence).toBe("high");

    const r2 = CWEMapper.classify("pii", "SSN found");
    expect(r2.confidence).toBe("medium");
  });
});

describe("CWEMapper metadata", () => {
  it("has OWASP labels for all categories", () => {
    expect(CWEMapper.OWASP_LABELS["A01:2021"]).toBe("Broken Access Control");
    expect(CWEMapper.OWASP_LABELS["A10:2021"]).toBe("SSRF");
  });

  it("has compliance framework labels", () => {
    expect(CWEMapper.COMPLIANCE_LABELS.GDPR).toContain("Data Protection");
    expect(CWEMapper.COMPLIANCE_LABELS.PCI).toContain("Payment Card");
  });

  it("DB has entries for all major modules", () => {
    const modules = new Set(CWEMapper.DB.flatMap((e) => e.modules));
    for (const m of ["idor", "jwt", "headers", "cookies", "pii", "advanced", "rbac"]) {
      expect(modules.has(m)).toBe(true);
    }
  });
});
