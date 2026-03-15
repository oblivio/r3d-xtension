import { describe, it, expect, beforeAll } from "vitest";

let CookieAuditor;

beforeAll(async () => {
  await import("../lib/cookie-auditor.js");
  CookieAuditor = globalThis.__R3D.CookieAuditor;
});

function makeCookie(overrides = {}) {
  return {
    name: "session",
    value: "abc123",
    domain: ".example.com",
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    ...overrides,
  };
}

// ── auditCookies ────────────────────────────────────────────────────

describe("CookieAuditor.auditCookies", () => {
  it("returns empty for a fully secure cookie", () => {
    const cookie = makeCookie({
      sameSite: "strict",
      domain: ".app.example.com",
      name: "pref",
    });
    const findings = CookieAuditor.auditCookies([cookie], "app.example.com");
    expect(findings).toHaveLength(0);
  });

  it("flags missing HttpOnly on auth cookies as HIGH", () => {
    const cookie = makeCookie({ httpOnly: false, name: "auth_token" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    const f = findings.find((f) => f.title.includes("HttpOnly"));
    expect(f).toBeDefined();
    expect(f.severity).toBe("HIGH");
  });

  it("flags missing HttpOnly on non-auth cookies as MEDIUM", () => {
    const cookie = makeCookie({ httpOnly: false, name: "theme" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    const f = findings.find((f) => f.title.includes("HttpOnly"));
    expect(f).toBeDefined();
    expect(f.severity).toBe("MEDIUM");
  });

  it("flags missing Secure flag", () => {
    const cookie = makeCookie({ secure: false, sameSite: "lax" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("Secure"))).toBe(true);
  });

  it("flags SameSite=None without Secure", () => {
    const cookie = makeCookie({ sameSite: "no_restriction", secure: false });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("SameSite=None without Secure"))).toBe(true);
  });

  it("flags SameSite=None with Secure as MEDIUM", () => {
    const cookie = makeCookie({ sameSite: "no_restriction", secure: true, name: "pref" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("cross-site allowed") && f.severity === "MEDIUM")).toBe(true);
  });

  it("flags unspecified SameSite", () => {
    const cookie = makeCookie({ sameSite: "unspecified" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("SameSite not explicitly set"))).toBe(true);
  });

  it("flags excessive cookie lifetime", () => {
    const futureSeconds = Date.now() / 1000 + 365 * 86400;
    const cookie = makeCookie({ expirationDate: futureSeconds, sameSite: "strict", domain: ".app.example.com", name: "pref" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("excessive lifetime"))).toBe(true);
  });

  it("flags broad domain scope", () => {
    const cookie = makeCookie({ domain: ".com", sameSite: "strict", name: "pref" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("broad domain"))).toBe(true);
  });

  it("flags path=/ on auth cookies", () => {
    const cookie = makeCookie({ path: "/", name: "session_token", sameSite: "strict", domain: ".app.example.com" });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("path=/"))).toBe(true);
  });

  it("detects JWT in cookie value", () => {
    const cookie = makeCookie({
      value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
      sameSite: "strict",
      domain: ".app.example.com",
      name: "pref",
    });
    const findings = CookieAuditor.auditCookies([cookie], "example.com");
    expect(findings.some((f) => f.title.includes("JWT"))).toBe(true);
  });
});

// ── auditSetCookieHeaders ───────────────────────────────────────────

describe("CookieAuditor.auditSetCookieHeaders", () => {
  it("returns empty for null input", () => {
    expect(CookieAuditor.auditSetCookieHeaders(null, "https://a.com")).toEqual([]);
  });

  it("flags missing HttpOnly on auth Set-Cookie", () => {
    const headers = ["session_token=abc; Secure; SameSite=Lax"];
    const findings = CookieAuditor.auditSetCookieHeaders(headers, "https://a.com");
    expect(findings.some((f) => f.title.includes("HttpOnly"))).toBe(true);
  });

  it("flags missing Secure on Set-Cookie", () => {
    const headers = ["pref=dark; HttpOnly; SameSite=Lax"];
    const findings = CookieAuditor.auditSetCookieHeaders(headers, "https://a.com");
    expect(findings.some((f) => f.title.includes("Secure"))).toBe(true);
  });

  it("passes secure Set-Cookie", () => {
    const headers = ["pref=dark; HttpOnly; Secure; SameSite=Lax"];
    const findings = CookieAuditor.auditSetCookieHeaders(headers, "https://a.com");
    expect(findings).toHaveLength(0);
  });
});
