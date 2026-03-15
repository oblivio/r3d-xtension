import { describe, it, expect, beforeAll } from "vitest";

let JWTAnalyzer;

beforeAll(async () => {
  await import("../lib/jwt-analyzer.js");
  JWTAnalyzer = globalThis.__R3D.JWTAnalyzer;
});

function b64url(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeJWT(header, payload, sig = "fakesig") {
  return `${b64url(header)}.${b64url(payload)}.${sig}`;
}

// ── decodeJWT ───────────────────────────────────────────────────────

describe("JWTAnalyzer.decodeJWT", () => {
  it("decodes a valid JWT", () => {
    const token = makeJWT({ alg: "RS256" }, { sub: "user1", exp: 9999999999 });
    const result = JWTAnalyzer.decodeJWT(token);
    expect(result).not.toBeNull();
    expect(result.header.alg).toBe("RS256");
    expect(result.payload.sub).toBe("user1");
    expect(result.hasSignature).toBe(true);
  });

  it("returns null for non-JWT strings", () => {
    expect(JWTAnalyzer.decodeJWT("not-a-jwt")).toBeNull();
    expect(JWTAnalyzer.decodeJWT("a.b")).toBeNull();
  });

  it("detects missing signature", () => {
    const token = `${b64url({ alg: "none" })}.${b64url({ sub: "1" })}.`;
    const result = JWTAnalyzer.decodeJWT(token);
    expect(result).not.toBeNull();
    expect(result.hasSignature).toBe(false);
  });
});

// ── looksLikeJWT ────────────────────────────────────────────────────

describe("JWTAnalyzer.looksLikeJWT", () => {
  it("returns true for JWT-like strings", () => {
    const token = makeJWT({ alg: "HS256" }, { sub: "1" });
    expect(JWTAnalyzer.looksLikeJWT(token)).toBe(true);
  });

  it("returns false for non-JWTs", () => {
    expect(JWTAnalyzer.looksLikeJWT("hello.world")).toBe(false);
    expect(JWTAnalyzer.looksLikeJWT(null)).toBe(false);
    expect(JWTAnalyzer.looksLikeJWT("")).toBe(false);
  });
});

// ── extractFromHeaders ──────────────────────────────────────────────

describe("JWTAnalyzer.extractFromHeaders", () => {
  it("extracts JWT from Authorization Bearer", () => {
    const token = makeJWT({ alg: "RS256" }, { sub: "1" });
    const result = JWTAnalyzer.extractFromHeaders({ Authorization: `Bearer ${token}` });
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result[0].raw).toBe(token);
  });

  it("returns empty for non-JWT headers", () => {
    expect(JWTAnalyzer.extractFromHeaders({ "Content-Type": "application/json" })).toEqual([]);
  });

  it("returns empty for null", () => {
    expect(JWTAnalyzer.extractFromHeaders(null)).toEqual([]);
  });
});

// ── extractFromBody ─────────────────────────────────────────────────

describe("JWTAnalyzer.extractFromBody", () => {
  it("extracts JWTs from response body", () => {
    const token = makeJWT({ alg: "RS256" }, { sub: "1" });
    const body = JSON.stringify({ access_token: token });
    const result = JWTAnalyzer.extractFromBody(body);
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it("returns empty for bodies without JWTs", () => {
    expect(JWTAnalyzer.extractFromBody('{"ok":true}')).toEqual([]);
  });
});

// ── extractFromURL ──────────────────────────────────────────────────

describe("JWTAnalyzer.extractFromURL", () => {
  it("extracts JWT from query parameter", () => {
    const token = makeJWT({ alg: "RS256" }, { sub: "1" });
    const url = `https://app.com/callback?token=${token}`;
    const result = JWTAnalyzer.extractFromURL(url);
    expect(result.length).toBe(1);
    expect(result[0].inURL).toBe(true);
  });

  it("returns empty when no JWT in URL", () => {
    expect(JWTAnalyzer.extractFromURL("https://app.com/page")).toEqual([]);
  });
});

// ── auditToken ──────────────────────────────────────────────────────

describe("JWTAnalyzer.auditToken", () => {
  it("flags none algorithm as CRITICAL", () => {
    const decoded = {
      header: { alg: "none" },
      payload: { sub: "1" },
      hasSignature: false,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.severity === "CRITICAL" && f.title.includes("none"))).toBe(true);
  });

  it("flags symmetric algorithm", () => {
    const decoded = {
      header: { alg: "HS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, jti: "a", aud: "app" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("symmetric"))).toBe(true);
  });

  it("flags missing exp claim", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("no expiration"))).toBe(true);
  });

  it("flags expired token", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 1000000 },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("Expired"))).toBe(true);
  });

  it("flags excessive lifetime", () => {
    const farFuture = Math.floor(Date.now() / 1000) + 365 * 86400;
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: farFuture, iat: 1, jti: "a", aud: "app" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("excessive lifetime"))).toBe(true);
  });

  it("flags missing iat", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, jti: "a", aud: "app" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("iat"))).toBe(true);
  });

  it("flags missing jti", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, aud: "app" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("jti"))).toBe(true);
  });

  it("flags missing audience", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, jti: "a" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("audience"))).toBe(true);
  });

  it("flags wildcard audience", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, jti: "a", aud: "*" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("wildcard audience"))).toBe(true);
  });

  it("flags overly broad scope", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, jti: "a", aud: "app", scope: "admin read write" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("broad scope"))).toBe(true);
  });

  it("flags impersonation claims", () => {
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, jti: "a", aud: "app", impersonated_by: "admin" },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("impersonation"))).toBe(true);
  });

  it("flags group bloat", () => {
    const groups = Array.from({ length: 60 }, (_, i) => `group-${i}`);
    const decoded = {
      header: { alg: "RS256" },
      payload: { sub: "1", exp: 9999999999, iat: 1, jti: "a", aud: "app", groups },
      hasSignature: true,
    };
    const findings = JWTAnalyzer.auditToken(decoded, "test", "https://a.com");
    expect(findings.some((f) => f.title.includes("group/role claims"))).toBe(true);
  });
});

// ── analyze (integration) ───────────────────────────────────────────

describe("JWTAnalyzer.analyze", () => {
  it("runs full pipeline and returns tokens + findings", () => {
    const token = makeJWT({ alg: "none" }, { sub: "1" });
    const result = JWTAnalyzer.analyze({
      url: "https://app.com/api",
      requestHeaders: { Authorization: `Bearer ${token}` },
    });
    expect(result.tokens.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });

  it("flags JWT in URL parameter", () => {
    const token = makeJWT({ alg: "RS256" }, { sub: "1", exp: 9999999999, iat: 1, jti: "a", aud: "x" });
    const result = JWTAnalyzer.analyze({
      url: `https://app.com/cb?token=${token}`,
    });
    expect(result.findings.some((f) => f.title.includes("URL parameter"))).toBe(true);
  });
});

// ── reassembleMultiPartCookies ──────────────────────────────────────

describe("JWTAnalyzer.reassembleMultiPartCookies", () => {
  it("reassembles chunked JWT cookies", () => {
    const header = b64url({ alg: "RS256" });
    const payload = b64url({ sub: "1" });
    const full = `${header}.${payload}.sig`;
    const mid = Math.floor(full.length / 2);

    const result = JWTAnalyzer.reassembleMultiPartCookies({
      "token_0": full.slice(0, mid),
      "token_1": full.slice(mid),
    });
    expect(result.length).toBe(1);
    expect(result[0].reassembled).toBe(true);
    expect(result[0].value).toBe(full);
  });

  it("returns single JWT cookies directly", () => {
    const token = makeJWT({ alg: "RS256" }, { sub: "1" });
    const result = JWTAnalyzer.reassembleMultiPartCookies({ session: token });
    expect(result.length).toBe(1);
    expect(result[0].reassembled).toBe(false);
  });
});
