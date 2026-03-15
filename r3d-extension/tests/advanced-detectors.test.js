import { describe, it, expect, beforeAll, beforeEach } from "vitest";

let AdvancedDetectors;

beforeAll(async () => {
  await import("../lib/advanced-detectors.js");
  AdvancedDetectors = globalThis.__R3D.AdvancedDetectors;
});

beforeEach(() => {
  AdvancedDetectors.clear();
});

describe("analyzeGraphQL", () => {
  it("detects introspection in response body", () => {
    const findings = AdvancedDetectors.analyzeGraphQL({
      url: "https://api.com/graphql",
      method: "POST",
      status: 200,
      responseBody: '{"data":{"__schema":{"types":[]}}}',
    });
    expect(findings.some((f) => f.title.includes("introspection"))).toBe(true);
    expect(findings[0].severity).toBe("HIGH");
  });

  it("ignores non-GraphQL endpoints", () => {
    const findings = AdvancedDetectors.analyzeGraphQL({
      url: "https://api.com/users",
      method: "GET",
      status: 200,
      responseBody: '{"users":[]}',
    });
    expect(findings).toHaveLength(0);
  });

  it("detects deep nesting", () => {
    const deep = "{".repeat(10) + '"x":1' + "}".repeat(10);
    const findings = AdvancedDetectors.analyzeGraphQL({
      url: "https://api.com/graphql",
      method: "POST",
      status: 200,
      responseBody: deep,
    });
    expect(findings.some((f) => f.title.includes("deep nesting"))).toBe(true);
  });

  it("ignores non-200 GraphQL responses", () => {
    const findings = AdvancedDetectors.analyzeGraphQL({
      url: "https://api.com/graphql",
      method: "POST",
      status: 400,
      responseBody: '{"data":{"__schema":{}}}',
    });
    expect(findings).toHaveLength(0);
  });
});

describe("analyzeOAuth", () => {
  it("detects missing PKCE", () => {
    const findings = AdvancedDetectors.analyzeOAuth({
      url: "https://idp.com/authorize?response_type=code&client_id=abc&redirect_uri=https://app.com/cb",
      method: "GET",
      status: 302,
    });
    expect(findings.some((f) => f.title.includes("PKCE"))).toBe(true);
  });

  it("detects missing state parameter", () => {
    const findings = AdvancedDetectors.analyzeOAuth({
      url: "https://idp.com/authorize?response_type=code&client_id=abc",
      method: "GET",
      status: 302,
    });
    expect(findings.some((f) => f.title.includes("state"))).toBe(true);
  });

  it("ignores non-authorize endpoints", () => {
    const findings = AdvancedDetectors.analyzeOAuth({
      url: "https://api.com/users",
      method: "GET",
      status: 200,
    });
    expect(findings).toHaveLength(0);
  });

  it("detects overly broad scope in token response", () => {
    const findings = AdvancedDetectors.analyzeOAuth({
      url: "https://idp.com/oauth/token",
      method: "POST",
      status: 200,
      responseBody: JSON.stringify({ access_token: "tok", scope: "admin read write" }),
    });
    expect(findings.some((f) => f.title.includes("broad scope"))).toBe(true);
  });
});

describe("analyzeURLParams", () => {
  it("detects open redirect parameters", () => {
    const findings = AdvancedDetectors.analyzeURLParams({
      url: "https://app.com/login?redirect=https://evil.com",
    });
    expect(findings.some((f) => f.title.includes("open redirect"))).toBe(true);
  });

  it("detects SSRF parameters", () => {
    const findings = AdvancedDetectors.analyzeURLParams({
      url: "https://app.com/proxy?file=http://internal.corp/secret",
    });
    expect(findings.some((f) => f.title.includes("SSRF"))).toBe(true);
  });

  it("detects sensitive data in GET params", () => {
    const findings = AdvancedDetectors.analyzeURLParams({
      url: "https://app.com/auth?password=hunter2",
    });
    expect(findings.some((f) => f.title.includes("Sensitive data"))).toBe(true);
  });

  it("ignores clean URLs", () => {
    const findings = AdvancedDetectors.analyzeURLParams({
      url: "https://app.com/page?q=search&page=1",
    });
    expect(findings).toHaveLength(0);
  });
});

describe("analyzeSensitivePaths", () => {
  it("detects .env exposure", () => {
    const findings = AdvancedDetectors.analyzeSensitivePaths({
      url: "https://app.com/.env",
      status: 200,
    });
    expect(findings.some((f) => f.severity === "CRITICAL")).toBe(true);
  });

  it("detects .git exposure", () => {
    AdvancedDetectors.clear();
    const findings = AdvancedDetectors.analyzeSensitivePaths({
      url: "https://app.com/.git/config",
      status: 200,
    });
    expect(findings.some((f) => f.title.includes("Git"))).toBe(true);
  });

  it("detects swagger.json", () => {
    AdvancedDetectors.clear();
    const findings = AdvancedDetectors.analyzeSensitivePaths({
      url: "https://app.com/swagger.json",
      status: 200,
    });
    expect(findings).toHaveLength(1);
  });

  it("ignores non-200 responses", () => {
    const findings = AdvancedDetectors.analyzeSensitivePaths({
      url: "https://app.com/.env",
      status: 404,
    });
    expect(findings).toHaveLength(0);
  });

  it("deduplicates same URL", () => {
    AdvancedDetectors.clear();
    AdvancedDetectors.analyzeSensitivePaths({ url: "https://dedup.com/.env", status: 200 });
    const second = AdvancedDetectors.analyzeSensitivePaths({ url: "https://dedup.com/.env", status: 200 });
    expect(second).toHaveLength(0);
  });
});

describe("analyze (integrated)", () => {
  it("runs all detectors", () => {
    AdvancedDetectors.clear();
    const findings = AdvancedDetectors.analyze({
      url: "https://app.com/.env",
      method: "GET",
      status: 200,
      responseBody: "",
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});
