import { describe, it, expect, beforeAll } from "vitest";

let PIIScanner;

beforeAll(async () => {
  await import("../lib/pii-scanner.js");
  PIIScanner = globalThis.__R3D.PIIScanner;
});

describe("PIIScanner.luhnCheck", () => {
  it("validates a known valid Visa number", () => {
    expect(PIIScanner.luhnCheck("4539578763621486")).toBe(true);
  });

  it("rejects an invalid card number", () => {
    expect(PIIScanner.luhnCheck("1234567890123456")).toBe(false);
  });

  it("handles spaces and dashes", () => {
    expect(PIIScanner.luhnCheck("4539 5787 6362 1486")).toBe(true);
    expect(PIIScanner.luhnCheck("4539-5787-6362-1486")).toBe(true);
  });

  it("rejects too-short numbers", () => {
    expect(PIIScanner.luhnCheck("123")).toBe(false);
  });
});

describe("PIIScanner.scan", () => {
  it("returns empty for null/empty input", () => {
    expect(PIIScanner.scan(null, "https://a.com")).toEqual([]);
    expect(PIIScanner.scan("", "https://a.com")).toEqual([]);
  });

  it("detects AWS access keys", () => {
    const body = '{"key": "AKIAIOSFODNN7EXAMPLE"}';
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("AWS"))).toBe(true);
  });

  it("detects MongoDB connection strings", () => {
    const body = 'config: "mongodb+srv://user:pass@cluster.mongodb.net/db"';
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("MongoDB"))).toBe(true);
    expect(findings.some((f) => f.severity === "CRITICAL")).toBe(true);
  });

  it("detects SSN patterns", () => {
    const body = '{"ssn": "123-45-6789"}';
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("SSN"))).toBe(true);
  });

  it("detects GitHub tokens", () => {
    const body = `token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`;
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("GitHub"))).toBe(true);
  });

  it("detects private key material", () => {
    const body = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("Private key"))).toBe(true);
  });

  it("detects internal IP addresses", () => {
    const body = '{"server": "10.0.1.50"}';
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("Internal IP"))).toBe(true);
  });

  it("detects bearer/JWT tokens in response bodies", () => {
    const body = '{"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef"}';
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("Bearer") || f.title.includes("JWT"))).toBe(true);
  });

  it("detects Slack tokens", () => {
    const prefix = "xoxb";
    const body = `token: "${prefix}-123456789012-1234567890123-abcdefghijklmn"`;
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings.some((f) => f.title.includes("Slack"))).toBe(true);
  });

  it("detects bulk email exposure (>5 unique)", () => {
    const emails = Array.from({ length: 10 }, (_, i) => `user${i}@corp.com`);
    const body = JSON.stringify({ users: emails.map((e) => ({ email: e })) });
    const findings = PIIScanner.scan(body, "https://a.com/api/users");
    expect(findings.some((f) => f.title.includes("Bulk email"))).toBe(true);
  });

  it("detects bulk record exposure", () => {
    const records = Array.from({ length: 25 }, (_, i) => ({
      email: `u${i}@a.com`,
      name: `User ${i}`,
    }));
    const body = JSON.stringify(records);
    const findings = PIIScanner.scan(body, "https://a.com/api/users");
    expect(findings.some((f) => f.title.includes("Mass record"))).toBe(true);
  });

  it("does not flag clean responses", () => {
    const body = '{"status": "ok", "items": [1, 2, 3]}';
    const findings = PIIScanner.scan(body, "https://a.com");
    expect(findings).toHaveLength(0);
  });
});
