import { describe, it, expect, beforeAll, beforeEach } from "vitest";

let EvidenceCollector;

beforeAll(async () => {
  await import("../lib/evidence-collector.js");
  EvidenceCollector = globalThis.__R3D.EvidenceCollector;
});

describe("redact", () => {
  it("masks Bearer tokens", () => {
    const result = EvidenceCollector.redact("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig");
    expect(result).not.toContain("eyJhbGciOiJSUzI1NiJ9");
    expect(result).toContain("REDACTED");
  });

  it("masks AWS access keys", () => {
    const result = EvidenceCollector.redact('key: "AKIAIOSFODNN7EXAMPLE"');
    expect(result).toContain("AKIA[REDACTED]");
  });

  it("masks MongoDB connection strings", () => {
    const result = EvidenceCollector.redact("mongodb+srv://admin:secret@cluster.mongodb.net/db");
    expect(result).not.toContain("admin:secret");
    expect(result).toContain("[REDACTED]");
  });

  it("masks GitHub tokens", () => {
    const result = EvidenceCollector.redact("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
  });

  it("masks Slack tokens", () => {
    const prefix = "xoxb";
    const result = EvidenceCollector.redact(`token: ${prefix}-123456789012-abcdefghij`);
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("123456789012-abcdefghij");
  });

  it("masks private keys", () => {
    const result = EvidenceCollector.redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END");
    expect(result).toContain("[REDACTED]");
  });

  it("masks JSON secret values", () => {
    const result = EvidenceCollector.redact('{"password": "hunter2"}');
    expect(result).not.toContain("hunter2");
    expect(result).toContain("[REDACTED]");
  });

  it("leaves clean text alone", () => {
    const clean = '{"status": "ok", "count": 42}';
    expect(EvidenceCollector.redact(clean)).toBe(clean);
  });

  it("returns null/undefined as-is", () => {
    expect(EvidenceCollector.redact(null)).toBeNull();
    expect(EvidenceCollector.redact(undefined)).toBeUndefined();
  });
});

describe("redactHeaders", () => {
  it("redacts Authorization header", () => {
    const result = EvidenceCollector.redactHeaders({
      Authorization: "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig",
      "Content-Type": "application/json",
    });
    expect(result.Authorization).toContain("REDACTED");
    expect(result["Content-Type"]).toBe("application/json");
  });

  it("redacts Cookie header", () => {
    const result = EvidenceCollector.redactHeaders({
      Cookie: "session=abc123; auth_token=secret",
    });
    expect(result.Cookie).toContain("REDACTED");
  });

  it("returns null for null input", () => {
    expect(EvidenceCollector.redactHeaders(null)).toBeNull();
  });
});

describe("EvidenceStore", () => {
  let store;

  beforeEach(() => {
    store = new EvidenceCollector.EvidenceStore();
  });

  it("captures evidence pack", () => {
    store.capture(
      { id: "f1" },
      { method: "GET", url: "https://a.com/api", status: 200 },
    );
    const pack = store.get("f1");
    expect(pack).not.toBeNull();
    expect(pack.findingId).toBe("f1");
    expect(pack.request.method).toBe("GET");
    expect(pack.response.status).toBe(200);
    expect(pack.redacted).toBe(true);
  });

  it("returns null for missing finding", () => {
    expect(store.get("nonexistent")).toBeNull();
  });

  it("tracks size", () => {
    store.capture({ id: "a" }, { url: "x" });
    store.capture({ id: "b" }, { url: "y" });
    expect(store.size()).toBe(2);
  });

  it("evicts oldest when at capacity (500)", () => {
    for (let i = 0; i < 501; i++) {
      store.capture({ id: `f-${i}` }, { url: `https://a.com/${i}` });
    }
    expect(store.size()).toBe(500);
    expect(store.get("f-0")).toBeNull();
    expect(store.get("f-500")).not.toBeNull();
  });

  it("getAll returns all packs", () => {
    store.capture({ id: "x" }, { url: "u" });
    store.capture({ id: "y" }, { url: "v" });
    const all = store.getAll();
    expect(Object.keys(all)).toHaveLength(2);
  });

  it("clear resets store", () => {
    store.capture({ id: "x" }, { url: "u" });
    store.clear();
    expect(store.size()).toBe(0);
    expect(store.get("x")).toBeNull();
  });

  it("no-ops on null input", () => {
    store.capture(null, null);
    expect(store.size()).toBe(0);
  });
});
