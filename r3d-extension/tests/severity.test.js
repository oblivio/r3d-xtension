import { describe, it, expect } from "vitest";

const {
  Severity,
  Confidence,
  Status,
  SEVERITY_WEIGHT,
  compareSeverity,
  createFinding,
  fingerprint,
  dedup,
  severityScore,
  countBySeverity,
} = globalThis.__R3D;

// ── Constants ───────────────────────────────────────────────────────

describe("Severity constants", () => {
  it("defines all five levels", () => {
    expect(Severity.CRITICAL).toBe("CRITICAL");
    expect(Severity.HIGH).toBe("HIGH");
    expect(Severity.MEDIUM).toBe("MEDIUM");
    expect(Severity.LOW).toBe("LOW");
    expect(Severity.INFO).toBe("INFO");
  });

  it("weights are ordered correctly", () => {
    expect(SEVERITY_WEIGHT.CRITICAL).toBeGreaterThan(SEVERITY_WEIGHT.HIGH);
    expect(SEVERITY_WEIGHT.HIGH).toBeGreaterThan(SEVERITY_WEIGHT.MEDIUM);
    expect(SEVERITY_WEIGHT.MEDIUM).toBeGreaterThan(SEVERITY_WEIGHT.LOW);
    expect(SEVERITY_WEIGHT.LOW).toBeGreaterThan(SEVERITY_WEIGHT.INFO);
  });
});

// ── compareSeverity ─────────────────────────────────────────────────

describe("compareSeverity", () => {
  it("sorts CRITICAL before LOW", () => {
    expect(compareSeverity("CRITICAL", "LOW")).toBeLessThan(0);
  });

  it("returns 0 for equal severities", () => {
    expect(compareSeverity("HIGH", "HIGH")).toBe(0);
  });

  it("sorts correctly in array.sort", () => {
    const items = ["LOW", "CRITICAL", "MEDIUM", "HIGH", "INFO"];
    items.sort(compareSeverity);
    expect(items).toEqual(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
  });
});

// ── fingerprint ─────────────────────────────────────────────────────

describe("fingerprint", () => {
  it("produces deterministic output", () => {
    const a = fingerprint("jwt", "Missing exp", "https://app.com/api/v1");
    const b = fingerprint("jwt", "Missing exp", "https://app.com/api/v1");
    expect(a).toBe(b);
  });

  it("normalizes ObjectIds in URLs", () => {
    const a = fingerprint("idor", "IDOR", "https://app.com/user/507f1f77bcf86cd799439011");
    const b = fingerprint("idor", "IDOR", "https://app.com/user/aaaaaaaabbbbccccddddeeee");
    expect(a).toBe(b);
  });

  it("normalizes UUIDs in URLs", () => {
    const a = fingerprint("test", "T", "https://x.com/a/550e8400-e29b-41d4-a716-446655440000");
    const b = fingerprint("test", "T", "https://x.com/a/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    expect(a).toBe(b);
  });

  it("normalizes numeric IDs in URLs", () => {
    const a = fingerprint("test", "T", "https://x.com/item/12345");
    const b = fingerprint("test", "T", "https://x.com/item/99999");
    expect(a).toBe(b);
  });

  it("starts with fp_ prefix", () => {
    expect(fingerprint("m", "t", "https://x.com")).toMatch(/^fp_/);
  });
});

// ── createFinding ───────────────────────────────────────────────────

describe("createFinding", () => {
  it("produces a finding with required fields", () => {
    const f = createFinding({
      module: "jwt",
      severity: Severity.HIGH,
      title: "Test finding",
      url: "https://example.com",
    });
    expect(f.id).toBeTruthy();
    expect(f.module).toBe("jwt");
    expect(f.severity).toBe("HIGH");
    expect(f.title).toBe("Test finding");
    expect(f.confidence).toBe(Confidence.MEDIUM);
    expect(f.status).toBe(Status.LIKELY);
    expect(f.fingerprint).toMatch(/^fp_/);
    expect(f.occurrences).toBe(1);
  });

  it("defaults are overridable", () => {
    const f = createFinding({
      module: "pii",
      severity: Severity.CRITICAL,
      title: "SSN",
      confidence: Confidence.HIGH,
      status: Status.CONFIRMED,
      cwe: "CWE-200",
    });
    expect(f.confidence).toBe("high");
    expect(f.status).toBe("confirmed");
    expect(f.cwe).toBe("CWE-200");
  });
});

// ── dedup ───────────────────────────────────────────────────────────

describe("dedup", () => {
  it("merges findings with the same fingerprint", () => {
    const base = {
      module: "jwt",
      severity: Severity.LOW,
      title: "Test",
      url: "https://a.com",
    };
    const f1 = createFinding(base);
    const f2 = createFinding(base);
    const result = dedup([f1, f2]);
    expect(result).toHaveLength(1);
    expect(result[0].occurrences).toBe(2);
  });

  it("keeps the highest severity on merge", () => {
    const fp = fingerprint("m", "T", "https://a.com");
    const findings = [
      { fingerprint: fp, severity: "LOW", ts: 1, occurrences: 1 },
      { fingerprint: fp, severity: "HIGH", ts: 2, occurrences: 1 },
    ];
    const result = dedup(findings);
    expect(result[0].severity).toBe("HIGH");
  });

  it("preserves unique findings", () => {
    const f1 = createFinding({ module: "a", severity: "LOW", title: "A", url: "https://1.com" });
    const f2 = createFinding({ module: "b", severity: "LOW", title: "B", url: "https://2.com" });
    expect(dedup([f1, f2])).toHaveLength(2);
  });
});

// ── severityScore ───────────────────────────────────────────────────

describe("severityScore", () => {
  it("sums weights * occurrences", () => {
    const findings = [
      { severity: "CRITICAL", occurrences: 2 },
      { severity: "LOW", occurrences: 1 },
    ];
    expect(severityScore(findings)).toBe(10 * 2 + 1 * 1);
  });

  it("returns 0 for empty array", () => {
    expect(severityScore([])).toBe(0);
  });
});

// ── countBySeverity ─────────────────────────────────────────────────

describe("countBySeverity", () => {
  it("counts each severity level", () => {
    const findings = [
      { severity: "CRITICAL" },
      { severity: "CRITICAL" },
      { severity: "LOW" },
      { severity: "INFO" },
    ];
    const counts = countBySeverity(findings);
    expect(counts.CRITICAL).toBe(2);
    expect(counts.LOW).toBe(1);
    expect(counts.INFO).toBe(1);
    expect(counts.HIGH).toBe(0);
    expect(counts.MEDIUM).toBe(0);
  });
});
