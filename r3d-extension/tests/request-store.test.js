import { describe, it, expect, beforeAll, beforeEach } from "vitest";

let RequestStore;

beforeAll(async () => {
  await import("../lib/request-store.js");
  RequestStore = globalThis.__R3D.RequestStore;
});

describe("RequestStore", () => {
  let store;

  beforeEach(() => {
    store = new RequestStore();
  });

  it("adds entries and assigns IDs", () => {
    const entry = store.add({ url: "https://app.com/api/users", method: "GET" });
    expect(entry.id).toBe(1);
    expect(store.size()).toBe(1);
  });

  it("indexes by domain", () => {
    store.add({ url: "https://alpha.com/a" });
    store.add({ url: "https://beta.com/b" });
    store.add({ url: "https://alpha.com/c" });
    expect(store.getByDomain("alpha.com")).toHaveLength(2);
    expect(store.getByDomain("beta.com")).toHaveLength(1);
  });

  it("indexes by pattern (normalizes IDs)", () => {
    store.add({ url: "https://app.com/users/507f1f77bcf86cd799439011/profile" });
    store.add({ url: "https://app.com/users/aaaaaaaabbbbccccddddeeee/profile" });
    const patterns = store.getPatterns();
    expect(patterns).toHaveLength(1);
    expect(patterns[0]).toContain("{objectId}");
  });

  it("normalizes UUIDs in patterns", () => {
    store.add({ url: "https://app.com/items/550e8400-e29b-41d4-a716-446655440000" });
    const patterns = store.getPatterns();
    expect(patterns[0]).toContain("{uuid}");
  });

  it("normalizes numeric IDs in patterns", () => {
    store.add({ url: "https://app.com/items/12345" });
    const patterns = store.getPatterns();
    expect(patterns[0]).toContain("{id}");
  });

  it("getDomains lists all seen domains", () => {
    store.add({ url: "https://a.com/x" });
    store.add({ url: "https://b.com/y" });
    const domains = store.getDomains();
    expect(domains).toContain("a.com");
    expect(domains).toContain("b.com");
  });

  it("getAll returns copies", () => {
    store.add({ url: "https://a.com/x" });
    const all = store.getAll();
    expect(all).toHaveLength(1);
    all.push({ fake: true });
    expect(store.size()).toBe(1);
  });

  it("evicts oldest on overflow", () => {
    const small = new RequestStore(3);
    small.add({ url: "https://a.com/1" });
    small.add({ url: "https://a.com/2" });
    small.add({ url: "https://a.com/3" });
    small.add({ url: "https://a.com/4" });
    expect(small.size()).toBe(3);
    expect(small.getAll()[0].id).toBe(2);
  });

  it("query filters by domain", () => {
    store.add({ url: "https://a.com/x", method: "GET" });
    store.add({ url: "https://b.com/y", method: "POST" });
    const results = store.query({ domain: "a.com" });
    expect(results).toHaveLength(1);
  });

  it("query filters by method", () => {
    store.add({ url: "https://a.com/x", method: "GET" });
    store.add({ url: "https://a.com/y", method: "POST" });
    expect(store.query({ method: "POST" })).toHaveLength(1);
  });

  it("query filters by statusRange", () => {
    store.add({ url: "https://a.com/a", status: 200 });
    store.add({ url: "https://a.com/b", status: 404 });
    store.add({ url: "https://a.com/c", status: 500 });
    expect(store.query({ statusRange: [400, 599] })).toHaveLength(2);
  });

  it("query filters by hasFindings", () => {
    store.add({ url: "https://a.com/a", findings: [{ id: "f1" }] });
    store.add({ url: "https://a.com/b", findings: [] });
    expect(store.query({ hasFindings: true })).toHaveLength(1);
  });

  it("onEntry fires listeners", () => {
    const received = [];
    store.onEntry((e) => received.push(e));
    store.add({ url: "https://a.com/x" });
    expect(received).toHaveLength(1);
  });

  it("onEntry returns unsubscribe function", () => {
    const received = [];
    const unsub = store.onEntry((e) => received.push(e));
    store.add({ url: "https://a.com/x" });
    unsub();
    store.add({ url: "https://a.com/y" });
    expect(received).toHaveLength(1);
  });

  it("clear resets everything", () => {
    store.add({ url: "https://a.com/x" });
    store.clear();
    expect(store.size()).toBe(0);
    expect(store.getDomains()).toHaveLength(0);
  });

  it("getAllFindings aggregates across entries", () => {
    store.add({ url: "https://a.com/a", findings: [{ id: "f1" }, { id: "f2" }] });
    store.add({ url: "https://a.com/b", findings: [{ id: "f3" }] });
    expect(store.getAllFindings()).toHaveLength(3);
  });

  it("detects base paths from JSON responses", () => {
    for (let i = 0; i < 5; i++) {
      store.add({ url: `https://api.com/v1/resource${i}`, responseContentType: "application/json" });
    }
    const paths = store.getDetectedBasePaths(3);
    expect(paths.length).toBeGreaterThanOrEqual(1);
    expect(paths[0].path).toContain("/v1");
  });
});
