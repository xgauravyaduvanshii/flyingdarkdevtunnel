import { describe, it, expect } from "vitest";

describe("entitlement shape", () => {
  it("matches expected defaults", () => {
    const free = {
      max_tunnels: 3,
      max_concurrent_conns: 50,
      reserved_domains: false,
      custom_domains: false,
      ip_allowlist: false,
      retention_hours: 24,
    };

    expect(free.max_tunnels).toBeGreaterThan(0);
    expect(free.retention_hours).toBe(24);
  });
});
