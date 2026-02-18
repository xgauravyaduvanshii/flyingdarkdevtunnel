import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../app.js";

const defaults: Record<string, string> = {
  NODE_ENV: "test",
  API_PORT: "4000",
  DATABASE_URL: "postgres://postgres:postgres@127.0.0.1:5432/fdt",
  REDIS_URL: "redis://127.0.0.1:6379",
  JWT_SECRET: "12345678901234567890123456789012",
  JWT_REFRESH_SECRET: "12345678901234567890123456789012",
  AGENT_JWT_SECRET: "12345678901234567890123456789012",
  BASE_DOMAIN: "tunnel.yourdomain.com",
  DOMAIN_VERIFY_STRICT: "false",
};

for (const [key, value] of Object.entries(defaults)) {
  if (!process.env[key]) {
    process.env[key] = value;
  }
}

describe("api integration", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  }, 30_000);

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it("supports paid custom domain routing and enriched agent token claims", async () => {
    const email = `integration-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as {
      accessToken: string;
      authtoken: string;
    };

    const accessToken = registerBody.accessToken;

    const usersRes = await app.inject({
      method: "GET",
      url: "/v1/admin/users",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(usersRes.statusCode).toBe(200);

    const usersBody = usersRes.json() as { users: Array<{ id: string; email: string }> };
    const me = usersBody.users.find((user) => user.email === email);
    expect(me).toBeTruthy();

    const promoteRes = await app.inject({
      method: "PATCH",
      url: `/v1/admin/users/${me!.id}/plan`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { planCode: "pro" },
    });
    expect(promoteRes.statusCode).toBe(200);

    const tunnelRes = await app.inject({
      method: "POST",
      url: "/v1/tunnels",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        name: "integration-http",
        protocol: "http",
        localAddr: "http://localhost:3000",
        inspect: true,
        basicAuthUser: "demo",
        basicAuthPassword: "secret",
        ipAllowlist: ["127.0.0.1/32"],
      },
    });
    expect(tunnelRes.statusCode).toBe(201);
    const tunnelBody = tunnelRes.json() as { id: string; subdomain: string | null };

    const domainName = `api-${randomUUID().slice(0, 8)}.example.com`;

    const customDomainRes = await app.inject({
      method: "POST",
      url: "/v1/domains/custom",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { domain: domainName, tlsMode: "termination" },
    });
    expect(customDomainRes.statusCode).toBe(201);
    const customDomainBody = customDomainRes.json() as { id: string; verificationHost: string };
    expect(customDomainBody.verificationHost).toContain("_fdt-verify");

    const verifyRes = await app.inject({
      method: "POST",
      url: `/v1/domains/custom/${customDomainBody.id}/verify`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    });
    expect(verifyRes.statusCode).toBe(200);

    const routeRes = await app.inject({
      method: "POST",
      url: `/v1/domains/custom/${customDomainBody.id}/route`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { tunnelId: tunnelBody.id, tlsMode: "termination" },
    });
    expect(routeRes.statusCode).toBe(200);

    const startRes = await app.inject({
      method: "POST",
      url: `/v1/tunnels/${tunnelBody.id}/start`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    });
    expect(startRes.statusCode).toBe(200);
    const startBody = startRes.json() as {
      agentToken: string;
      hosts: string[];
      tlsModes: Record<string, "termination" | "passthrough">;
    };

    const claims = jwt.verify(startBody.agentToken, process.env.AGENT_JWT_SECRET!) as {
      hosts: string[];
      tlsModes: Record<string, "termination" | "passthrough">;
      basicAuthUser: string;
      basicAuthPassword: string;
      ipAllowlist: string[];
      tokenType: string;
    };

    expect(claims.tokenType).toBe("agent");
    expect(claims.basicAuthUser).toBe("demo");
    expect(claims.basicAuthPassword).toBe("secret");
    expect(claims.ipAllowlist).toContain("127.0.0.1/32");
    expect(claims.hosts).toContain(domainName);
    expect(claims.hosts.some((host) => host.endsWith(`.${process.env.BASE_DOMAIN}`))).toBe(true);
    expect(claims.tlsModes[domainName]).toBe("termination");
    expect(startBody.hosts).toContain(domainName);

    const adminDomainsRes = await app.inject({
      method: "GET",
      url: "/v1/admin/domains",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminDomainsRes.statusCode).toBe(200);
    const adminDomainsBody = adminDomainsRes.json() as {
      domains: Array<{ domain: string; tls_status: string; tls_mode: string }>;
    };
    const adminDomain = adminDomainsBody.domains.find((item) => item.domain === domainName);
    expect(adminDomain).toBeTruthy();
    expect(adminDomain?.tls_mode).toBe("termination");
    expect(adminDomain?.tls_status).toBe("pending_issue");
  }, 30_000);
});
