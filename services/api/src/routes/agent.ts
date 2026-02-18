import argon2 from "argon2";
import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { getEntitlements } from "../lib/entitlements.js";

export const agentRoutes: FastifyPluginAsync = async (app) => {
  app.post("/exchange", async (request, reply) => {
    const body = z.object({ authtoken: z.string().min(20), tunnelId: z.string().uuid() }).parse(request.body);

    const tunnelRes = await app.db.query<{
      id: string;
      protocol: "http" | "https" | "tcp";
      subdomain: string | null;
      org_id: string;
      user_id: string;
      authtoken_hash: string;
      status: string;
      local_addr: string;
      public_url: string | null;
      region: string;
      inspect: boolean;
      basic_auth_user: string | null;
      basic_auth_password: string | null;
      ip_allowlist: string[];
    }>(
      `
      SELECT t.id, t.protocol, t.subdomain, t.org_id, t.status, t.local_addr, t.public_url, t.region, t.inspect,
             t.basic_auth_user, t.basic_auth_password, t.ip_allowlist,
             u.id AS user_id, u.authtoken_hash
      FROM tunnels t
      JOIN memberships m ON m.org_id = t.org_id
      JOIN users u ON u.id = m.user_id
      WHERE t.id = $1
      ORDER BY m.created_at ASC
      LIMIT 1
    `,
      [body.tunnelId],
    );

    const tunnel = tunnelRes.rows[0];
    if (!tunnel) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    const ok = await argon2.verify(tunnel.authtoken_hash, body.authtoken);
    if (!ok) {
      await app.db.query(
        `
        INSERT INTO security_anomaly_events (id, category, severity, ip, user_id, org_id, route, details)
        VALUES ($1, 'auth_failed', 'high', $2, $3, $4, '/v1/agent/exchange', $5)
      `,
        [uuidv4(), request.ip ?? null, tunnel.user_id ?? null, tunnel.org_id, { reason: "invalid_authtoken", tunnelId: body.tunnelId }],
      );
      return reply.code(401).send({ message: "Invalid authtoken" });
    }

    const hosts: string[] = [];
    const tlsModes: Record<string, "termination" | "passthrough"> = {};
    if (tunnel.subdomain) {
      const defaultHost = `${tunnel.subdomain}.${app.env.BASE_DOMAIN}`;
      hosts.push(defaultHost);
      tlsModes[defaultHost] = "termination";
    }

    const domainRoutes = await app.db.query<{
      domain: string;
      tls_mode: "termination" | "passthrough";
    }>(
      `
      SELECT domain, tls_mode
      FROM custom_domains
      WHERE org_id = $1 AND target_tunnel_id = $2 AND verified = TRUE
    `,
      [tunnel.org_id, tunnel.id],
    );
    for (const route of domainRoutes.rows) {
      hosts.push(route.domain);
      tlsModes[route.domain] = route.tls_mode;
    }

    const token = await app.auth.signAgentToken({
      userId: tunnel.user_id,
      orgId: tunnel.org_id,
      tunnelId: tunnel.id,
      protocol: tunnel.protocol,
      subdomain: tunnel.subdomain,
      hosts,
      tlsModes,
      basicAuthUser: tunnel.basic_auth_user,
      basicAuthPassword: tunnel.basic_auth_password,
      ipAllowlist: tunnel.ip_allowlist ?? [],
      region: tunnel.region ?? "us",
      maxConcurrentConns: (await getEntitlements(app, tunnel.org_id)).max_concurrent_conns,
    });

    await app.audit.log({
      actorUserId: tunnel.user_id,
      orgId: tunnel.org_id,
      action: "agent.exchange",
      entityType: "tunnel",
      entityId: tunnel.id
    });

    return {
      agentToken: token,
      tunnel: {
        id: tunnel.id,
        protocol: tunnel.protocol,
        subdomain: tunnel.subdomain,
        localAddr: tunnel.local_addr,
        publicUrl: tunnel.public_url,
        region: tunnel.region ?? "us",
        inspect: tunnel.inspect,
        hosts,
        tlsModes,
        authPolicy: {
          basicAuthUser: tunnel.basic_auth_user,
          basicAuthPassword: tunnel.basic_auth_password,
          ipAllowlist: tunnel.ip_allowlist,
        },
      },
    };
  });
};
