import argon2 from "argon2";
import { FastifyPluginAsync } from "fastify";
import { z } from "zod";

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
      inspect: boolean;
      basic_auth_user: string | null;
      basic_auth_password: string | null;
      ip_allowlist: string[];
    }>(
      `
      SELECT t.id, t.protocol, t.subdomain, t.org_id, t.status, t.local_addr, t.public_url, t.inspect,
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
      return reply.code(401).send({ message: "Invalid authtoken" });
    }

    const token = await app.auth.signAgentToken({
      userId: tunnel.user_id,
      orgId: tunnel.org_id,
      tunnelId: tunnel.id,
      protocol: tunnel.protocol,
      subdomain: tunnel.subdomain,
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
        inspect: tunnel.inspect,
        authPolicy: {
          basicAuthUser: tunnel.basic_auth_user,
          basicAuthPassword: tunnel.basic_auth_password,
          ipAllowlist: tunnel.ip_allowlist,
        },
      },
    };
  });
};
