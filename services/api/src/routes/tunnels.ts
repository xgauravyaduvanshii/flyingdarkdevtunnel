import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { getEntitlements } from "../lib/entitlements.js";
import { generateSubdomain } from "../lib/utils.js";

const createTunnelSchema = z.object({
  name: z.string().min(2).max(80),
  protocol: z.enum(["http", "https", "tcp"]),
  localAddr: z.string().min(3),
  requestedSubdomain: z.string().regex(/^[a-z0-9-]{3,40}$/).optional(),
  region: z.string().min(2).max(16).optional(),
  inspect: z.boolean().default(true),
  basicAuthUser: z.string().optional(),
  basicAuthPassword: z.string().optional(),
  ipAllowlist: z.array(z.string()).optional()
});

const updateTunnelSchema = createTunnelSchema.partial();

export const tunnelRoutes: FastifyPluginAsync = async (app) => {
  const allowedRegions = app.env.ALLOWED_REGIONS.split(",")
    .map((region) => region.trim().toLowerCase())
    .filter(Boolean);

  app.addHook("preHandler", app.auth.requireAuth);

  app.get("/", async (request) => {
    const tunnels = await app.db.query(
      `
      SELECT id, name, protocol, local_addr, subdomain, public_url, status, inspect, region, created_at, updated_at
      FROM tunnels
      WHERE org_id = $1
      ORDER BY created_at DESC
    `,
      [request.authUser!.orgId],
    );
    return { tunnels: tunnels.rows };
  });

  app.post("/", async (request, reply) => {
    const body = createTunnelSchema.parse(request.body);

    const entitlement = await getEntitlements(app, request.authUser!.orgId);
    const countRes = await app.db.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM tunnels WHERE org_id = $1`, [
      request.authUser!.orgId,
    ]);
    const count = Number(countRes.rows[0]?.count ?? 0);
    if (count >= entitlement.max_tunnels) {
      return reply.code(403).send({ message: "Plan tunnel limit reached" });
    }

    if (body.ipAllowlist && body.ipAllowlist.length > 0 && !entitlement.ip_allowlist) {
      return reply.code(403).send({ message: "IP allowlist requires paid plan" });
    }

    const id = uuidv4();
    const region = (body.region ?? allowedRegions[0] ?? "us").toLowerCase();
    if (!allowedRegions.includes(region)) {
      return reply.code(400).send({ message: `Region is not allowed. Allowed regions: ${allowedRegions.join(", ")}` });
    }

    const subdomain = body.protocol === "tcp" ? null : body.requestedSubdomain ?? generateSubdomain("t");
    const publicUrl =
      body.protocol === "tcp"
        ? `tcp://${app.env.BASE_DOMAIN}`
        : `${body.protocol}://${subdomain}.${app.env.BASE_DOMAIN}`;

    await app.db.query(
      `
      INSERT INTO tunnels
      (id, org_id, name, protocol, local_addr, subdomain, public_url, status, inspect, basic_auth_user, basic_auth_password, ip_allowlist, region)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'stopped', $8, $9, $10, $11, $12)
    `,
      [
        id,
        request.authUser!.orgId,
        body.name,
        body.protocol,
        body.localAddr,
        subdomain,
        publicUrl,
        body.inspect,
        body.basicAuthUser ?? null,
        body.basicAuthPassword ?? null,
        body.ipAllowlist ?? [],
        region,
      ],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "tunnel.create",
      entityType: "tunnel",
      entityId: id,
      metadata: { protocol: body.protocol, publicUrl, region }
    });

    return reply.code(201).send({ id, publicUrl, subdomain, status: "stopped", region });
  });

  app.patch("/:id", async (request, reply) => {
    const body = updateTunnelSchema.parse(request.body);
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const existing = await app.db.query(`SELECT id, org_id FROM tunnels WHERE id = $1 AND org_id = $2`, [
      params.id,
      request.authUser!.orgId,
    ]);

    if (!existing.rowCount) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    if (body.region && !allowedRegions.includes(body.region.toLowerCase())) {
      return reply.code(400).send({ message: `Region is not allowed. Allowed regions: ${allowedRegions.join(", ")}` });
    }

    const patchMap: Record<string, unknown> = {
      name: body.name,
      local_addr: body.localAddr,
      inspect: body.inspect,
      basic_auth_user: body.basicAuthUser,
      basic_auth_password: body.basicAuthPassword,
      ip_allowlist: body.ipAllowlist,
      region: body.region?.toLowerCase(),
      updated_at: new Date().toISOString()
    };

    const keys = Object.entries(patchMap).filter(([, value]) => value !== undefined);
    if (!keys.length) {
      return { message: "No changes" };
    }

    const setSql = keys.map(([key], index) => `${key} = $${index + 1}`).join(", ");
    const values = keys.map(([, value]) => value);
    values.push(params.id, request.authUser!.orgId);

    await app.db.query(`UPDATE tunnels SET ${setSql} WHERE id = $${keys.length + 1} AND org_id = $${keys.length + 2}`, values);

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "tunnel.update",
      entityType: "tunnel",
      entityId: params.id,
      metadata: body
    });

    return { ok: true };
  });

  app.delete("/:id", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const result = await app.db.query(`DELETE FROM tunnels WHERE id = $1 AND org_id = $2`, [params.id, request.authUser!.orgId]);

    if (!result.rowCount) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "tunnel.delete",
      entityType: "tunnel",
      entityId: params.id
    });

    return { ok: true };
  });

  app.post("/:id/start", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const entitlements = await getEntitlements(app, request.authUser!.orgId);

    const tunnel = await app.db.query<{
      id: string;
      protocol: "http" | "https" | "tcp";
      subdomain: string | null;
      org_id: string;
      region: string;
      basic_auth_user: string | null;
      basic_auth_password: string | null;
      ip_allowlist: string[] | null;
    }>(
      `
      SELECT id, protocol, subdomain, org_id, region, basic_auth_user, basic_auth_password, ip_allowlist
      FROM tunnels
      WHERE id = $1 AND org_id = $2
    `,
      [params.id, request.authUser!.orgId],
    );

    if (!tunnel.rowCount || !tunnel.rows[0]) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    await app.db.query(`UPDATE tunnels SET status = 'active', updated_at = NOW() WHERE id = $1`, [params.id]);
    const sessionId = uuidv4();
    await app.db.query(`INSERT INTO tunnel_sessions (id, tunnel_id, active) VALUES ($1, $2, TRUE)`, [sessionId, params.id]);

    const row = tunnel.rows[0];
    const hosts: string[] = [];
    const tlsModes: Record<string, "termination" | "passthrough"> = {};
    if (row.subdomain) {
      const defaultHost = `${row.subdomain}.${app.env.BASE_DOMAIN}`;
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
      [request.authUser!.orgId, row.id],
    );
    for (const domainRoute of domainRoutes.rows) {
      hosts.push(domainRoute.domain);
      tlsModes[domainRoute.domain] = domainRoute.tls_mode;
    }

    const agentToken = await app.auth.signAgentToken({
      userId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      tunnelId: row.id,
      protocol: row.protocol,
      subdomain: row.subdomain,
      hosts,
      tlsModes,
      basicAuthUser: row.basic_auth_user ?? null,
      basicAuthPassword: row.basic_auth_password ?? null,
      ipAllowlist: row.ip_allowlist ?? [],
      region: row.region ?? "us",
      maxConcurrentConns: entitlements.max_concurrent_conns,
    });

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "tunnel.start",
      entityType: "tunnel",
      entityId: params.id
    });

    return {
      ok: true,
      sessionId,
      agentToken,
      hosts,
      tlsModes,
      region: row.region ?? "us",
      maxConcurrentConns: entitlements.max_concurrent_conns,
    };
  });

  app.post("/:id/stop", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const result = await app.db.query(`UPDATE tunnels SET status = 'stopped', updated_at = NOW() WHERE id = $1 AND org_id = $2`, [
      params.id,
      request.authUser!.orgId,
    ]);

    if (!result.rowCount) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    await app.db.query(`UPDATE tunnel_sessions SET active = FALSE, disconnected_at = NOW() WHERE tunnel_id = $1 AND active = TRUE`, [
      params.id,
    ]);

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "tunnel.stop",
      entityType: "tunnel",
      entityId: params.id
    });

    return { ok: true };
  });
};
