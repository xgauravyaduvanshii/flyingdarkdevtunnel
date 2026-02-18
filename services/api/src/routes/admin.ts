import { FastifyPluginAsync } from "fastify";
import { z } from "zod";

export const adminRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.auth.requireAdmin);

  app.get("/users", async () => {
    const users = await app.db.query(
      `
      SELECT u.id, u.email, u.created_at, m.role, m.org_id
      FROM users u
      JOIN memberships m ON m.user_id = u.id
      ORDER BY u.created_at DESC
      LIMIT 500
    `,
    );

    return { users: users.rows };
  });

  app.get("/tunnels", async () => {
    const tunnels = await app.db.query(
      `
      SELECT id, org_id, name, protocol, subdomain, public_url, status, region, created_at
      FROM tunnels
      ORDER BY created_at DESC
      LIMIT 1000
    `,
    );

    return { tunnels: tunnels.rows };
  });

  app.get("/domains", async () => {
    const domains = await app.db.query(
      `
      SELECT
        cd.id,
        cd.domain,
        cd.verified,
        cd.tls_status,
        cd.tls_mode,
        cd.target_tunnel_id,
        cd.certificate_ref,
        cd.tls_last_checked_at,
        cd.tls_not_after,
        cd.tls_last_error,
        cd.created_at,
        cd.org_id,
        t.name AS tunnel_name
      FROM custom_domains cd
      LEFT JOIN tunnels t ON t.id = cd.target_tunnel_id
      ORDER BY cd.created_at DESC
      LIMIT 1000
    `,
    );

    return { domains: domains.rows };
  });

  app.patch("/users/:id/plan", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z.object({ planCode: z.enum(["free", "pro", "team"]) }).parse(request.body);

    const member = await app.db.query<{ org_id: string }>(`SELECT org_id FROM memberships WHERE user_id = $1 LIMIT 1`, [params.id]);

    if (!member.rowCount) {
      return reply.code(404).send({ message: "User membership not found" });
    }

    const orgId = member.rows[0].org_id;
    const plan = await app.db.query(
      `
      SELECT id, max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours
      FROM plans
      WHERE code = $1
      LIMIT 1
    `,
      [body.planCode],
    );

    if (!plan.rowCount) {
      return reply.code(404).send({ message: "Plan not found" });
    }

    const p = plan.rows[0];

    await app.db.query(
      `
      UPDATE entitlements
      SET
        plan_id = $1,
        max_tunnels = $2,
        max_concurrent_conns = $3,
        reserved_domains = $4,
        custom_domains = $5,
        ip_allowlist = $6,
        retention_hours = $7,
        updated_at = NOW()
      WHERE org_id = $8
    `,
      [
        p.id,
        p.max_tunnels,
        p.max_concurrent_conns,
        p.reserved_domains,
        p.custom_domains,
        p.ip_allowlist,
        p.retention_hours,
        orgId,
      ],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId,
      action: "admin.plan.override",
      entityType: "organization",
      entityId: orgId,
      metadata: body
    });

    return { ok: true };
  });

  app.get("/audit", async (request) => {
    const limit = z.coerce.number().min(1).max(500).default(100).parse((request.query as any)?.limit ?? 100);

    const logs = await app.db.query(
      `
      SELECT id, actor_user_id, org_id, action, entity_type, entity_id, metadata, created_at
      FROM audit_logs
      ORDER BY created_at DESC
      LIMIT $1
    `,
      [limit],
    );

    return { audit: logs.rows };
  });
};
