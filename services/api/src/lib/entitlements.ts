import type { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";

export type Entitlement = {
  max_tunnels: number;
  max_concurrent_conns: number;
  reserved_domains: boolean;
  custom_domains: boolean;
  ip_allowlist: boolean;
  retention_hours: number;
};

export async function getEntitlements(app: FastifyInstance, orgId: string): Promise<Entitlement> {
  const current = await app.db.query<Entitlement>(
    `
      SELECT max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours
      FROM entitlements
      WHERE org_id = $1
    `,
    [orgId],
  );

  if (current.rowCount && current.rows[0]) {
    return current.rows[0];
  }

  const freePlan = await app.db.query<Entitlement>(
    `
      SELECT max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours
      FROM plans
      WHERE code = 'free'
      LIMIT 1
    `,
  );

  const fallback = freePlan.rows[0];
  if (!fallback) {
    throw new Error("Free plan missing in database");
  }
  await app.db.query(
    `
      INSERT INTO entitlements
      (id, org_id, plan_id, max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours)
      VALUES ($8, $1, '11111111-1111-1111-1111-111111111111', $2, $3, $4, $5, $6, $7)
      ON CONFLICT (org_id) DO NOTHING
    `,
    [
      orgId,
      fallback.max_tunnels,
      fallback.max_concurrent_conns,
      fallback.reserved_domains,
      fallback.custom_domains,
      fallback.ip_allowlist,
      fallback.retention_hours,
      randomUUID()
    ],
  );

  return fallback;
}
