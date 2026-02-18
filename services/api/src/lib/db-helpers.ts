import type { FastifyInstance } from "fastify";

export async function getMembership(app: FastifyInstance, userId: string, orgId: string) {
  const membership = await app.db.query<{ role: string }>(
    `SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2 LIMIT 1`,
    [userId, orgId],
  );
  return membership.rows[0] ?? null;
}
