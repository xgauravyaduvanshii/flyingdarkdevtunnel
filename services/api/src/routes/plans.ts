import { FastifyPluginAsync } from "fastify";

export const planRoutes: FastifyPluginAsync = async (app) => {
  app.get("/plans", async () => {
    const plans = await app.db.query(
      `
      SELECT id, code, name, max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours
      FROM plans
      ORDER BY max_tunnels ASC
    `,
    );
    return { plans: plans.rows };
  });
};
