import type { FastifyInstance } from "fastify";
import { adminRoutes } from "./admin.js";
import { agentRoutes } from "./agent.js";
import { authRoutes } from "./auth.js";
import { billingRoutes } from "./billing.js";
import { domainRoutes } from "./domains.js";
import { planRoutes } from "./plans.js";
import { relayRoutes } from "./relay.js";
import { requestRoutes } from "./requests.js";
import { tunnelRoutes } from "./tunnels.js";

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  await app.register(async (v1) => {
    await v1.register(authRoutes, { prefix: "/auth" });
    await v1.register(tunnelRoutes, { prefix: "/tunnels" });
    await v1.register(requestRoutes, { prefix: "/requests" });
    await v1.register(domainRoutes, { prefix: "/domains" });
    await v1.register(planRoutes);
    await v1.register(billingRoutes, { prefix: "/billing" });
    await v1.register(adminRoutes, { prefix: "/admin" });
    await v1.register(agentRoutes, { prefix: "/agent" });
    await v1.register(relayRoutes, { prefix: "/relay" });
  }, { prefix: "/v1" });

  app.get("/healthz", async () => ({ ok: true }));
}
