import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";

const plugin: FastifyPluginAsync = async (app) => {
  app.decorate("audit", {
    log: async ({ actorUserId, orgId, action, entityType, entityId, metadata }) => {
      await app.db.query(
        `
        INSERT INTO audit_logs (id, actor_user_id, org_id, action, entity_type, entity_id, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
        [uuidv4(), actorUserId, orgId, action, entityType, entityId, metadata ?? null],
      );
    }
  });
};

export const auditPlugin = fp(plugin);
