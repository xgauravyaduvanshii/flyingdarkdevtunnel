import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { computeAuditEntryHash } from "../lib/audit-chain.js";

const plugin: FastifyPluginAsync = async (app) => {
  app.decorate("audit", {
    log: async ({ actorUserId, orgId, action, entityType, entityId, metadata }) => {
      const createdAt = new Date();
      const previous = await app.db.query<{ entry_hash: string }>(
        `
        SELECT entry_hash
        FROM audit_logs
        WHERE org_id IS NOT DISTINCT FROM $1
          AND entry_hash IS NOT NULL
        ORDER BY created_at DESC, id DESC
        LIMIT 1
      `,
        [orgId],
      );
      const prevHash = previous.rows[0]?.entry_hash ?? null;
      const entryHash = computeAuditEntryHash({
        actorUserId,
        orgId,
        action,
        entityType,
        entityId,
        metadata,
        createdAtIso: createdAt.toISOString(),
        prevHash,
      });

      await app.db.query(
        `
        INSERT INTO audit_logs (id, actor_user_id, org_id, action, entity_type, entity_id, metadata, prev_hash, entry_hash, immutable, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, $10)
      `,
        [uuidv4(), actorUserId, orgId, action, entityType, entityId, metadata ?? null, prevHash, entryHash, createdAt],
      );
    }
  });
};

export const auditPlugin = fp(plugin);
