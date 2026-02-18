import { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";

function relayTokenFromHeaders(headers: Record<string, unknown>): string | null {
  const bearerRaw = headers.authorization;
  if (typeof bearerRaw === "string" && bearerRaw.startsWith("Bearer ")) {
    return bearerRaw.slice("Bearer ".length).trim();
  }
  const relayHeader = headers["x-relay-token"];
  if (typeof relayHeader === "string" && relayHeader.trim()) {
    return relayHeader.trim();
  }
  return null;
}

export const relayRoutes: FastifyPluginAsync = async (app) => {
  async function requireRelayToken(request: FastifyRequest, reply: FastifyReply): Promise<boolean> {
    if (!app.env.RELAY_HEARTBEAT_TOKEN) {
      await reply.code(503).send({ message: "Relay heartbeat token is not configured" });
      return false;
    }

    const providedToken = relayTokenFromHeaders(request.headers as Record<string, unknown>);
    if (!providedToken || providedToken !== app.env.RELAY_HEARTBEAT_TOKEN) {
      await app.db.query(
        `
          INSERT INTO security_anomaly_events (id, category, severity, ip, route, details)
          VALUES ($1, 'auth_failed', 'high', $2, $3, $4)
        `,
        [uuidv4(), request.ip ?? null, request.url ?? "/v1/relay", { reason: "invalid_relay_heartbeat_token" }],
      );
      await reply.code(401).send({ message: "Invalid relay heartbeat token" });
      return false;
    }

    return true;
  }

  app.post("/heartbeat", async (request, reply) => {
    const ok = await requireRelayToken(request, reply);
    if (!ok) return;

    const body = z
      .object({
        edgeId: z.string().min(3).max(120),
        region: z.string().min(2).max(20),
        status: z.enum(["online", "degraded", "offline"]).optional().default("online"),
        capacity: z.coerce.number().int().nonnegative().optional().default(0),
        inFlight: z.coerce.number().int().nonnegative().optional().default(0),
        rejectedOverlimit: z.coerce.number().int().nonnegative().optional().default(0),
        metadata: z.record(z.unknown()).optional(),
      })
      .parse(request.body ?? {});

    await app.db.query(
      `
        INSERT INTO relay_edges (
          id,
          edge_id,
          region,
          status,
          capacity,
          in_flight,
          rejected_overlimit,
          metadata_json,
          last_heartbeat_at,
          updated_at
        )
        VALUES ($1, $2, LOWER($3), $4, $5, $6, $7, $8, NOW(), NOW())
        ON CONFLICT (edge_id) DO UPDATE
        SET
          region = LOWER(EXCLUDED.region),
          status = EXCLUDED.status,
          capacity = EXCLUDED.capacity,
          in_flight = EXCLUDED.in_flight,
          rejected_overlimit = EXCLUDED.rejected_overlimit,
          metadata_json = COALESCE(EXCLUDED.metadata_json, relay_edges.metadata_json),
          last_heartbeat_at = NOW(),
          updated_at = NOW()
      `,
      [
        uuidv4(),
        body.edgeId,
        body.region,
        body.status,
        body.capacity,
        body.inFlight,
        body.rejectedOverlimit,
        body.metadata ?? null,
      ],
    );

    return {
      ok: true,
      edgeId: body.edgeId,
      region: body.region.toLowerCase(),
      status: body.status,
      receivedAt: new Date().toISOString(),
    };
  });

  app.get("/cert-replication", async (request, reply) => {
    const ok = await requireRelayToken(request, reply);
    if (!ok) return;

    const query = z
      .object({
        region: z.string().min(2).max(20),
        includeStale: z.coerce.boolean().optional().default(false),
        limit: z.coerce.number().int().min(1).max(5000).default(2000),
      })
      .parse(request.query ?? {});

    const rows = await app.db.query(
      `
        SELECT
          domain,
          source_region,
          target_region,
          tls_mode,
          tls_status,
          replication_state,
          lag_seconds,
          certificate_ref,
          tls_not_after,
          renewal_due_at,
          cert_last_event_at,
          synced_at
        FROM cert_region_replicas
        WHERE target_region = LOWER($1)
          AND ($2::boolean = TRUE OR replication_state <> 'stale')
        ORDER BY synced_at DESC, domain ASC
        LIMIT $3
      `,
      [query.region, query.includeStale, query.limit],
    );

    return {
      region: query.region.toLowerCase(),
      includeStale: query.includeStale,
      replicas: rows.rows,
      generatedAt: new Date().toISOString(),
    };
  });
};
