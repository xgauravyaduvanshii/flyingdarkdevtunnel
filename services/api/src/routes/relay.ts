import { FastifyPluginAsync } from "fastify";
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
  app.post("/heartbeat", async (request, reply) => {
    if (!app.env.RELAY_HEARTBEAT_TOKEN) {
      return reply.code(503).send({ message: "Relay heartbeat token is not configured" });
    }

    const providedToken = relayTokenFromHeaders(request.headers as Record<string, unknown>);
    if (!providedToken || providedToken !== app.env.RELAY_HEARTBEAT_TOKEN) {
      await app.db.query(
        `
          INSERT INTO security_anomaly_events (id, category, severity, ip, route, details)
          VALUES ($1, 'auth_failed', 'high', $2, '/v1/relay/heartbeat', $3)
        `,
        [uuidv4(), request.ip ?? null, { reason: "invalid_relay_heartbeat_token" }],
      );
      return reply.code(401).send({ message: "Invalid relay heartbeat token" });
    }

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
};
