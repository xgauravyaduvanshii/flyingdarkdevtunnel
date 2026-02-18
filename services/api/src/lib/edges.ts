import type { FastifyInstance } from "fastify";

export type RelayEdgeRow = {
  edge_id: string;
  region: string;
  status: "online" | "degraded" | "offline";
  capacity: number;
  in_flight: number;
  rejected_overlimit: string;
  last_heartbeat_at: Date;
  metadata_json: unknown;
};

export async function pickRelayEdgeForRegion(app: FastifyInstance, requestedRegion: string): Promise<string> {
  const region = requestedRegion.trim().toLowerCase();
  const maxAgeSeconds = app.env.RELAY_HEARTBEAT_MAX_AGE_SECONDS;
  const preferred = await app.db.query<{ edge_id: string }>(
    `
      SELECT edge_id
      FROM relay_edges
      WHERE region = $1
        AND status IN ('online', 'degraded')
        AND last_heartbeat_at >= NOW() - make_interval(secs => $2::int)
      ORDER BY
        CASE
          WHEN capacity > 0 THEN in_flight::float8 / capacity::float8
          ELSE in_flight::float8
        END ASC,
        rejected_overlimit ASC,
        last_heartbeat_at DESC
      LIMIT 1
    `,
    [region, maxAgeSeconds],
  );

  if (preferred.rowCount && preferred.rows[0]) {
    return preferred.rows[0].edge_id;
  }

  const anyHealthy = await app.db.query<{ edge_id: string }>(
    `
      SELECT edge_id
      FROM relay_edges
      WHERE status IN ('online', 'degraded')
        AND last_heartbeat_at >= NOW() - make_interval(secs => $1::int)
      ORDER BY last_heartbeat_at DESC
      LIMIT 1
    `,
    [maxAgeSeconds],
  );

  if (anyHealthy.rowCount && anyHealthy.rows[0]) {
    return anyHealthy.rows[0].edge_id;
  }

  return `${region || "us"}-edge-fallback`;
}
