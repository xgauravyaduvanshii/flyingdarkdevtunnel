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

type RegionEdgeWeightMap = Map<string, Map<string, number>>;
type RegionFailoverMap = Map<string, string[]>;

function parseRegionEdgeWeights(raw: string | undefined): RegionEdgeWeightMap {
  const map: RegionEdgeWeightMap = new Map();
  if (!raw) return map;

  for (const segmentRaw of raw.split(";")) {
    const segment = segmentRaw.trim();
    if (!segment) continue;
    const [regionRaw, edgesRaw] = segment.split("=", 2);
    const region = regionRaw?.trim().toLowerCase();
    if (!region || !edgesRaw) continue;

    const edgeMap: Map<string, number> = new Map();
    for (const edgeItemRaw of edgesRaw.split("|")) {
      const edgeItem = edgeItemRaw.trim();
      if (!edgeItem) continue;

      const [edgeIdRaw, weightRaw] = edgeItem.split(":", 2);
      const edgeId = edgeIdRaw?.trim();
      if (!edgeId) continue;
      const parsedWeight = weightRaw ? Number.parseFloat(weightRaw.trim()) : 1;
      const weight = Number.isFinite(parsedWeight) && parsedWeight > 0 ? parsedWeight : 1;
      edgeMap.set(edgeId, weight);
    }

    if (edgeMap.size > 0) {
      map.set(region, edgeMap);
    }
  }

  return map;
}

function parseFailoverRegions(raw: string | undefined): RegionFailoverMap {
  const map: RegionFailoverMap = new Map();
  if (!raw) return map;

  for (const segmentRaw of raw.split(";")) {
    const segment = segmentRaw.trim();
    if (!segment) continue;

    const [regionRaw, failoversRaw] = segment.split("=", 2);
    const region = regionRaw?.trim().toLowerCase();
    if (!region || !failoversRaw) continue;

    const failovers = failoversRaw
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry.length > 0 && entry !== region);

    if (failovers.length > 0) {
      map.set(region, Array.from(new Set(failovers)));
    }
  }

  return map;
}

function selectEdgeByScore(edges: RelayEdgeRow[], edgeWeights: Map<string, number> | undefined): RelayEdgeRow | null {
  if (edges.length === 0) return null;

  const ranked = [...edges].sort((left, right) => {
    const leftWeight = edgeWeights?.get(left.edge_id) ?? 1;
    const rightWeight = edgeWeights?.get(right.edge_id) ?? 1;

    const leftLoad = left.capacity > 0 ? left.in_flight / left.capacity : left.in_flight;
    const rightLoad = right.capacity > 0 ? right.in_flight / right.capacity : right.in_flight;

    const leftRejected = Number.parseInt(left.rejected_overlimit, 10) || 0;
    const rightRejected = Number.parseInt(right.rejected_overlimit, 10) || 0;

    const leftScore = (leftLoad + leftRejected / 10_000) / leftWeight;
    const rightScore = (rightLoad + rightRejected / 10_000) / rightWeight;
    if (leftScore !== rightScore) return leftScore - rightScore;

    return right.last_heartbeat_at.getTime() - left.last_heartbeat_at.getTime();
  });

  return ranked[0] ?? null;
}

async function fetchHealthyEdgesForRegion(
  app: FastifyInstance,
  region: string,
  maxAgeSeconds: number,
): Promise<RelayEdgeRow[]> {
  const rows = await app.db.query<RelayEdgeRow>(
    `
      SELECT
        edge_id,
        region,
        status,
        capacity,
        in_flight,
        rejected_overlimit::text,
        last_heartbeat_at,
        metadata_json
      FROM relay_edges
      WHERE region = $1
        AND status IN ('online', 'degraded')
        AND last_heartbeat_at >= NOW() - make_interval(secs => $2::int)
      ORDER BY last_heartbeat_at DESC
    `,
    [region, maxAgeSeconds],
  );

  return rows.rows;
}

export async function pickRelayEdgeForRegion(app: FastifyInstance, requestedRegion: string): Promise<string> {
  const region = requestedRegion.trim().toLowerCase();
  const maxAgeSeconds = app.env.RELAY_HEARTBEAT_MAX_AGE_SECONDS;
  const edgeWeights = parseRegionEdgeWeights(app.env.RELAY_REGION_WEIGHTS);
  const failoverRegions = parseFailoverRegions(app.env.RELAY_FAILOVER_REGIONS);
  const regionCandidates = [region, ...(failoverRegions.get(region) ?? [])];

  for (const candidateRegion of regionCandidates) {
    const edges = await fetchHealthyEdgesForRegion(app, candidateRegion, maxAgeSeconds);
    const selected = selectEdgeByScore(edges, edgeWeights.get(candidateRegion));
    if (selected) {
      return selected.edge_id;
    }
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
