import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";

export const requestRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.auth.requireAuth);

  app.get("/", async (request, reply) => {
    const query = z.object({ tunnelId: z.string().uuid() }).parse(request.query);

    const ownsTunnel = await app.db.query(`SELECT id FROM tunnels WHERE id = $1 AND org_id = $2`, [
      query.tunnelId,
      request.authUser!.orgId,
    ]);
    if (!ownsTunnel.rowCount) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    const rows = await app.db.query(
      `
      SELECT id, method, path, status_code, request_size, response_size, started_at, completed_at
      FROM request_logs
      WHERE tunnel_id = $1
      ORDER BY started_at DESC
      LIMIT 200
    `,
      [query.tunnelId],
    );

    return { requests: rows.rows };
  });

  app.get("/:id", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const row = await app.db.query(
      `
      SELECT rl.*, rp.req_body_ref, rp.res_body_ref
      FROM request_logs rl
      LEFT JOIN request_payload_refs rp ON rp.request_log_id = rl.id
      JOIN tunnels t ON t.id = rl.tunnel_id
      WHERE rl.id = $1 AND t.org_id = $2
      LIMIT 1
    `,
      [params.id, request.authUser!.orgId],
    );

    if (!row.rowCount) {
      return reply.code(404).send({ message: "Request log not found" });
    }

    return { request: row.rows[0] };
  });

  app.post("/:id/replay", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const exists = await app.db.query(
      `
      SELECT rl.id
      FROM request_logs rl
      JOIN tunnels t ON t.id = rl.tunnel_id
      WHERE rl.id = $1 AND t.org_id = $2
    `,
      [params.id, request.authUser!.orgId],
    );

    if (!exists.rowCount) {
      return reply.code(404).send({ message: "Request log not found" });
    }

    const replayId = uuidv4();
    await app.db.query(
      `INSERT INTO replay_jobs (id, request_log_id, status, result) VALUES ($1, $2, 'queued', NULL)`,
      [replayId, params.id],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "request.replay",
      entityType: "request_log",
      entityId: params.id,
      metadata: { replayId }
    });

    return reply.code(202).send({ replayId, status: "queued" });
  });
};
