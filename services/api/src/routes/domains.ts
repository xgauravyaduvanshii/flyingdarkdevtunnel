import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { getEntitlements } from "../lib/entitlements.js";
import { randomToken } from "../lib/utils.js";

export const domainRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.auth.requireAuth);

  app.post("/custom", async (request, reply) => {
    const body = z.object({ domain: z.string().min(3).toLowerCase() }).parse(request.body);
    const entitlement = await getEntitlements(app, request.authUser!.orgId);

    if (!entitlement.custom_domains) {
      return reply.code(403).send({ message: "Custom domains require paid plan" });
    }

    const id = uuidv4();
    const token = randomToken(8);

    await app.db.query(
      `
      INSERT INTO custom_domains (id, org_id, domain, verification_token, verified, tls_status)
      VALUES ($1, $2, $3, $4, FALSE, 'pending')
    `,
      [id, request.authUser!.orgId, body.domain, token],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.create",
      entityType: "custom_domain",
      entityId: id,
      metadata: { domain: body.domain }
    });

    return reply.code(201).send({ id, domain: body.domain, verificationToken: token, verified: false });
  });

  app.post("/custom/:id/verify", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const domain = await app.db.query(`SELECT id, domain FROM custom_domains WHERE id = $1 AND org_id = $2 LIMIT 1`, [
      params.id,
      request.authUser!.orgId,
    ]);

    if (!domain.rowCount) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }

    await app.db.query(`UPDATE custom_domains SET verified = TRUE, tls_status = 'issued' WHERE id = $1`, [params.id]);

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.verify",
      entityType: "custom_domain",
      entityId: params.id
    });

    return { ok: true, verified: true, tlsStatus: "issued" };
  });

  app.delete("/custom/:id", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const result = await app.db.query(`DELETE FROM custom_domains WHERE id = $1 AND org_id = $2`, [
      params.id,
      request.authUser!.orgId,
    ]);

    if (!result.rowCount) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.delete",
      entityType: "custom_domain",
      entityId: params.id
    });

    return { ok: true };
  });
};
