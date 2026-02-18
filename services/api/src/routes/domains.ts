import dns from "node:dns/promises";
import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { getEntitlements } from "../lib/entitlements.js";
import { randomToken } from "../lib/utils.js";

const tlsModeSchema = z.enum(["termination", "passthrough"]);

function normalizeDomain(input: string): string {
  return input.trim().toLowerCase().replace(/\.+$/, "");
}

function isDomainSyntaxValid(domain: string): boolean {
  if (!domain || domain.length > 253) {
    return false;
  }
  const labels = domain.split(".");
  if (labels.length < 2) {
    return false;
  }

  return labels.every((label) => /^[a-z0-9-]{1,63}$/.test(label) && !label.startsWith("-") && !label.endsWith("-"));
}

async function verifyDnsTxt(domain: string, expectedToken: string): Promise<boolean> {
  const verificationHost = `_fdt-verify.${domain}`;
  const records = await dns.resolveTxt(verificationHost);
  const flattened = records.map((chunks) => chunks.join("").trim());
  return flattened.includes(expectedToken);
}

export const domainRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.auth.requireAuth);

  app.get("/custom", async (request) => {
    const rows = await app.db.query(
      `
      SELECT id, domain, verified, verification_token, tls_status, tls_mode, target_tunnel_id, last_verified_at, certificate_ref, created_at
      FROM custom_domains
      WHERE org_id = $1
      ORDER BY created_at DESC
    `,
      [request.authUser!.orgId],
    );

    return {
      domains: rows.rows,
    };
  });

  app.post("/custom", async (request, reply) => {
    const body = z
      .object({
        domain: z.string().min(3),
        tlsMode: tlsModeSchema.default("termination"),
      })
      .parse(request.body);

    const entitlement = await getEntitlements(app, request.authUser!.orgId);
    if (!entitlement.custom_domains) {
      return reply.code(403).send({ message: "Custom domains require paid plan" });
    }

    const domain = normalizeDomain(body.domain);
    if (!isDomainSyntaxValid(domain)) {
      return reply.code(400).send({ message: "Invalid domain format" });
    }

    const id = uuidv4();
    const token = randomToken(8);

    await app.db.query(
      `
      INSERT INTO custom_domains
      (id, org_id, domain, verification_token, verified, tls_status, tls_mode)
      VALUES ($1, $2, $3, $4, FALSE, 'pending', $5)
    `,
      [id, request.authUser!.orgId, domain, token, body.tlsMode],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.create",
      entityType: "custom_domain",
      entityId: id,
      metadata: { domain, tlsMode: body.tlsMode },
    });

    return reply.code(201).send({
      id,
      domain,
      tlsMode: body.tlsMode,
      verificationToken: token,
      verificationHost: `_fdt-verify.${domain}`,
      verified: false,
    });
  });

  app.post("/custom/:id/verify", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const domainRes = await app.db.query<{
      id: string;
      domain: string;
      verification_token: string;
    }>(
      `
      SELECT id, domain, verification_token
      FROM custom_domains
      WHERE id = $1 AND org_id = $2
      LIMIT 1
    `,
      [params.id, request.authUser!.orgId],
    );

    const row = domainRes.rows[0];
    if (!row) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }

    if (app.env.DOMAIN_VERIFY_STRICT) {
      let verified = false;
      try {
        verified = await verifyDnsTxt(row.domain, row.verification_token);
      } catch (error) {
        return reply.code(400).send({ message: `DNS lookup failed: ${String(error)}` });
      }

      if (!verified) {
        return reply.code(400).send({
          message: "TXT verification failed",
          expectedHost: `_fdt-verify.${row.domain}`,
          expectedValue: row.verification_token,
        });
      }
    }

    await app.db.query(
      `
      UPDATE custom_domains
      SET verified = TRUE, tls_status = 'pending_issue', last_verified_at = NOW()
      WHERE id = $1
    `,
      [params.id],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.verify",
      entityType: "custom_domain",
      entityId: params.id,
      metadata: { strictDnsCheck: app.env.DOMAIN_VERIFY_STRICT },
    });

    return { ok: true, verified: true, tlsStatus: "pending_issue" };
  });

  app.post("/custom/:id/route", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z
      .object({
        tunnelId: z.string().uuid(),
        tlsMode: tlsModeSchema,
      })
      .parse(request.body);

    const domainRes = await app.db.query<{
      id: string;
      domain: string;
      verified: boolean;
    }>(
      `
      SELECT id, domain, verified
      FROM custom_domains
      WHERE id = $1 AND org_id = $2
      LIMIT 1
    `,
      [params.id, request.authUser!.orgId],
    );

    const domain = domainRes.rows[0];
    if (!domain) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }
    if (!domain.verified) {
      return reply.code(400).send({ message: "Domain must be verified before routing" });
    }

    const tunnelRes = await app.db.query<{ id: string; protocol: "http" | "https" | "tcp" }>(
      `SELECT id, protocol FROM tunnels WHERE id = $1 AND org_id = $2 LIMIT 1`,
      [body.tunnelId, request.authUser!.orgId],
    );

    const tunnel = tunnelRes.rows[0];
    if (!tunnel) {
      return reply.code(404).send({ message: "Tunnel not found" });
    }

    if (body.tlsMode === "passthrough" && !["tcp", "https"].includes(tunnel.protocol)) {
      return reply.code(400).send({ message: "TLS passthrough requires tunnel protocol tcp or https" });
    }

    await app.db.query(
      `
      UPDATE custom_domains
      SET target_tunnel_id = $1, tls_mode = $2, tls_status = CASE WHEN verified THEN 'pending_issue' ELSE tls_status END
      WHERE id = $3
    `,
      [body.tunnelId, body.tlsMode, params.id],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.route",
      entityType: "custom_domain",
      entityId: params.id,
      metadata: {
        tunnelId: body.tunnelId,
        tlsMode: body.tlsMode,
      },
    });

    return {
      ok: true,
      domain: domain.domain,
      tunnelId: body.tunnelId,
      tlsMode: body.tlsMode,
    };
  });

  app.post("/custom/:id/unroute", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const result = await app.db.query(
      `
      UPDATE custom_domains
      SET target_tunnel_id = NULL
      WHERE id = $1 AND org_id = $2
    `,
      [params.id, request.authUser!.orgId],
    );

    if (!result.rowCount) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.unroute",
      entityType: "custom_domain",
      entityId: params.id,
    });

    return { ok: true };
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
      entityId: params.id,
    });

    return { ok: true };
  });
};
