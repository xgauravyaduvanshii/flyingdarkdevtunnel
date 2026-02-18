import crypto from "node:crypto";
import dns from "node:dns/promises";
import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { getEntitlements } from "../lib/entitlements.js";
import { randomToken } from "../lib/utils.js";

const tlsModeSchema = z.enum(["termination", "passthrough"]);
const certFailurePolicySchema = z.enum(["standard", "strict", "hold"]);
const certEventTypeSchema = z.enum([
  "issuance_succeeded",
  "issuance_failed",
  "renewal_succeeded",
  "renewal_failed",
  "certificate_expiring",
]);

type CertSourceKeyMap = Map<string, string>;

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

function certSourceKey(source: string, clusterId: string): string {
  return `${source.trim().toLowerCase()}::${clusterId.trim().toLowerCase()}`;
}

function parseCertSourceKeys(raw: string | undefined): CertSourceKeyMap {
  const map: CertSourceKeyMap = new Map();
  if (!raw) return map;

  for (const item of raw.split(",")) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    const [subject, secret] = trimmed.split("=", 2);
    if (!subject || !secret) continue;

    const [source, clusterId] = subject.split(":", 2).map((part) => part?.trim().toLowerCase() ?? "");
    if (!source || !clusterId || !secret.trim()) continue;
    map.set(certSourceKey(source, clusterId), secret.trim());
  }

  return map;
}

function headerValue(value: string | string[] | undefined): string | null {
  if (!value) return null;
  if (Array.isArray(value)) return value[0] ?? null;
  return value;
}

function getRawBody(request: { rawBody?: string | Buffer; body?: unknown }): string {
  const raw = request.rawBody;
  if (typeof raw === "string") return raw;
  if (raw && Buffer.isBuffer(raw)) return raw.toString("utf8");
  return JSON.stringify(request.body ?? {});
}

function safeHexCompare(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length || left.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

export const domainRoutes: FastifyPluginAsync = async (app) => {
  const sourceKeys = parseCertSourceKeys(app.env.CERT_EVENT_SOURCE_KEYS);
  const provenanceRequired = app.env.CERT_EVENT_REQUIRE_PROVENANCE || sourceKeys.size > 0;

  async function recordCertSourceActivity(input: {
    source: string;
    clusterId: string;
    eventId: string | null;
    eventType: string | null;
    status: "accepted" | "signature_failed";
    signatureFailed?: boolean;
  }): Promise<void> {
    await app.db.query(
      `
        INSERT INTO cert_event_source_activity (
          source,
          cluster_id,
          last_event_id,
          last_event_type,
          last_status,
          events_total,
          signature_failures,
          last_seen_at,
          updated_at
        )
        VALUES ($1, $2, $3, $4, $5, 1, $6, NOW(), NOW())
        ON CONFLICT (source, cluster_id) DO UPDATE
        SET
          last_event_id = COALESCE(EXCLUDED.last_event_id, cert_event_source_activity.last_event_id),
          last_event_type = COALESCE(EXCLUDED.last_event_type, cert_event_source_activity.last_event_type),
          last_status = EXCLUDED.last_status,
          events_total = cert_event_source_activity.events_total + 1,
          signature_failures = cert_event_source_activity.signature_failures + EXCLUDED.signature_failures,
          last_seen_at = NOW(),
          updated_at = NOW()
      `,
      [
        input.source.trim().toLowerCase(),
        input.clusterId.trim().toLowerCase(),
        input.eventId,
        input.eventType,
        input.status,
        input.signatureFailed ? 1 : 0,
      ],
    );
  }

  app.post("/cert-events", { config: { rawBody: true } }, async (request, reply) => {
    if (!app.env.CERT_EVENT_INGEST_TOKEN) {
      return reply.code(503).send({ message: "Certificate event ingest token is not configured" });
    }

    const providedToken = request.headers["x-cert-event-token"];
    const ingestToken = typeof providedToken === "string" ? providedToken.trim() : "";
    if (!ingestToken || ingestToken !== app.env.CERT_EVENT_INGEST_TOKEN) {
      return reply.code(401).send({ message: "Invalid certificate ingest token" });
    }

    const body = z
      .object({
        source: z.string().min(2).max(80).optional().default("cert_manager"),
        clusterId: z.string().min(2).max(120).optional(),
        sourceEventId: z.string().min(3).max(200).optional(),
        domainId: z.string().uuid().optional(),
        domain: z.string().min(3).optional(),
        eventType: certEventTypeSchema,
        certificateRef: z.string().max(255).optional(),
        notAfter: z.coerce.date().optional(),
        renewalDueAt: z.coerce.date().optional(),
        reason: z.string().max(4000).optional(),
        payload: z.record(z.unknown()).optional(),
      })
      .parse(request.body ?? {});

    const source = body.source.trim().toLowerCase();
    let eventClusterId = body.clusterId?.trim().toLowerCase() ?? "";
    const rawBody = getRawBody(request);
    let provenanceVerified = false;
    let provenanceSubject: string | null = null;

    if (provenanceRequired) {
      const sourceHeader = headerValue(request.headers["x-cert-source"])?.trim().toLowerCase() ?? source;
      const clusterHeader = headerValue(request.headers["x-cert-cluster"])?.trim().toLowerCase() ?? eventClusterId;
      const timestampRaw = headerValue(request.headers["x-cert-timestamp"]);
      const signature = headerValue(request.headers["x-cert-signature"])?.trim().toLowerCase() ?? "";
      const signingSecret = sourceKeys.get(certSourceKey(sourceHeader, clusterHeader));

      if (!signingSecret) {
        await recordCertSourceActivity({
          source: sourceHeader || source,
          clusterId: clusterHeader || "unknown",
          eventId: body.sourceEventId ?? null,
          eventType: body.eventType,
          status: "signature_failed",
          signatureFailed: true,
        });
        return reply.code(401).send({ message: "Unknown certificate source/cluster identity" });
      }

      const eventTs = timestampRaw ? Number.parseInt(timestampRaw, 10) : Number.NaN;
      if (!Number.isFinite(eventTs)) {
        await recordCertSourceActivity({
          source: sourceHeader,
          clusterId: clusterHeader,
          eventId: body.sourceEventId ?? null,
          eventType: body.eventType,
          status: "signature_failed",
          signatureFailed: true,
        });
        return reply.code(401).send({ message: "Invalid certificate timestamp" });
      }

      const nowSeconds = Math.floor(Date.now() / 1000);
      if (Math.abs(nowSeconds - eventTs) > app.env.CERT_EVENT_MAX_AGE_SECONDS) {
        await recordCertSourceActivity({
          source: sourceHeader,
          clusterId: clusterHeader,
          eventId: body.sourceEventId ?? null,
          eventType: body.eventType,
          status: "signature_failed",
          signatureFailed: true,
        });
        return reply.code(401).send({ message: "Certificate signature timestamp expired" });
      }

      const expected = crypto.createHmac("sha256", signingSecret).update(`${timestampRaw}.${rawBody}`).digest("hex");
      if (!signature || !safeHexCompare(expected, signature)) {
        await recordCertSourceActivity({
          source: sourceHeader,
          clusterId: clusterHeader,
          eventId: body.sourceEventId ?? null,
          eventType: body.eventType,
          status: "signature_failed",
          signatureFailed: true,
        });
        return reply.code(401).send({ message: "Invalid certificate signature" });
      }

      if (body.source && sourceHeader !== source) {
        return reply.code(400).send({ message: "x-cert-source header does not match source body field" });
      }
      if (body.clusterId && clusterHeader !== eventClusterId) {
        return reply.code(400).send({ message: "x-cert-cluster header does not match clusterId body field" });
      }

      provenanceVerified = true;
      eventClusterId = clusterHeader;
      provenanceSubject = `${sourceHeader}:${clusterHeader}`;
    }

    let domainId: string | null = body.domainId ?? null;
    let domain = body.domain ? normalizeDomain(body.domain) : "";

    if (domainId) {
      const domainRes = await app.db.query<{ id: string; domain: string }>(
        `SELECT id, domain FROM custom_domains WHERE id = $1 LIMIT 1`,
        [domainId],
      );
      if (!domainRes.rowCount || !domainRes.rows[0]) {
        return reply.code(404).send({ message: "Custom domain not found for domainId" });
      }
      domain = domainRes.rows[0].domain;
      domainId = domainRes.rows[0].id;
    } else if (domain) {
      const domainRes = await app.db.query<{ id: string }>(`SELECT id FROM custom_domains WHERE domain = $1 LIMIT 1`, [domain]);
      if (domainRes.rowCount && domainRes.rows[0]) {
        domainId = domainRes.rows[0].id;
      }
    }

    if (!domain) {
      return reply.code(400).send({ message: "domain or domainId is required" });
    }

    let eventId = uuidv4();
    if (body.sourceEventId) {
      const existing = await app.db.query<{ id: string }>(
        `
          SELECT id
          FROM certificate_lifecycle_events
          WHERE source = $1 AND source_event_id = $2
          ORDER BY created_at DESC
          LIMIT 1
        `,
        [source, body.sourceEventId],
      );

      if (existing.rowCount && existing.rows[0]) {
        eventId = existing.rows[0].id;
        await app.db.query(
          `
            UPDATE certificate_lifecycle_events
            SET
              domain_id = COALESCE($2, domain_id),
              domain = $3,
              event_type = $4,
              status = 'pending',
              certificate_ref = COALESCE($5, certificate_ref),
              not_after = COALESCE($6, not_after),
              renewal_due_at = COALESCE($7, renewal_due_at),
              reason = COALESCE($8, reason),
              payload_json = COALESCE($9, payload_json),
              cluster_id = COALESCE($10, cluster_id),
              provenance_subject = COALESCE($11, provenance_subject),
              provenance_verified = COALESCE($12, provenance_verified),
              last_error = NULL,
              retry_count = 0,
              next_retry_at = NULL,
              processed_at = NULL,
              updated_at = NOW()
            WHERE id = $1
          `,
          [
            eventId,
            domainId,
            domain,
            body.eventType,
            body.certificateRef ?? null,
            body.notAfter ?? null,
            body.renewalDueAt ?? null,
            body.reason ?? null,
            body.payload ?? null,
            eventClusterId || null,
            provenanceSubject,
            provenanceRequired ? provenanceVerified : null,
          ],
        );
      } else {
        await app.db.query(
          `
            INSERT INTO certificate_lifecycle_events (
              id,
              source,
              source_event_id,
              cluster_id,
              domain_id,
              domain,
              event_type,
              status,
              certificate_ref,
              not_after,
              renewal_due_at,
              reason,
              payload_json,
              provenance_subject,
              provenance_verified,
              retry_count,
              next_retry_at,
              last_error,
              updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12, $13, 0, NULL, NULL, NOW())
          `,
          [
            eventId,
            source,
            body.sourceEventId,
            eventClusterId || null,
            domainId,
            domain,
            body.eventType,
            body.certificateRef ?? null,
            body.notAfter ?? null,
            body.renewalDueAt ?? null,
            body.reason ?? null,
            body.payload ?? null,
            provenanceSubject,
            provenanceVerified,
          ],
        );
      }
    } else {
      await app.db.query(
        `
          INSERT INTO certificate_lifecycle_events (
            id,
            source,
            source_event_id,
            cluster_id,
            domain_id,
            domain,
            event_type,
            status,
            certificate_ref,
            not_after,
            renewal_due_at,
            reason,
            payload_json,
            provenance_subject,
            provenance_verified
          )
          VALUES ($1, $2, NULL, $3, $4, $5, $6, 'pending', $7, $8, $9, $10, $11, $12)
        `,
        [
          eventId,
          source,
          eventClusterId || null,
          domainId,
          domain,
          body.eventType,
          body.certificateRef ?? null,
          body.notAfter ?? null,
          body.renewalDueAt ?? null,
          body.reason ?? null,
          body.payload ?? null,
          provenanceSubject,
          provenanceVerified,
        ],
      );
    }

    if (provenanceVerified && eventClusterId) {
      await recordCertSourceActivity({
        source,
        clusterId: eventClusterId,
        eventId: body.sourceEventId ?? eventId,
        eventType: body.eventType,
        status: "accepted",
      });
    }

    return reply.code(202).send({
      ok: true,
      eventId,
      status: "pending",
      source,
      clusterId: eventClusterId || null,
      provenanceVerified,
      provenanceSubject,
    });
  });

  app.addHook("preHandler", async (request, reply) => {
    if (request.url === "/v1/domains/cert-events" || request.url.endsWith("/domains/cert-events")) {
      return;
    }
    await app.auth.requireAuth(request, reply);
  });

  app.get("/custom", async (request) => {
    const rows = await app.db.query(
      `
      SELECT
        id,
        domain,
        verified,
        verification_token,
        tls_status,
        tls_mode,
        target_tunnel_id,
        last_verified_at,
        certificate_ref,
        tls_last_checked_at,
        tls_not_after,
        tls_last_error,
        cert_failure_policy,
        cert_failure_count,
        cert_retry_backoff_seconds,
        cert_next_retry_at,
        cert_last_event_type,
        cert_last_event_at,
        cert_renewal_due_at,
        created_at
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
      SET verified = TRUE, tls_status = 'pending_issue', last_verified_at = NOW(), updated_at = NOW()
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
      SET
        target_tunnel_id = $1,
        tls_mode = $2,
        tls_status = CASE WHEN verified THEN 'pending_issue' ELSE tls_status END,
        updated_at = NOW()
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

  app.patch("/custom/:id/failure-policy", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z.object({ policy: certFailurePolicySchema }).parse(request.body ?? {});

    const result = await app.db.query(
      `
      UPDATE custom_domains
      SET cert_failure_policy = $1, updated_at = NOW()
      WHERE id = $2 AND org_id = $3
    `,
      [body.policy, params.id, request.authUser!.orgId],
    );

    if (!result.rowCount) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "domain.custom.failure_policy.update",
      entityType: "custom_domain",
      entityId: params.id,
      metadata: { policy: body.policy },
    });

    return { ok: true, policy: body.policy };
  });

  app.get("/custom/:id/cert-events", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const query = z.object({ limit: z.coerce.number().int().min(1).max(500).default(100) }).parse(request.query ?? {});

    const ownership = await app.db.query<{ id: string }>(
      `SELECT id FROM custom_domains WHERE id = $1 AND org_id = $2 LIMIT 1`,
      [params.id, request.authUser!.orgId],
    );
    if (!ownership.rowCount) {
      return reply.code(404).send({ message: "Custom domain not found" });
    }

    const events = await app.db.query(
      `
      SELECT
        id,
        source,
        source_event_id,
        cluster_id,
        domain_id,
        domain,
        event_type,
        status,
        certificate_ref,
        not_after,
        renewal_due_at,
        reason,
        retry_count,
        next_retry_at,
        last_error,
        provenance_subject,
        provenance_verified,
        created_at,
        updated_at,
        processed_at
      FROM certificate_lifecycle_events
      WHERE domain_id = $1
      ORDER BY created_at DESC
      LIMIT $2
    `,
      [params.id, query.limit],
    );

    return { events: events.rows };
  });

  app.post("/custom/:id/unroute", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);

    const result = await app.db.query(
      `
      UPDATE custom_domains
      SET target_tunnel_id = NULL, updated_at = NOW()
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
