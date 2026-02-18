import argon2 from "argon2";
import { FastifyPluginAsync } from "fastify";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { computeAuditEntryHash } from "../lib/audit-chain.js";
import { pickRelayEdgeForRegion } from "../lib/edges.js";
import { randomToken } from "../lib/utils.js";
import { reconcileFailedWebhookEvents, replayWebhookEventById } from "./billing.js";

const invoiceStatusSchema = z.enum(["draft", "open", "paid", "past_due", "void", "uncollectible", "failed", "refunded"]);
const orgRoleSchema = z.enum(["owner", "admin", "member", "billing", "viewer"]);

function csvEscape(value: unknown): string {
  const text = value == null ? "" : String(value);
  if (text.includes('"') || text.includes(",") || text.includes("\n")) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function toCsv(headers: string[], rows: Array<Record<string, unknown>>): string {
  const lines = [headers.map(csvEscape).join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => csvEscape(row[header])).join(","));
  }
  return `${lines.join("\n")}\n`;
}

export const adminRoutes: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", app.auth.requireAdmin);

  app.get("/users", async () => {
    const users = await app.db.query(
      `
      SELECT u.id, u.email, u.created_at, m.role, m.org_id
      FROM users u
      JOIN memberships m ON m.user_id = u.id
      ORDER BY u.created_at DESC
      LIMIT 500
    `,
    );

    return { users: users.rows };
  });

  app.get("/relay-edges", async (request) => {
    const query = z
      .object({
        region: z.string().min(2).max(20).optional(),
        status: z.enum(["online", "degraded", "offline"]).optional(),
        staleSeconds: z.coerce.number().int().positive().max(3600).optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const staleSeconds = query.staleSeconds ?? app.env.RELAY_HEARTBEAT_MAX_AGE_SECONDS;

    const edges = await app.db.query(
      `
      SELECT
        id,
        edge_id,
        region,
        status,
        capacity,
        in_flight,
        rejected_overlimit,
        metadata_json,
        last_heartbeat_at,
        created_at,
        updated_at
      FROM relay_edges
      WHERE ($1::text IS NULL OR region = LOWER($1))
        AND ($2::text IS NULL OR status = $2)
      ORDER BY
        CASE WHEN last_heartbeat_at >= NOW() - make_interval(secs => $3::int) THEN 0 ELSE 1 END,
        region ASC,
        last_heartbeat_at DESC
      LIMIT $4
    `,
      [query.region ?? null, query.status ?? null, staleSeconds, query.limit],
    );

    let recommendedEdge: string | null = null;
    if (query.region) {
      recommendedEdge = await pickRelayEdgeForRegion(app, query.region);
    }

    return {
      edges: edges.rows,
      recommendedEdge,
      staleSeconds,
    };
  });

  app.get("/cert-sources", async (request) => {
    const query = z
      .object({
        source: z.string().min(2).max(80).optional(),
        clusterId: z.string().min(2).max(120).optional(),
        status: z.enum(["accepted", "signature_failed"]).optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const rows = await app.db.query(
      `
      SELECT
        source,
        cluster_id,
        last_event_id,
        last_event_type,
        last_status,
        events_total,
        signature_failures,
        last_seen_at,
        updated_at
      FROM cert_event_source_activity
      WHERE ($1::text IS NULL OR source = LOWER($1))
        AND ($2::text IS NULL OR cluster_id = LOWER($2))
        AND ($3::text IS NULL OR last_status = $3)
      ORDER BY last_seen_at DESC
      LIMIT $4
    `,
      [query.source ?? null, query.clusterId ?? null, query.status ?? null, query.limit],
    );

    return { sources: rows.rows };
  });

  app.get("/security-anomalies", async (request) => {
    const query = z
      .object({
        category: z.enum(["auth_failed", "rate_limited", "token_revoked", "abuse_signal"]).optional(),
        severity: z.enum(["low", "medium", "high"]).optional(),
        ip: z.string().optional(),
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const events = await app.db.query(
      `
      SELECT id, category, severity, ip, user_id, org_id, route, details, created_at
      FROM security_anomaly_events
      WHERE ($1::text IS NULL OR category = $1)
        AND ($2::text IS NULL OR severity = $2)
        AND ($3::text IS NULL OR ip = $3)
        AND ($4::uuid IS NULL OR org_id = $4)
      ORDER BY created_at DESC
      LIMIT $5
    `,
      [query.category ?? null, query.severity ?? null, query.ip ?? null, query.orgId ?? null, query.limit],
    );

    return { anomalies: events.rows };
  });

  app.get("/revoked-tokens", async (request) => {
    const query = z
      .object({
        tokenType: z.enum(["access", "refresh", "agent"]).optional(),
        userId: z.string().uuid().optional(),
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const rows = await app.db.query(
      `
      SELECT id, jti, token_type, user_id, org_id, expires_at, reason, created_at
      FROM auth_revoked_tokens
      WHERE ($1::text IS NULL OR token_type = $1)
        AND ($2::uuid IS NULL OR user_id = $2)
        AND ($3::uuid IS NULL OR org_id = $3)
      ORDER BY created_at DESC
      LIMIT $4
    `,
      [query.tokenType ?? null, query.userId ?? null, query.orgId ?? null, query.limit],
    );

    return { tokens: rows.rows };
  });

  app.post("/revoked-tokens/prune", async (request) => {
    const body = z
      .object({
        before: z.coerce.date().optional(),
      })
      .parse(request.body ?? {});

    const before = body.before ?? new Date();
    const result = await app.db.query(`DELETE FROM auth_revoked_tokens WHERE expires_at IS NOT NULL AND expires_at < $1`, [before]);

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.revoked_tokens.prune",
      entityType: "auth_revoked_tokens",
      entityId: "bulk",
      metadata: { before: before.toISOString(), deleted: result.rowCount ?? 0 },
    });

    return { ok: true, deleted: result.rowCount ?? 0, before: before.toISOString() };
  });

  app.get("/members", async (request) => {
    const members = await app.db.query(
      `
      SELECT
        m.id,
        m.user_id,
        m.org_id,
        m.role,
        m.created_at,
        u.email,
        u.created_at AS user_created_at
      FROM memberships m
      JOIN users u ON u.id = m.user_id
      WHERE m.org_id = $1
      ORDER BY
        CASE m.role
          WHEN 'owner' THEN 0
          WHEN 'admin' THEN 1
          WHEN 'member' THEN 2
          WHEN 'billing' THEN 3
          ELSE 4
        END,
        m.created_at ASC
    `,
      [request.authUser!.orgId],
    );

    return { members: members.rows };
  });

  app.post("/members", async (request, reply) => {
    const body = z
      .object({
        email: z.string().email(),
        role: orgRoleSchema.default("member"),
      })
      .parse(request.body ?? {});

    if (body.role === "owner" && request.authUser!.role !== "owner") {
      return reply.code(403).send({ message: "Only owners can add owner memberships" });
    }

    const user = await app.db.query<{ id: string; email: string }>(`SELECT id, email FROM users WHERE email = $1 LIMIT 1`, [body.email]);
    if (!user.rowCount || !user.rows[0]) {
      return reply.code(404).send({ message: "User not found for email" });
    }

    const membershipId = uuidv4();
    await app.db.query(
      `
      INSERT INTO memberships (id, user_id, org_id, role)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (user_id, org_id) DO UPDATE
      SET role = EXCLUDED.role
    `,
      [membershipId, user.rows[0].id, request.authUser!.orgId, body.role],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.member.upsert",
      entityType: "membership",
      entityId: user.rows[0].id,
      metadata: { role: body.role, email: body.email },
    });

    return { ok: true, userId: user.rows[0].id, role: body.role };
  });

  app.patch("/members/:userId/role", async (request, reply) => {
    const params = z.object({ userId: z.string().uuid() }).parse(request.params);
    const body = z.object({ role: orgRoleSchema }).parse(request.body ?? {});

    const target = await app.db.query<{ role: string }>(
      `SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2 LIMIT 1`,
      [params.userId, request.authUser!.orgId],
    );
    if (!target.rowCount || !target.rows[0]) {
      return reply.code(404).send({ message: "Membership not found" });
    }

    const currentRole = target.rows[0].role;
    if (body.role === "owner" && request.authUser!.role !== "owner") {
      return reply.code(403).send({ message: "Only owners can assign owner role" });
    }
    if (currentRole === "owner" && body.role !== "owner" && request.authUser!.role !== "owner") {
      return reply.code(403).send({ message: "Only owners can demote owner role" });
    }

    if (currentRole === "owner" && body.role !== "owner") {
      const owners = await app.db.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM memberships WHERE org_id = $1 AND role = 'owner'`,
        [request.authUser!.orgId],
      );
      const ownerCount = Number.parseInt(owners.rows[0]?.count ?? "0", 10);
      if (ownerCount <= 1) {
        return reply.code(409).send({ message: "Cannot remove the last owner" });
      }
    }

    await app.db.query(
      `UPDATE memberships SET role = $1 WHERE user_id = $2 AND org_id = $3`,
      [body.role, params.userId, request.authUser!.orgId],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.member.role.update",
      entityType: "membership",
      entityId: params.userId,
      metadata: { fromRole: currentRole, toRole: body.role },
    });

    return { ok: true, userId: params.userId, role: body.role };
  });

  app.delete("/members/:userId", async (request, reply) => {
    const params = z.object({ userId: z.string().uuid() }).parse(request.params);
    if (params.userId === request.authUser!.userId) {
      return reply.code(409).send({ message: "Use another owner/admin to remove this membership" });
    }

    const target = await app.db.query<{ role: string }>(
      `SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2 LIMIT 1`,
      [params.userId, request.authUser!.orgId],
    );
    if (!target.rowCount || !target.rows[0]) {
      return reply.code(404).send({ message: "Membership not found" });
    }

    const targetRole = target.rows[0].role;
    if (targetRole === "owner") {
      if (request.authUser!.role !== "owner") {
        return reply.code(403).send({ message: "Only owners can remove owners" });
      }
      const owners = await app.db.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM memberships WHERE org_id = $1 AND role = 'owner'`,
        [request.authUser!.orgId],
      );
      const ownerCount = Number.parseInt(owners.rows[0]?.count ?? "0", 10);
      if (ownerCount <= 1) {
        return reply.code(409).send({ message: "Cannot remove the last owner" });
      }
    } else if (targetRole === "admin" && request.authUser!.role !== "owner") {
      return reply.code(403).send({ message: "Only owners can remove admin memberships" });
    }

    await app.db.query(`DELETE FROM memberships WHERE user_id = $1 AND org_id = $2`, [params.userId, request.authUser!.orgId]);
    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.member.delete",
      entityType: "membership",
      entityId: params.userId,
      metadata: { role: targetRole },
    });

    return { ok: true };
  });

  app.get("/sso", async (request) => {
    const sso = await app.db.query(
      `
      SELECT id, org_id, provider, enabled, issuer, entrypoint, audience, certificate, metadata_json, created_at, updated_at
      FROM sso_providers
      WHERE org_id = $1
      LIMIT 1
    `,
      [request.authUser!.orgId],
    );

    return { sso: sso.rows[0] ?? null };
  });

  app.put("/sso", async (request) => {
    const body = z
      .object({
        provider: z.enum(["saml", "oidc"]),
        enabled: z.boolean().default(false),
        issuer: z.string().max(500).optional(),
        entrypoint: z.string().max(500).optional(),
        audience: z.string().max(500).optional(),
        certificate: z.string().max(8000).optional(),
        metadata: z.record(z.unknown()).optional(),
      })
      .parse(request.body ?? {});

    await app.db.query(
      `
      INSERT INTO sso_providers (
        id,
        org_id,
        provider,
        enabled,
        issuer,
        entrypoint,
        audience,
        certificate,
        metadata_json,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      ON CONFLICT (org_id) DO UPDATE
      SET
        provider = EXCLUDED.provider,
        enabled = EXCLUDED.enabled,
        issuer = EXCLUDED.issuer,
        entrypoint = EXCLUDED.entrypoint,
        audience = EXCLUDED.audience,
        certificate = EXCLUDED.certificate,
        metadata_json = EXCLUDED.metadata_json,
        updated_at = NOW()
    `,
      [
        uuidv4(),
        request.authUser!.orgId,
        body.provider,
        body.enabled,
        body.issuer ?? null,
        body.entrypoint ?? null,
        body.audience ?? null,
        body.certificate ?? null,
        body.metadata ?? null,
      ],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.sso.upsert",
      entityType: "sso_provider",
      entityId: request.authUser!.orgId,
      metadata: { provider: body.provider, enabled: body.enabled },
    });

    return { ok: true };
  });

  app.post("/secrets/rotate/authtoken", async (request, reply) => {
    const body = z
      .object({
        userId: z.string().uuid().optional(),
        reason: z.string().min(2).max(500).optional(),
      })
      .parse(request.body ?? {});

    const targetUserId = body.userId ?? request.authUser!.userId;
    const member = await app.db.query<{ role: string }>(
      `SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2 LIMIT 1`,
      [targetUserId, request.authUser!.orgId],
    );
    if (!member.rowCount || !member.rows[0]) {
      return reply.code(404).send({ message: "Target user is not in organization" });
    }

    if (targetUserId !== request.authUser!.userId && request.authUser!.role !== "owner") {
      return reply.code(403).send({ message: "Only owner can rotate other users' auth tokens" });
    }

    const rawAuthtoken = randomToken(24);
    const hash = await argon2.hash(rawAuthtoken);

    await app.db.query(`UPDATE users SET authtoken_hash = $1 WHERE id = $2`, [hash, targetUserId]);
    await app.db.query(
      `
      INSERT INTO secret_rotations (id, actor_user_id, target_user_id, org_id, secret_type, reason, metadata)
      VALUES ($1, $2, $3, $4, 'authtoken', $5, $6)
    `,
      [
        uuidv4(),
        request.authUser!.userId,
        targetUserId,
        request.authUser!.orgId,
        body.reason ?? "admin authtoken rotation",
        { targetRole: member.rows[0].role },
      ],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.secret.rotate.authtoken",
      entityType: "user",
      entityId: targetUserId,
      metadata: { reason: body.reason ?? null },
    });

    return { ok: true, userId: targetUserId, authtoken: rawAuthtoken };
  });

  app.get("/tunnels", async () => {
    const tunnels = await app.db.query(
      `
      SELECT id, org_id, name, protocol, subdomain, public_url, status, region, created_at
      FROM tunnels
      ORDER BY created_at DESC
      LIMIT 1000
    `,
    );

    return { tunnels: tunnels.rows };
  });

  app.get("/domains", async () => {
    const domains = await app.db.query(
      `
      SELECT
        cd.id,
        cd.domain,
        cd.verified,
        cd.tls_status,
        cd.tls_mode,
        cd.target_tunnel_id,
        cd.certificate_ref,
        cd.tls_last_checked_at,
        cd.tls_not_after,
        cd.tls_last_error,
        cd.cert_failure_policy,
        cd.cert_failure_count,
        cd.cert_retry_backoff_seconds,
        cd.cert_next_retry_at,
        cd.cert_last_event_type,
        cd.cert_last_event_at,
        cd.cert_renewal_due_at,
        cd.created_at,
        cd.updated_at,
        cd.org_id,
        t.name AS tunnel_name
      FROM custom_domains cd
      LEFT JOIN tunnels t ON t.id = cd.target_tunnel_id
      ORDER BY cd.created_at DESC
      LIMIT 1000
    `,
    );

    return { domains: domains.rows };
  });

  app.get("/billing-webhooks", async (request) => {
    const query = z
      .object({
        provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
        status: z.enum(["pending", "processed", "failed"]).optional(),
        limit: z.coerce.number().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const events = await app.db.query(
      `
      SELECT
        id,
        provider,
        event_id,
        provider_event_type,
        payload_hash,
        status,
        attempts,
        replay_count,
        received_at,
        processed_at,
        last_error
      FROM billing_webhook_events
      WHERE ($1::text IS NULL OR provider = $1)
        AND ($2::text IS NULL OR status = $2)
      ORDER BY received_at DESC
      LIMIT $3
    `,
      [query.provider ?? null, query.status ?? null, query.limit],
    );

    const stats = await app.db.query<{
      total: string;
      pending: string;
      processed: string;
      failed: string;
      stale_pending: string;
    }>(
      `
      SELECT
        COUNT(*)::text AS total,
        COUNT(*) FILTER (WHERE status = 'pending')::text AS pending,
        COUNT(*) FILTER (WHERE status = 'processed')::text AS processed,
        COUNT(*) FILTER (WHERE status = 'failed')::text AS failed,
        COUNT(*) FILTER (WHERE status = 'pending' AND received_at < NOW() - INTERVAL '5 minutes')::text AS stale_pending
      FROM billing_webhook_events
    `,
    );

    return {
      events: events.rows,
      stats: stats.rows[0] ?? { total: "0", pending: "0", processed: "0", failed: "0", stale_pending: "0" },
    };
  });

  app.post("/billing-webhooks/:id/replay", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z.object({ force: z.boolean().optional().default(false) }).parse(request.body ?? {});

    const result = await replayWebhookEventById(app, params.id, body.force);
    if (result.status === "skipped") {
      return reply.code(409).send({ message: result.message ?? "Replay skipped", result });
    }

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.billing_webhook.replay",
      entityType: "billing_webhook_event",
      entityId: params.id,
      metadata: { force: body.force, replayResult: result },
    });

    return { ok: true, result };
  });

  app.post("/billing-webhooks/reconcile", async (request) => {
    const body = z
      .object({
        provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
        limit: z.coerce.number().int().min(1).max(500).default(50),
        force: z.boolean().optional().default(false),
      })
      .parse(request.body ?? {});

    const summary = await reconcileFailedWebhookEvents(app, {
      provider: body.provider,
      limit: body.limit,
      force: body.force,
    });

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.billing_webhook.reconcile",
      entityType: "billing_webhook_event",
      entityId: body.provider ?? "all",
      metadata: { limit: body.limit, force: body.force, summary: { ...summary, results: undefined } },
    });

    return { ok: true, ...summary };
  });

  app.get("/billing-finance-events", async (request) => {
    const query = z
      .object({
        provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
        type: z.enum(["subscription_cancel", "refund", "payment_failed", "payment_recovered"]).optional(),
        status: z.enum(["pending", "processed", "failed", "mocked"]).optional(),
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const events = await app.db.query(
      `
        SELECT
          id,
          org_id,
          provider,
          event_type,
          status,
          external_id,
          external_ref,
          amount_cents,
          currency,
          reason,
          error,
          created_at,
          updated_at
        FROM billing_finance_events
        WHERE ($1::text IS NULL OR provider = $1)
          AND ($2::text IS NULL OR event_type = $2)
          AND ($3::text IS NULL OR status = $3)
          AND ($4::uuid IS NULL OR org_id = $4)
        ORDER BY created_at DESC
        LIMIT $5
      `,
      [query.provider ?? null, query.type ?? null, query.status ?? null, query.orgId ?? null, query.limit],
    );

    const stats = await app.db.query<{
      total: string;
      processed: string;
      failed: string;
      mocked: string;
      refunds: string;
      cancellations: string;
      payment_failed: string;
    }>(
      `
        SELECT
          COUNT(*)::text AS total,
          COUNT(*) FILTER (WHERE status = 'processed')::text AS processed,
          COUNT(*) FILTER (WHERE status = 'failed')::text AS failed,
          COUNT(*) FILTER (WHERE status = 'mocked')::text AS mocked,
          COUNT(*) FILTER (WHERE event_type = 'refund')::text AS refunds,
          COUNT(*) FILTER (WHERE event_type = 'subscription_cancel')::text AS cancellations,
          COUNT(*) FILTER (WHERE event_type = 'payment_failed')::text AS payment_failed
        FROM billing_finance_events
      `,
    );

    return {
      events: events.rows,
      stats:
        stats.rows[0] ??
        {
          total: "0",
          processed: "0",
          failed: "0",
          mocked: "0",
          refunds: "0",
          cancellations: "0",
          payment_failed: "0",
        },
    };
  });

  app.get("/billing-dunning", async (request) => {
    const query = z
      .object({
        provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
        status: z.enum(["open", "recovered", "closed"]).optional(),
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const cases = await app.db.query(
      `
      SELECT
        id,
        org_id,
        provider,
        subscription_ref,
        status,
        stage,
        retry_count,
        next_attempt_at,
        last_attempt_at,
        notification_count,
        last_error,
        latest_event_id,
        latest_event_type,
        created_at,
        updated_at
      FROM billing_dunning_cases
      WHERE ($1::text IS NULL OR provider = $1)
        AND ($2::text IS NULL OR status = $2)
        AND ($3::uuid IS NULL OR org_id = $3)
      ORDER BY updated_at DESC
      LIMIT $4
    `,
      [query.provider ?? null, query.status ?? null, query.orgId ?? null, query.limit],
    );

    const stats = await app.db.query<{
      total: string;
      open: string;
      recovered: string;
      closed: string;
      due_now: string;
    }>(
      `
      SELECT
        COUNT(*)::text AS total,
        COUNT(*) FILTER (WHERE status = 'open')::text AS open,
        COUNT(*) FILTER (WHERE status = 'recovered')::text AS recovered,
        COUNT(*) FILTER (WHERE status = 'closed')::text AS closed,
        COUNT(*) FILTER (WHERE status = 'open' AND (next_attempt_at IS NULL OR next_attempt_at <= NOW()))::text AS due_now
      FROM billing_dunning_cases
      WHERE ($1::text IS NULL OR provider = $1)
        AND ($2::text IS NULL OR status = $2)
        AND ($3::uuid IS NULL OR org_id = $3)
    `,
      [query.provider ?? null, query.status ?? null, query.orgId ?? null],
    );

    return {
      cases: cases.rows,
      stats: stats.rows[0] ?? { total: "0", open: "0", recovered: "0", closed: "0", due_now: "0" },
    };
  });

  app.get("/billing-reports/exports", async (request) => {
    const query = z
      .object({
        status: z.enum(["pending", "running", "completed", "failed"]).optional(),
        dataset: z.enum(["finance_events", "invoices", "dunning"]).optional(),
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
      })
      .parse(request.query ?? {});

    const exports = await app.db.query(
      `
      SELECT
        id,
        org_id,
        dataset,
        format,
        status,
        destination,
        sink_url,
        scheduled_for,
        started_at,
        completed_at,
        row_count,
        content_hash,
        error,
        created_at,
        updated_at
      FROM billing_report_exports
      WHERE ($1::text IS NULL OR status = $1)
        AND ($2::text IS NULL OR dataset = $2)
        AND ($3::uuid IS NULL OR org_id = $3)
      ORDER BY created_at DESC
      LIMIT $4
    `,
      [query.status ?? null, query.dataset ?? null, query.orgId ?? null, query.limit],
    );

    return { exports: exports.rows };
  });

  app.post("/billing-reports/exports", async (request, reply) => {
    const body = z
      .object({
        dataset: z.enum(["finance_events", "invoices", "dunning"]),
        destination: z.enum(["inline", "webhook", "s3", "warehouse"]).optional().default("inline"),
        sinkUrl: z.string().url().optional(),
        orgId: z.string().uuid().optional(),
        scheduledFor: z.coerce.date().optional(),
        payload: z.record(z.unknown()).optional(),
      })
      .parse(request.body ?? {});

    if ((body.destination === "webhook" || body.destination === "warehouse") && !body.sinkUrl) {
      return reply.code(400).send({ message: "sinkUrl is required for webhook and warehouse destinations" });
    }

    const id = uuidv4();
    await app.db.query(
      `
      INSERT INTO billing_report_exports (
        id,
        org_id,
        dataset,
        format,
        status,
        destination,
        sink_url,
        scheduled_for,
        payload_json
      )
      VALUES ($1, $2, $3, 'csv', 'pending', $4, $5, $6, $7)
    `,
      [id, body.orgId ?? null, body.dataset, body.destination, body.sinkUrl ?? null, body.scheduledFor ?? new Date(), body.payload ?? null],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId: request.authUser!.orgId,
      action: "admin.billing_report.export.create",
      entityType: "billing_report_export",
      entityId: id,
      metadata: {
        dataset: body.dataset,
        destination: body.destination,
        orgId: body.orgId ?? null,
      },
    });

    return { ok: true, id };
  });

  app.get("/billing-invoices", async (request) => {
    const query = z
      .object({
        provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
        status: invoiceStatusSchema.optional(),
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(200),
        includeTax: z.coerce.boolean().optional().default(false),
      })
      .parse(request.query ?? {});

    const invoices = await app.db.query(
      `
        SELECT
          id,
          org_id,
          provider,
          provider_invoice_id,
          provider_subscription_id,
          provider_payment_id,
          status,
          currency,
          subtotal_cents,
          tax_cents,
          total_cents,
          amount_due_cents,
          amount_paid_cents,
          invoice_url,
          period_start,
          period_end,
          issued_at,
          due_at,
          paid_at,
          created_at,
          updated_at
        FROM billing_invoices
        WHERE ($1::text IS NULL OR provider = $1)
          AND ($2::text IS NULL OR status = $2)
          AND ($3::uuid IS NULL OR org_id = $3)
        ORDER BY created_at DESC
        LIMIT $4
      `,
      [query.provider ?? null, query.status ?? null, query.orgId ?? null, query.limit],
    );

    const stats = await app.db.query<{
      total: string;
      paid: string;
      failed: string;
      refunded: string;
      total_amount_cents: string;
      total_tax_cents: string;
    }>(
      `
        SELECT
          COUNT(*)::text AS total,
          COUNT(*) FILTER (WHERE status = 'paid')::text AS paid,
          COUNT(*) FILTER (WHERE status = 'failed')::text AS failed,
          COUNT(*) FILTER (WHERE status = 'refunded')::text AS refunded,
          COALESCE(SUM(total_cents), 0)::text AS total_amount_cents,
          COALESCE(SUM(tax_cents), 0)::text AS total_tax_cents
        FROM billing_invoices
        WHERE ($1::text IS NULL OR provider = $1)
          AND ($2::text IS NULL OR status = $2)
          AND ($3::uuid IS NULL OR org_id = $3)
      `,
      [query.provider ?? null, query.status ?? null, query.orgId ?? null],
    );

    const taxRecords = query.includeTax
      ? await app.db.query(
          `
            SELECT
              id,
              invoice_id,
              org_id,
              provider,
              tax_type,
              jurisdiction,
              rate_bps,
              amount_cents,
              currency,
              created_at
            FROM billing_tax_records
            WHERE invoice_id = ANY($1::uuid[])
            ORDER BY created_at DESC
          `,
          [invoices.rows.map((row) => row.id)],
        )
      : { rows: [] };

    return {
      invoices: invoices.rows,
      taxRecords: taxRecords.rows,
      stats:
        stats.rows[0] ??
        {
          total: "0",
          paid: "0",
          failed: "0",
          refunded: "0",
          total_amount_cents: "0",
          total_tax_cents: "0",
        },
    };
  });

  app.get("/billing-invoices/export", async (request, reply) => {
    const query = z
      .object({
        provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
        status: invoiceStatusSchema.optional(),
        orgId: z.string().uuid().optional(),
        dataset: z.enum(["invoices", "tax"]).optional().default("invoices"),
        limit: z.coerce.number().int().min(1).max(5000).default(2000),
      })
      .parse(request.query ?? {});

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    if (query.dataset === "tax") {
      const taxes = await app.db.query(
        `
          SELECT
            t.id,
            t.invoice_id,
            i.org_id,
            t.provider,
            i.provider_invoice_id,
            i.status AS invoice_status,
            t.tax_type,
            t.jurisdiction,
            t.rate_bps,
            t.amount_cents,
            t.currency,
            t.created_at
          FROM billing_tax_records t
          JOIN billing_invoices i ON i.id = t.invoice_id
          WHERE ($1::text IS NULL OR t.provider = $1)
            AND ($2::text IS NULL OR i.status = $2)
            AND ($3::uuid IS NULL OR i.org_id = $3)
          ORDER BY t.created_at DESC
          LIMIT $4
        `,
        [query.provider ?? null, query.status ?? null, query.orgId ?? null, query.limit],
      );

      const csv = toCsv(
        [
          "id",
          "invoice_id",
          "org_id",
          "provider",
          "provider_invoice_id",
          "invoice_status",
          "tax_type",
          "jurisdiction",
          "rate_bps",
          "amount_cents",
          "currency",
          "created_at",
        ],
        taxes.rows as Array<Record<string, unknown>>,
      );

      reply.header("content-type", "text/csv; charset=utf-8");
      reply.header("content-disposition", `attachment; filename="billing-tax-records-${timestamp}.csv"`);
      return reply.send(csv);
    }

    const invoices = await app.db.query(
      `
        SELECT
          id,
          org_id,
          provider,
          provider_invoice_id,
          provider_subscription_id,
          provider_payment_id,
          status,
          currency,
          subtotal_cents,
          tax_cents,
          total_cents,
          amount_due_cents,
          amount_paid_cents,
          invoice_url,
          period_start,
          period_end,
          issued_at,
          due_at,
          paid_at,
          created_at,
          updated_at
        FROM billing_invoices
        WHERE ($1::text IS NULL OR provider = $1)
          AND ($2::text IS NULL OR status = $2)
          AND ($3::uuid IS NULL OR org_id = $3)
        ORDER BY created_at DESC
        LIMIT $4
      `,
      [query.provider ?? null, query.status ?? null, query.orgId ?? null, query.limit],
    );

    const csv = toCsv(
      [
        "id",
        "org_id",
        "provider",
        "provider_invoice_id",
        "provider_subscription_id",
        "provider_payment_id",
        "status",
        "currency",
        "subtotal_cents",
        "tax_cents",
        "total_cents",
        "amount_due_cents",
        "amount_paid_cents",
        "invoice_url",
        "period_start",
        "period_end",
        "issued_at",
        "due_at",
        "paid_at",
        "created_at",
        "updated_at",
      ],
      invoices.rows as Array<Record<string, unknown>>,
    );

    reply.header("content-type", "text/csv; charset=utf-8");
    reply.header("content-disposition", `attachment; filename="billing-invoices-admin-${timestamp}.csv"`);
    return reply.send(csv);
  });

  app.patch("/users/:id/plan", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z.object({ planCode: z.enum(["free", "pro", "team"]) }).parse(request.body);

    const member = await app.db.query<{ org_id: string }>(`SELECT org_id FROM memberships WHERE user_id = $1 LIMIT 1`, [params.id]);

    if (!member.rowCount) {
      return reply.code(404).send({ message: "User membership not found" });
    }

    const orgId = member.rows[0].org_id;
    const plan = await app.db.query(
      `
      SELECT id, max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours
      FROM plans
      WHERE code = $1
      LIMIT 1
    `,
      [body.planCode],
    );

    if (!plan.rowCount) {
      return reply.code(404).send({ message: "Plan not found" });
    }

    const p = plan.rows[0];

    await app.db.query(
      `
      UPDATE entitlements
      SET
        plan_id = $1,
        max_tunnels = $2,
        max_concurrent_conns = $3,
        reserved_domains = $4,
        custom_domains = $5,
        ip_allowlist = $6,
        retention_hours = $7,
        updated_at = NOW()
      WHERE org_id = $8
    `,
      [
        p.id,
        p.max_tunnels,
        p.max_concurrent_conns,
        p.reserved_domains,
        p.custom_domains,
        p.ip_allowlist,
        p.retention_hours,
        orgId,
      ],
    );

    await app.audit.log({
      actorUserId: request.authUser!.userId,
      orgId,
      action: "admin.plan.override",
      entityType: "organization",
      entityId: orgId,
      metadata: body
    });

    return { ok: true };
  });

  app.get("/audit", async (request) => {
    const query = z
      .object({
        limit: z.coerce.number().min(1).max(500).default(100),
        orgId: z.string().uuid().optional(),
      })
      .parse(request.query ?? {});

    const logs = await app.db.query(
      `
      SELECT id, actor_user_id, org_id, action, entity_type, entity_id, metadata, prev_hash, entry_hash, immutable, created_at
      FROM audit_logs
      WHERE ($2::uuid IS NULL OR org_id = $2)
      ORDER BY created_at DESC
      LIMIT $1
    `,
      [query.limit, query.orgId ?? null],
    );

    return { audit: logs.rows };
  });

  app.get("/audit/integrity", async (request) => {
    const query = z
      .object({
        orgId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(5000).default(1000),
      })
      .parse(request.query ?? {});

    const rows = await app.db.query<{
      id: string;
      actor_user_id: string | null;
      org_id: string | null;
      action: string;
      entity_type: string;
      entity_id: string;
      metadata: Record<string, unknown> | null;
      prev_hash: string | null;
      entry_hash: string | null;
      created_at: string;
    }>(
      `
      SELECT
        id,
        actor_user_id,
        org_id,
        action,
        entity_type,
        entity_id,
        metadata,
        prev_hash,
        entry_hash,
        created_at
      FROM audit_logs
      WHERE entry_hash IS NOT NULL
        AND ($1::uuid IS NULL OR org_id = $1)
      ORDER BY created_at ASC, id ASC
      LIMIT $2
    `,
      [query.orgId ?? null, query.limit],
    );

    let previousHash: string | null = null;
    let validCount = 0;
    const mismatches: Array<{ id: string; reason: string }> = [];

    for (const row of rows.rows) {
      const expected = computeAuditEntryHash({
        actorUserId: row.actor_user_id,
        orgId: row.org_id,
        action: row.action,
        entityType: row.entity_type,
        entityId: row.entity_id,
        metadata: row.metadata ?? undefined,
        createdAtIso: new Date(row.created_at).toISOString(),
        prevHash: previousHash,
      });

      if (row.prev_hash !== previousHash) {
        mismatches.push({ id: row.id, reason: "prev_hash mismatch" });
      } else if (row.entry_hash !== expected) {
        mismatches.push({ id: row.id, reason: "entry_hash mismatch" });
      } else {
        validCount += 1;
      }

      previousHash = row.entry_hash;
    }

    return {
      ok: mismatches.length === 0,
      scanned: rows.rows.length,
      valid: validCount,
      mismatches,
      latestHash: previousHash,
    };
  });
};
