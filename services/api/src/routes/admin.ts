import { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { reconcileFailedWebhookEvents, replayWebhookEventById } from "./billing.js";

const invoiceStatusSchema = z.enum(["draft", "open", "paid", "past_due", "void", "uncollectible", "failed", "refunded"]);

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
        cd.created_at,
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
    const limit = z.coerce.number().min(1).max(500).default(100).parse((request.query as any)?.limit ?? 100);

    const logs = await app.db.query(
      `
      SELECT id, actor_user_id, org_id, action, entity_type, entity_id, metadata, created_at
      FROM audit_logs
      ORDER BY created_at DESC
      LIMIT $1
    `,
      [limit],
    );

    return { audit: logs.rows };
  });
};
