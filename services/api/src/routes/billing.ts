import { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import crypto from "node:crypto";
import Stripe from "stripe";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";

const checkoutProviderSchema = z.enum(["stripe", "razorpay", "paypal"]);
type CheckoutProvider = z.infer<typeof checkoutProviderSchema>;

type PlanRow = {
  id: string;
  stripe_price_id: string | null;
  razorpay_plan_id: string | null;
  paypal_plan_id: string | null;
};

type SubscriptionStateInput = {
  orgId: string;
  provider: CheckoutProvider;
  status: string;
  planId: string | null;
  stripeSubscriptionId?: string | null;
  razorpaySubscriptionId?: string | null;
  paypalSubscriptionId?: string | null;
  externalCustomerId?: string | null;
  currentPeriodEnd?: Date | null;
};

type RazorpaySubscriptionPayload = {
  id?: string;
  short_url?: string;
};

type PaypalTokenResponse = {
  access_token?: string;
};

type PaypalCreateSubscriptionResponse = {
  id?: string;
  links?: Array<{ rel?: string; href?: string }>;
};

type PaypalVerifyWebhookResponse = {
  verification_status?: string;
};

type WebhookProvider = CheckoutProvider;
type WebhookStoreStatus = "pending" | "processed" | "failed";

type ReplayResult = {
  id: string;
  provider?: WebhookProvider;
  status: "processed" | "failed" | "skipped";
  message?: string;
};

type FinanceEventType = "subscription_cancel" | "refund" | "payment_failed" | "payment_recovered";
type FinanceEventStatus = "pending" | "processed" | "failed" | "mocked";
type DunningStatus = "open" | "recovered" | "closed";

type SubscriptionRow = {
  org_id: string;
  billing_provider: CheckoutProvider;
  status: string;
  plan_id: string | null;
  plan_code: string | null;
  plan_name: string | null;
  stripe_subscription_id: string | null;
  razorpay_subscription_id: string | null;
  paypal_subscription_id: string | null;
};

type InvoiceStatus = "draft" | "open" | "paid" | "past_due" | "void" | "uncollectible" | "failed" | "refunded";

type BillingInvoiceRow = {
  id: string;
  org_id: string;
  provider: CheckoutProvider;
  provider_invoice_id: string | null;
  provider_subscription_id: string | null;
  provider_payment_id: string | null;
  status: InvoiceStatus;
  currency: string | null;
  subtotal_cents: string | null;
  tax_cents: string | null;
  total_cents: string | null;
  amount_due_cents: string | null;
  amount_paid_cents: string | null;
  invoice_url: string | null;
  period_start: string | null;
  period_end: string | null;
  issued_at: string | null;
  due_at: string | null;
  paid_at: string | null;
  created_at: string;
  updated_at: string;
};

type BillingTaxRow = {
  id: string;
  invoice_id: string;
  org_id: string;
  provider: CheckoutProvider;
  tax_type: string;
  jurisdiction: string | null;
  rate_bps: number | null;
  amount_cents: string;
  currency: string | null;
  created_at: string;
};

type DunningCaseRow = {
  id: string;
  org_id: string;
  provider: CheckoutProvider;
  subscription_ref: string;
  status: DunningStatus;
  stage: number;
  retry_count: number;
};

type DunningChannel = "webhook" | "email" | "slack";

const razorpayWebhookSchema = z
  .object({
    event: z.string(),
    payload: z
      .object({
        subscription: z
          .object({
            entity: z
              .object({
                id: z.string(),
                plan_id: z.string().optional(),
                status: z.string().optional(),
                customer_id: z.string().optional(),
                notes: z.record(z.string()).optional(),
              })
              .passthrough(),
          })
          .optional(),
      })
      .passthrough(),
  })
  .passthrough();

const paypalWebhookSchema = z
  .object({
    id: z.string().optional(),
    event_type: z.string(),
    resource: z
      .object({
        id: z.string().optional(),
        plan_id: z.string().optional(),
        status: z.string().optional(),
        custom_id: z.string().optional(),
        subscriber: z
          .object({
            payer_id: z.string().optional(),
          })
          .optional(),
      })
      .passthrough(),
  })
  .passthrough();

const invoiceStatusSchema = z.enum(["draft", "open", "paid", "past_due", "void", "uncollectible", "failed", "refunded"]);

function headerValue(value: string | string[] | undefined): string | null {
  if (!value) return null;
  if (Array.isArray(value)) return value[0] ?? null;
  return value;
}

function paymentMockUrl(provider: CheckoutProvider, planCode: string): string {
  return `https://billing.mock/checkout?provider=${provider}&plan=${planCode}`;
}

function paypalBaseUrl(environment: "sandbox" | "live"): string {
  return environment === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
}

function createBasicAuth(user: string, password: string): string {
  return `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`;
}

function safeHexCompare(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function getRawBody(request: FastifyRequest): string {
  const raw = request.rawBody;
  if (typeof raw === "string") return raw;
  if (raw && Buffer.isBuffer(raw)) return raw.toString("utf8");
  return JSON.stringify(request.body ?? {});
}

function eventIsFresh(eventTime: Date, maxAgeSeconds: number): boolean {
  const ageMs = Date.now() - eventTime.getTime();
  if (Number.isNaN(ageMs)) return false;
  return ageMs <= maxAgeSeconds * 1000;
}

function unixToDate(value: number | null | undefined): Date | null {
  if (typeof value !== "number") return null;
  if (!Number.isFinite(value)) return null;
  return new Date(value * 1000);
}

function normalizeStripeInvoiceStatus(status: string | null | undefined, eventType?: string): InvoiceStatus {
  if (eventType === "charge.refunded" || eventType === "charge.refund.updated") return "refunded";
  switch ((status ?? "").toLowerCase()) {
    case "draft":
      return "draft";
    case "open":
      return "open";
    case "paid":
      return "paid";
    case "void":
      return "void";
    case "uncollectible":
      return "uncollectible";
    default:
      return eventType === "invoice.payment_failed" ? "failed" : "open";
  }
}

function sumStripeTaxCents(invoice: Stripe.Invoice): number | null {
  if (typeof invoice.tax === "number") return invoice.tax;
  if (Array.isArray(invoice.total_tax_amounts) && invoice.total_tax_amounts.length > 0) {
    const sum = invoice.total_tax_amounts.reduce((acc, item) => acc + (item.amount ?? 0), 0);
    return sum;
  }
  return null;
}

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

async function startWebhookEvent(
  app: FastifyInstance,
  provider: WebhookProvider,
  eventId: string,
  payloadHash: string,
  providerEventType: string | null,
  payloadJson: unknown,
): Promise<{ duplicate: boolean; mismatch: boolean }> {
  const insert = await app.db.query(
    `
      INSERT INTO billing_webhook_events
        (id, provider, event_id, provider_event_type, payload_hash, payload_json, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'pending')
      ON CONFLICT (provider, event_id) DO NOTHING
    `,
    [uuidv4(), provider, eventId, providerEventType, payloadHash, payloadJson ?? null],
  );
  if (insert.rowCount) {
    return { duplicate: false, mismatch: false };
  }

  await app.db.query(
    `
      UPDATE billing_webhook_events
      SET attempts = attempts + 1
      WHERE provider = $1 AND event_id = $2
    `,
    [provider, eventId],
  );

  const existing = await app.db.query<{ payload_hash: string }>(
    `SELECT payload_hash FROM billing_webhook_events WHERE provider = $1 AND event_id = $2 LIMIT 1`,
    [provider, eventId],
  );
  const mismatch = existing.rows[0]?.payload_hash ? existing.rows[0].payload_hash !== payloadHash : false;
  return { duplicate: true, mismatch };
}

async function finishWebhookEvent(
  app: FastifyInstance,
  provider: WebhookProvider,
  eventId: string,
  status: WebhookStoreStatus,
  error?: unknown,
): Promise<void> {
  await app.db.query(
    `
      UPDATE billing_webhook_events
      SET
        status = $3,
        processed_at = CASE WHEN $3 = 'processed' THEN NOW() ELSE processed_at END,
        last_error = CASE WHEN $3 = 'failed' THEN $4 ELSE NULL END
      WHERE provider = $1 AND event_id = $2
    `,
    [provider, eventId, status, error ? String(error) : null],
  );
}

function normalizeEventId(provider: WebhookProvider, maybeEventId: string | null, rawBody: string): string {
  if (maybeEventId && maybeEventId.trim().length) {
    return maybeEventId.trim();
  }
  return `${provider}:${sha256Hex(rawBody)}`;
}

async function findPlanIdByExternalRef(
  app: FastifyInstance,
  provider: CheckoutProvider,
  externalRef: string,
): Promise<string | null> {
  const column =
    provider === "stripe" ? "stripe_price_id" : provider === "razorpay" ? "razorpay_plan_id" : "paypal_plan_id";
  const result = await app.db.query<{ id: string }>(`SELECT id FROM plans WHERE ${column} = $1 LIMIT 1`, [externalRef]);
  return result.rows[0]?.id ?? null;
}

async function findOrgIdBySubscriptionRef(
  app: FastifyInstance,
  provider: CheckoutProvider,
  externalRef: string,
): Promise<string | null> {
  const column =
    provider === "stripe"
      ? "stripe_subscription_id"
      : provider === "razorpay"
        ? "razorpay_subscription_id"
        : "paypal_subscription_id";
  const result = await app.db.query<{ org_id: string }>(`SELECT org_id FROM subscriptions WHERE ${column} = $1 LIMIT 1`, [
    externalRef,
  ]);
  return result.rows[0]?.org_id ?? null;
}

async function upsertSubscriptionState(app: FastifyInstance, input: SubscriptionStateInput): Promise<void> {
  await app.db.query(
    `
      INSERT INTO subscriptions (
        id,
        org_id,
        billing_provider,
        external_customer_id,
        stripe_subscription_id,
        razorpay_subscription_id,
        paypal_subscription_id,
        status,
        plan_id,
        current_period_end
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (org_id) DO UPDATE
      SET
        billing_provider = EXCLUDED.billing_provider,
        external_customer_id = COALESCE(EXCLUDED.external_customer_id, subscriptions.external_customer_id),
        stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, subscriptions.stripe_subscription_id),
        razorpay_subscription_id = COALESCE(EXCLUDED.razorpay_subscription_id, subscriptions.razorpay_subscription_id),
        paypal_subscription_id = COALESCE(EXCLUDED.paypal_subscription_id, subscriptions.paypal_subscription_id),
        status = EXCLUDED.status,
        plan_id = COALESCE(EXCLUDED.plan_id, subscriptions.plan_id),
        current_period_end = COALESCE(EXCLUDED.current_period_end, subscriptions.current_period_end),
        updated_at = NOW()
    `,
    [
      uuidv4(),
      input.orgId,
      input.provider,
      input.externalCustomerId ?? null,
      input.stripeSubscriptionId ?? null,
      input.razorpaySubscriptionId ?? null,
      input.paypalSubscriptionId ?? null,
      input.status,
      input.planId,
      input.currentPeriodEnd ?? null,
    ],
  );
}

async function applyEntitlementsFromPlan(
  app: FastifyInstance,
  orgId: string,
  planId: string,
): Promise<void> {
  await app.db.query(
    `
      UPDATE entitlements e
      SET
        plan_id = p.id,
        max_tunnels = p.max_tunnels,
        max_concurrent_conns = p.max_concurrent_conns,
        reserved_domains = p.reserved_domains,
        custom_domains = p.custom_domains,
        ip_allowlist = p.ip_allowlist,
        retention_hours = p.retention_hours,
        updated_at = NOW()
      FROM plans p
      WHERE e.org_id = $1 AND p.id = $2
    `,
    [orgId, planId],
  );
}

async function setFreePlan(app: FastifyInstance, orgId: string, provider: CheckoutProvider, status: string): Promise<void> {
  const freePlan = await app.db.query<{ id: string }>(`SELECT id FROM plans WHERE code = 'free' LIMIT 1`);
  const freePlanId = freePlan.rows[0]?.id ?? null;
  await upsertSubscriptionState(app, {
    orgId,
    provider,
    status,
    planId: freePlanId,
  });
  if (freePlanId) {
    await applyEntitlementsFromPlan(app, orgId, freePlanId);
  }
}

function subscriptionIdForProvider(input: SubscriptionRow): string | null {
  if (input.billing_provider === "stripe") return input.stripe_subscription_id;
  if (input.billing_provider === "razorpay") return input.razorpay_subscription_id;
  return input.paypal_subscription_id;
}

async function getOrgSubscription(app: FastifyInstance, orgId: string): Promise<SubscriptionRow | null> {
  const result = await app.db.query<SubscriptionRow>(
    `
      SELECT
        s.org_id,
        s.billing_provider,
        s.status,
        s.plan_id,
        p.code AS plan_code,
        p.name AS plan_name,
        s.stripe_subscription_id,
        s.razorpay_subscription_id,
        s.paypal_subscription_id
      FROM subscriptions s
      LEFT JOIN plans p ON p.id = s.plan_id
      WHERE s.org_id = $1
      LIMIT 1
    `,
    [orgId],
  );
  return result.rows[0] ?? null;
}

async function recordFinanceEvent(
  app: FastifyInstance,
  input: {
    orgId: string;
    provider: CheckoutProvider;
    eventType: FinanceEventType;
    status: FinanceEventStatus;
    externalId?: string | null;
    externalRef?: string | null;
    amountCents?: number | null;
    currency?: string | null;
    reason?: string | null;
    payload?: unknown;
    result?: unknown;
    error?: string | null;
  },
): Promise<string> {
  const id = uuidv4();
  await app.db.query(
    `
      INSERT INTO billing_finance_events (
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
        payload_json,
        result_json,
        error
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    `,
    [
      id,
      input.orgId,
      input.provider,
      input.eventType,
      input.status,
      input.externalId ?? null,
      input.externalRef ?? null,
      input.amountCents ?? null,
      input.currency ?? null,
      input.reason ?? null,
      input.payload ?? null,
      input.result ?? null,
      input.error ?? null,
    ],
  );
  return id;
}

async function upsertInvoiceRecord(
  app: FastifyInstance,
  input: {
    orgId: string;
    provider: CheckoutProvider;
    providerInvoiceId?: string | null;
    providerSubscriptionId?: string | null;
    providerPaymentId?: string | null;
    status: InvoiceStatus;
    currency?: string | null;
    subtotalCents?: number | null;
    taxCents?: number | null;
    totalCents?: number | null;
    amountDueCents?: number | null;
    amountPaidCents?: number | null;
    invoiceUrl?: string | null;
    periodStart?: Date | null;
    periodEnd?: Date | null;
    issuedAt?: Date | null;
    dueAt?: Date | null;
    paidAt?: Date | null;
    payload?: unknown;
  },
): Promise<string> {
  if (input.providerInvoiceId) {
    const upsert = await app.db.query<{ id: string }>(
      `
        INSERT INTO billing_invoices (
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
          payload_json
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, UPPER($8), $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
        ON CONFLICT (provider, provider_invoice_id) DO UPDATE
        SET
          org_id = EXCLUDED.org_id,
          provider_subscription_id = COALESCE(EXCLUDED.provider_subscription_id, billing_invoices.provider_subscription_id),
          provider_payment_id = COALESCE(EXCLUDED.provider_payment_id, billing_invoices.provider_payment_id),
          status = EXCLUDED.status,
          currency = COALESCE(EXCLUDED.currency, billing_invoices.currency),
          subtotal_cents = COALESCE(EXCLUDED.subtotal_cents, billing_invoices.subtotal_cents),
          tax_cents = COALESCE(EXCLUDED.tax_cents, billing_invoices.tax_cents),
          total_cents = COALESCE(EXCLUDED.total_cents, billing_invoices.total_cents),
          amount_due_cents = COALESCE(EXCLUDED.amount_due_cents, billing_invoices.amount_due_cents),
          amount_paid_cents = COALESCE(EXCLUDED.amount_paid_cents, billing_invoices.amount_paid_cents),
          invoice_url = COALESCE(EXCLUDED.invoice_url, billing_invoices.invoice_url),
          period_start = COALESCE(EXCLUDED.period_start, billing_invoices.period_start),
          period_end = COALESCE(EXCLUDED.period_end, billing_invoices.period_end),
          issued_at = COALESCE(EXCLUDED.issued_at, billing_invoices.issued_at),
          due_at = COALESCE(EXCLUDED.due_at, billing_invoices.due_at),
          paid_at = COALESCE(EXCLUDED.paid_at, billing_invoices.paid_at),
          payload_json = COALESCE(EXCLUDED.payload_json, billing_invoices.payload_json),
          updated_at = NOW()
        RETURNING id
      `,
      [
        uuidv4(),
        input.orgId,
        input.provider,
        input.providerInvoiceId,
        input.providerSubscriptionId ?? null,
        input.providerPaymentId ?? null,
        input.status,
        input.currency ?? null,
        input.subtotalCents ?? null,
        input.taxCents ?? null,
        input.totalCents ?? null,
        input.amountDueCents ?? null,
        input.amountPaidCents ?? null,
        input.invoiceUrl ?? null,
        input.periodStart ?? null,
        input.periodEnd ?? null,
        input.issuedAt ?? null,
        input.dueAt ?? null,
        input.paidAt ?? null,
        input.payload ?? null,
      ],
    );
    return upsert.rows[0].id;
  }

  const id = uuidv4();
  await app.db.query(
    `
      INSERT INTO billing_invoices (
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
        payload_json
      )
      VALUES ($1, $2, $3, NULL, $4, $5, $6, UPPER($7), $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
    `,
    [
      id,
      input.orgId,
      input.provider,
      input.providerSubscriptionId ?? null,
      input.providerPaymentId ?? null,
      input.status,
      input.currency ?? null,
      input.subtotalCents ?? null,
      input.taxCents ?? null,
      input.totalCents ?? null,
      input.amountDueCents ?? null,
      input.amountPaidCents ?? null,
      input.invoiceUrl ?? null,
      input.periodStart ?? null,
      input.periodEnd ?? null,
      input.issuedAt ?? null,
      input.dueAt ?? null,
      input.paidAt ?? null,
      input.payload ?? null,
    ],
  );
  return id;
}

async function upsertTaxRecord(
  app: FastifyInstance,
  input: {
    invoiceId: string;
    orgId: string;
    provider: CheckoutProvider;
    taxType: string;
    jurisdiction: string;
    rateBps?: number | null;
    amountCents: number;
    currency?: string | null;
    payload?: unknown;
  },
): Promise<void> {
  await app.db.query(
    `
      INSERT INTO billing_tax_records (
        id,
        invoice_id,
        org_id,
        provider,
        tax_type,
        jurisdiction,
        rate_bps,
        amount_cents,
        currency,
        payload_json
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, UPPER($9), $10)
      ON CONFLICT (invoice_id, tax_type, jurisdiction) DO UPDATE
      SET
        rate_bps = EXCLUDED.rate_bps,
        amount_cents = EXCLUDED.amount_cents,
        currency = EXCLUDED.currency,
        payload_json = COALESCE(EXCLUDED.payload_json, billing_tax_records.payload_json)
    `,
    [
      uuidv4(),
      input.invoiceId,
      input.orgId,
      input.provider,
      input.taxType,
      input.jurisdiction,
      input.rateBps ?? null,
      input.amountCents,
      input.currency ?? null,
      input.payload ?? null,
    ],
  );
}

async function upsertStripeInvoiceFromEvent(
  app: FastifyInstance,
  orgId: string,
  eventType: string,
  invoice: Stripe.Invoice,
): Promise<void> {
  const subscriptionRef =
    typeof invoice.subscription === "string"
      ? invoice.subscription
      : invoice.subscription && "id" in invoice.subscription
        ? String(invoice.subscription.id)
        : null;

  const paymentRef =
    typeof invoice.payment_intent === "string"
      ? invoice.payment_intent
      : typeof invoice.charge === "string"
        ? invoice.charge
        : null;

  const periodStart =
    unixToDate((invoice as any).period_start as number | undefined) ??
    unixToDate(invoice.lines?.data?.[0]?.period?.start ?? null);
  const periodEnd =
    unixToDate((invoice as any).period_end as number | undefined) ??
    unixToDate(invoice.lines?.data?.[0]?.period?.end ?? null);

  const taxCents = sumStripeTaxCents(invoice);
  const invoiceId = await upsertInvoiceRecord(app, {
    orgId,
    provider: "stripe",
    providerInvoiceId: invoice.id,
    providerSubscriptionId: subscriptionRef,
    providerPaymentId: paymentRef,
    status: normalizeStripeInvoiceStatus(invoice.status, eventType),
    currency: invoice.currency?.toUpperCase() ?? null,
    subtotalCents: typeof invoice.subtotal === "number" ? invoice.subtotal : null,
    taxCents,
    totalCents: typeof invoice.total === "number" ? invoice.total : null,
    amountDueCents: typeof invoice.amount_due === "number" ? invoice.amount_due : null,
    amountPaidCents: typeof invoice.amount_paid === "number" ? invoice.amount_paid : null,
    invoiceUrl: invoice.hosted_invoice_url ?? invoice.invoice_pdf ?? null,
    periodStart,
    periodEnd,
    issuedAt: unixToDate(invoice.created),
    dueAt: unixToDate(invoice.due_date),
    paidAt: unixToDate(invoice.status_transitions?.paid_at ?? null),
    payload: invoice,
  });

  if (taxCents && taxCents > 0) {
    await upsertTaxRecord(app, {
      invoiceId,
      orgId,
      provider: "stripe",
      taxType: "provider_total_tax",
      jurisdiction: "unknown",
      amountCents: taxCents,
      currency: invoice.currency?.toUpperCase() ?? null,
      payload: {
        total_tax_amounts: invoice.total_tax_amounts ?? [],
      },
    });
  }
}

async function listOrgInvoices(
  app: FastifyInstance,
  orgId: string,
  options: { status?: InvoiceStatus; limit: number },
): Promise<BillingInvoiceRow[]> {
  const result = await app.db.query<BillingInvoiceRow>(
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
      WHERE org_id = $1
        AND ($2::text IS NULL OR status = $2)
      ORDER BY created_at DESC
      LIMIT $3
    `,
    [orgId, options.status ?? null, options.limit],
  );
  return result.rows;
}

async function listTaxRecordsForInvoices(app: FastifyInstance, invoiceIds: string[]): Promise<BillingTaxRow[]> {
  if (!invoiceIds.length) return [];
  const taxes = await app.db.query<BillingTaxRow>(
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
    [invoiceIds],
  );
  return taxes.rows;
}

function dunningDelaySecondsForStage(provider: CheckoutProvider, stage: number): number {
  const profiles: Record<CheckoutProvider, number[]> = {
    stripe: [15 * 60, 60 * 60, 6 * 60 * 60, 24 * 60 * 60, 48 * 60 * 60],
    razorpay: [30 * 60, 2 * 60 * 60, 8 * 60 * 60, 24 * 60 * 60, 48 * 60 * 60],
    paypal: [30 * 60, 4 * 60 * 60, 12 * 60 * 60, 24 * 60 * 60, 72 * 60 * 60],
  };
  const schedule = profiles[provider];
  if (!schedule || schedule.length === 0) return 24 * 60 * 60;
  const index = Math.max(0, Math.min(stage - 1, schedule.length - 1));
  return schedule[index] ?? schedule[schedule.length - 1] ?? 24 * 60 * 60;
}

function defaultDunningChannels(provider: CheckoutProvider): DunningChannel[] {
  if (provider === "razorpay") return ["webhook", "email"];
  if (provider === "paypal") return ["email", "webhook"];
  return ["webhook", "email"];
}

async function upsertDunningOpenCase(
  app: FastifyInstance,
  input: {
    orgId: string;
    provider: CheckoutProvider;
    subscriptionRef: string;
    eventId?: string | null;
    eventType: string;
    payload?: unknown;
  },
): Promise<void> {
  if (!input.subscriptionRef) return;

  const existing = await app.db.query<DunningCaseRow>(
    `
      SELECT id, org_id, provider, subscription_ref, status, stage, retry_count
      FROM billing_dunning_cases
      WHERE org_id = $1 AND provider = $2 AND subscription_ref = $3
      LIMIT 1
    `,
    [input.orgId, input.provider, input.subscriptionRef],
  );

  const nextStage = Math.min((existing.rows[0]?.status === "open" ? existing.rows[0].stage + 1 : 1), 10);
  const retryCount = existing.rows[0] ? existing.rows[0].retry_count + 1 : 0;
  const delaySeconds = dunningDelaySecondsForStage(input.provider, nextStage);
  const nextAttemptAt = new Date(Date.now() + delaySeconds * 1000);
  const channels = defaultDunningChannels(input.provider);

  await app.db.query(
    `
      INSERT INTO billing_dunning_cases (
        id,
        org_id,
        provider,
        subscription_ref,
        status,
        stage,
        retry_count,
        next_attempt_at,
        last_attempt_at,
        notification_channels,
        latest_event_id,
        latest_event_type,
        payload_json,
        updated_at
      )
      VALUES ($1, $2, $3, $4, 'open', $5, $6, $7, NOW(), $8, $9, $10, $11, NOW())
      ON CONFLICT (org_id, provider, subscription_ref) DO UPDATE
      SET
        status = 'open',
        stage = EXCLUDED.stage,
        retry_count = EXCLUDED.retry_count,
        next_attempt_at = EXCLUDED.next_attempt_at,
        last_attempt_at = NOW(),
        notification_channels = EXCLUDED.notification_channels,
        latest_event_id = COALESCE(EXCLUDED.latest_event_id, billing_dunning_cases.latest_event_id),
        latest_event_type = EXCLUDED.latest_event_type,
        payload_json = COALESCE(EXCLUDED.payload_json, billing_dunning_cases.payload_json),
        updated_at = NOW()
    `,
    [
      uuidv4(),
      input.orgId,
      input.provider,
      input.subscriptionRef,
      nextStage,
      retryCount,
      nextAttemptAt,
      channels,
      input.eventId ?? null,
      input.eventType,
      input.payload ?? null,
    ],
  );
}

async function upsertDunningRecoveredCase(
  app: FastifyInstance,
  input: {
    orgId: string;
    provider: CheckoutProvider;
    subscriptionRef: string;
    eventId?: string | null;
    eventType: string;
    payload?: unknown;
  },
): Promise<void> {
  if (!input.subscriptionRef) return;

  await app.db.query(
    `
      INSERT INTO billing_dunning_cases (
        id,
        org_id,
        provider,
        subscription_ref,
        status,
        stage,
        retry_count,
        next_attempt_at,
        latest_event_id,
        latest_event_type,
        payload_json,
        updated_at
      )
      VALUES ($1, $2, $3, $4, 'recovered', 1, 0, NULL, $5, $6, $7, NOW())
      ON CONFLICT (org_id, provider, subscription_ref) DO UPDATE
      SET
        status = 'recovered',
        next_attempt_at = NULL,
        latest_event_id = COALESCE(EXCLUDED.latest_event_id, billing_dunning_cases.latest_event_id),
        latest_event_type = EXCLUDED.latest_event_type,
        payload_json = COALESCE(EXCLUDED.payload_json, billing_dunning_cases.payload_json),
        last_error = NULL,
        updated_at = NOW()
    `,
    [
      uuidv4(),
      input.orgId,
      input.provider,
      input.subscriptionRef,
      input.eventId ?? null,
      input.eventType,
      input.payload ?? null,
    ],
  );
}

async function paypalAccessToken(app: FastifyInstance): Promise<string> {
  if (!app.env.PAYPAL_CLIENT_ID || !app.env.PAYPAL_CLIENT_SECRET) {
    throw new Error("PayPal credentials are missing");
  }

  const response = await fetch(`${paypalBaseUrl(app.env.PAYPAL_ENVIRONMENT)}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      authorization: createBasicAuth(app.env.PAYPAL_CLIENT_ID, app.env.PAYPAL_CLIENT_SECRET),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  if (!response.ok) {
    throw new Error(`PayPal auth failed with status ${response.status}`);
  }

  const payload = (await response.json()) as PaypalTokenResponse;
  if (!payload.access_token) {
    throw new Error("PayPal auth response missing access token");
  }
  return payload.access_token;
}

async function verifyPaypalWebhook(
  app: FastifyInstance,
  body: unknown,
  headers: Record<string, string | string[] | undefined>,
): Promise<boolean> {
  if (!app.env.PAYPAL_WEBHOOK_ID || !app.env.PAYPAL_CLIENT_ID || !app.env.PAYPAL_CLIENT_SECRET) {
    return true;
  }

  const transmissionId = headerValue(headers["paypal-transmission-id"]);
  const transmissionTime = headerValue(headers["paypal-transmission-time"]);
  const transmissionSig = headerValue(headers["paypal-transmission-sig"]);
  const certUrl = headerValue(headers["paypal-cert-url"]);
  const authAlgo = headerValue(headers["paypal-auth-algo"]);

  if (!transmissionId || !transmissionTime || !transmissionSig || !certUrl || !authAlgo) {
    return false;
  }

  const token = await paypalAccessToken(app);
  const response = await fetch(`${paypalBaseUrl(app.env.PAYPAL_ENVIRONMENT)}/v1/notifications/verify-webhook-signature`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      transmission_id: transmissionId,
      transmission_time: transmissionTime,
      cert_url: certUrl,
      auth_algo: authAlgo,
      transmission_sig: transmissionSig,
      webhook_id: app.env.PAYPAL_WEBHOOK_ID,
      webhook_event: body,
    }),
  });

  if (!response.ok) {
    return false;
  }

  const payload = (await response.json()) as PaypalVerifyWebhookResponse;
  return payload.verification_status === "SUCCESS";
}

function verifyRunbookSignature(
  app: FastifyInstance,
  request: FastifyRequest,
): { ok: boolean; message?: string } {
  if (!app.env.BILLING_RUNBOOK_SIGNING_SECRET) {
    return { ok: false, message: "Runbook signing secret is not configured" };
  }

  const signature = headerValue(request.headers["x-fdt-runbook-signature"]);
  const timestampRaw = headerValue(request.headers["x-fdt-runbook-timestamp"]);
  if (!signature || !timestampRaw) {
    return { ok: false, message: "Missing runbook signature headers" };
  }

  const timestamp = Number.parseInt(timestampRaw, 10);
  if (!Number.isFinite(timestamp)) {
    return { ok: false, message: "Invalid runbook timestamp" };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestamp) > app.env.BILLING_RUNBOOK_MAX_AGE_SECONDS) {
    return { ok: false, message: "Runbook signature expired" };
  }

  const rawBody = getRawBody(request);
  const expected = crypto
    .createHmac("sha256", app.env.BILLING_RUNBOOK_SIGNING_SECRET)
    .update(`${timestampRaw}.${rawBody}`)
    .digest("hex");

  if (!safeHexCompare(expected, signature)) {
    return { ok: false, message: "Invalid runbook signature" };
  }

  return { ok: true };
}

function verifySettlementSignature(
  app: FastifyInstance,
  request: FastifyRequest,
): { ok: boolean; message?: string } {
  if (!app.env.BILLING_SETTLEMENT_SIGNING_SECRET) {
    return { ok: false, message: "Settlement signing secret is not configured" };
  }

  const signature = headerValue(request.headers["x-fdt-settlement-signature"]);
  const timestampRaw = headerValue(request.headers["x-fdt-settlement-timestamp"]);
  if (!signature || !timestampRaw) {
    return { ok: false, message: "Missing settlement signature headers" };
  }

  const timestamp = Number.parseInt(timestampRaw, 10);
  if (!Number.isFinite(timestamp)) {
    return { ok: false, message: "Invalid settlement timestamp" };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestamp) > app.env.BILLING_SETTLEMENT_MAX_AGE_SECONDS) {
    return { ok: false, message: "Settlement signature expired" };
  }

  const rawBody = getRawBody(request);
  const expected = crypto
    .createHmac("sha256", app.env.BILLING_SETTLEMENT_SIGNING_SECRET)
    .update(`${timestampRaw}.${rawBody}`)
    .digest("hex");

  if (!safeHexCompare(expected, signature)) {
    return { ok: false, message: "Invalid settlement signature" };
  }

  return { ok: true };
}

async function processStripeEvent(app: FastifyInstance, event: Stripe.Event): Promise<void> {
  if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.created") {
    const sub = event.data.object as Stripe.Subscription;
    let orgId = sub.metadata.orgId;
    const priceId = sub.items.data[0]?.price.id;
    if (!orgId) {
      orgId = (await findOrgIdBySubscriptionRef(app, "stripe", sub.id)) ?? "";
    }
    if (orgId && priceId) {
      const planId = await findPlanIdByExternalRef(app, "stripe", priceId);
      if (planId) {
        await upsertSubscriptionState(app, {
          orgId,
          provider: "stripe",
          status: sub.status,
          planId,
          stripeSubscriptionId: sub.id,
          externalCustomerId: sub.customer ? String(sub.customer) : null,
        });
        await applyEntitlementsFromPlan(app, orgId, planId);
      }
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const sub = event.data.object as Stripe.Subscription;
    let orgId = sub.metadata.orgId;
    if (!orgId) {
      orgId = (await findOrgIdBySubscriptionRef(app, "stripe", sub.id)) ?? "";
    }
    if (orgId) {
      await setFreePlan(app, orgId, "stripe", sub.status || "canceled");
    }
  }

  if (event.type === "invoice.payment_failed" || event.type === "invoice.paid" || event.type === "invoice.finalized") {
    const invoice = event.data.object as Stripe.Invoice;
    const subscriptionRef =
      typeof invoice.subscription === "string"
        ? invoice.subscription
        : invoice.subscription && "id" in invoice.subscription
          ? String(invoice.subscription.id)
          : null;

    let orgId = invoice.metadata?.orgId ?? "";
    if (!orgId && subscriptionRef) {
      orgId = (await findOrgIdBySubscriptionRef(app, "stripe", subscriptionRef)) ?? "";
    }
    if (orgId) {
      await upsertStripeInvoiceFromEvent(app, orgId, event.type, invoice);

      if (event.type === "invoice.finalized") {
        return;
      }

      if (subscriptionRef) {
        if (event.type === "invoice.payment_failed") {
          await upsertDunningOpenCase(app, {
            orgId,
            provider: "stripe",
            subscriptionRef,
            eventId: event.id,
            eventType: event.type,
            payload: event.data.object,
          });
        } else if (event.type === "invoice.paid") {
          await upsertDunningRecoveredCase(app, {
            orgId,
            provider: "stripe",
            subscriptionRef,
            eventId: event.id,
            eventType: event.type,
            payload: event.data.object,
          });
        }
      }

      await recordFinanceEvent(app, {
        orgId,
        provider: "stripe",
        eventType: event.type === "invoice.payment_failed" ? "payment_failed" : "payment_recovered",
        status: "processed",
        externalId: event.id,
        externalRef: subscriptionRef,
        amountCents: typeof invoice.amount_paid === "number" ? invoice.amount_paid : null,
        currency: invoice.currency?.toUpperCase() ?? null,
        payload: event.data.object,
        result: { eventType: event.type },
      });
    }
  }
}

async function processRazorpayWebhookPayload(
  app: FastifyInstance,
  payload: z.infer<typeof razorpayWebhookSchema>,
): Promise<void> {
  const entity = payload.payload.subscription?.entity;
  if (!entity?.id) {
    return;
  }

  let orgId = entity.notes?.orgId;
  if (!orgId) {
    orgId = (await findOrgIdBySubscriptionRef(app, "razorpay", entity.id)) ?? "";
  }
  if (!orgId) {
    return;
  }

  const status = entity.status ?? payload.event;
  const canceled =
    ["subscription.cancelled", "subscription.halted"].includes(payload.event) ||
    ["cancelled", "halted"].includes(status);
  if (canceled) {
    await setFreePlan(app, orgId, "razorpay", status);
    return;
  }

  const planId = entity.plan_id ? await findPlanIdByExternalRef(app, "razorpay", entity.plan_id) : null;
  await upsertSubscriptionState(app, {
    orgId,
    provider: "razorpay",
    status,
    planId,
    razorpaySubscriptionId: entity.id,
    externalCustomerId: entity.customer_id ?? null,
  });
  if (planId && ["subscription.activated", "subscription.charged", "subscription.authenticated"].includes(payload.event)) {
    await applyEntitlementsFromPlan(app, orgId, planId);
  }

  if (["subscription.halted", "payment.failed"].includes(payload.event)) {
    await upsertDunningOpenCase(app, {
      orgId,
      provider: "razorpay",
      subscriptionRef: entity.id,
      eventType: payload.event,
      payload,
    });
    await recordFinanceEvent(app, {
      orgId,
      provider: "razorpay",
      eventType: "payment_failed",
      status: "processed",
      externalRef: entity.id,
      payload,
      result: { eventType: payload.event },
    });
  } else if (["subscription.charged", "payment.captured"].includes(payload.event)) {
    await upsertDunningRecoveredCase(app, {
      orgId,
      provider: "razorpay",
      subscriptionRef: entity.id,
      eventType: payload.event,
      payload,
    });
    await recordFinanceEvent(app, {
      orgId,
      provider: "razorpay",
      eventType: "payment_recovered",
      status: "processed",
      externalRef: entity.id,
      payload,
      result: { eventType: payload.event },
    });
  }
}

async function processPaypalWebhookPayload(
  app: FastifyInstance,
  payload: z.infer<typeof paypalWebhookSchema>,
): Promise<void> {
  if (!payload.resource.id) {
    return;
  }

  const subscriptionId = payload.resource.id;
  const customId = payload.resource.custom_id ?? "";
  let orgId = customId.split(":")[0];
  if (!orgId) {
    orgId = (await findOrgIdBySubscriptionRef(app, "paypal", subscriptionId)) ?? "";
  }
  if (!orgId) {
    return;
  }

  const status = payload.resource.status ?? payload.event_type;
  const canceledEvents = ["BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.SUSPENDED", "BILLING.SUBSCRIPTION.EXPIRED"];
  if (canceledEvents.includes(payload.event_type)) {
    await setFreePlan(app, orgId, "paypal", status);
    return;
  }

  const planId = payload.resource.plan_id ? await findPlanIdByExternalRef(app, "paypal", payload.resource.plan_id) : null;
  await upsertSubscriptionState(app, {
    orgId,
    provider: "paypal",
    status,
    planId,
    paypalSubscriptionId: subscriptionId,
    externalCustomerId: payload.resource.subscriber?.payer_id ?? null,
  });

  const activeEvents = ["BILLING.SUBSCRIPTION.ACTIVATED", "BILLING.SUBSCRIPTION.UPDATED"];
  if (planId && activeEvents.includes(payload.event_type)) {
    await applyEntitlementsFromPlan(app, orgId, planId);
  }

  if (payload.event_type === "BILLING.SUBSCRIPTION.PAYMENT.FAILED") {
    await upsertDunningOpenCase(app, {
      orgId,
      provider: "paypal",
      subscriptionRef: subscriptionId,
      eventId: payload.id ?? null,
      eventType: payload.event_type,
      payload,
    });
    await recordFinanceEvent(app, {
      orgId,
      provider: "paypal",
      eventType: "payment_failed",
      status: "processed",
      externalId: payload.id ?? null,
      externalRef: subscriptionId,
      payload,
      result: { eventType: payload.event_type },
    });
  } else if (payload.event_type === "BILLING.SUBSCRIPTION.PAYMENT.COMPLETED") {
    await upsertDunningRecoveredCase(app, {
      orgId,
      provider: "paypal",
      subscriptionRef: subscriptionId,
      eventId: payload.id ?? null,
      eventType: payload.event_type,
      payload,
    });
    await recordFinanceEvent(app, {
      orgId,
      provider: "paypal",
      eventType: "payment_recovered",
      status: "processed",
      externalId: payload.id ?? null,
      externalRef: subscriptionId,
      payload,
      result: { eventType: payload.event_type },
    });
  }
}

export async function replayWebhookEventById(
  app: FastifyInstance,
  id: string,
  force: boolean,
): Promise<ReplayResult> {
  const row = await app.db.query<{
    id: string;
    provider: WebhookProvider;
    status: "pending" | "processed" | "failed";
    payload_json: unknown;
  }>(
    `
      SELECT id, provider, status, payload_json
      FROM billing_webhook_events
      WHERE id = $1
      LIMIT 1
    `,
    [id],
  );

  const event = row.rows[0];
  if (!event) {
    return { id, status: "skipped", message: "event not found" };
  }

  if (event.status !== "failed" && !force) {
    return { id: event.id, provider: event.provider, status: "skipped", message: "event is not failed (use force=true)" };
  }
  if (!event.payload_json || typeof event.payload_json !== "object") {
    await app.db.query(
      `
        UPDATE billing_webhook_events
        SET
          status = 'failed',
          attempts = attempts + 1,
          replay_count = replay_count + 1,
          last_error = 'payload_json missing for replay'
        WHERE id = $1
      `,
      [event.id],
    );
    return { id: event.id, provider: event.provider, status: "failed", message: "payload_json missing for replay" };
  }

  try {
    if (event.provider === "stripe") {
      const stripeEvent = event.payload_json as Stripe.Event;
      await processStripeEvent(app, stripeEvent);
    } else if (event.provider === "razorpay") {
      const parsed = razorpayWebhookSchema.safeParse(event.payload_json);
      if (!parsed.success) {
        throw new Error(`invalid razorpay payload: ${parsed.error.message}`);
      }
      await processRazorpayWebhookPayload(app, parsed.data);
    } else {
      const parsed = paypalWebhookSchema.safeParse(event.payload_json);
      if (!parsed.success) {
        throw new Error(`invalid paypal payload: ${parsed.error.message}`);
      }
      await processPaypalWebhookPayload(app, parsed.data);
    }

    await app.db.query(
      `
        UPDATE billing_webhook_events
        SET
          status = 'processed',
          processed_at = NOW(),
          attempts = attempts + 1,
          replay_count = replay_count + 1,
          last_error = NULL
        WHERE id = $1
      `,
      [event.id],
    );

    return { id: event.id, provider: event.provider, status: "processed" };
  } catch (error) {
    await app.db.query(
      `
        UPDATE billing_webhook_events
        SET
          status = 'failed',
          attempts = attempts + 1,
          replay_count = replay_count + 1,
          last_error = $2
        WHERE id = $1
      `,
      [event.id, String(error)],
    );
    return { id: event.id, provider: event.provider, status: "failed", message: String(error) };
  }
}

export async function reconcileFailedWebhookEvents(
  app: FastifyInstance,
  options: { provider?: WebhookProvider; limit: number; force: boolean },
): Promise<{ attempted: number; processed: number; failed: number; skipped: number; results: ReplayResult[] }> {
  const rows = await app.db.query<{ id: string }>(
    `
      SELECT id
      FROM billing_webhook_events
      WHERE ($1::text IS NULL OR provider = $1)
        AND ($2::bool OR status = 'failed')
      ORDER BY received_at ASC
      LIMIT $3
    `,
    [options.provider ?? null, options.force, options.limit],
  );

  const results: ReplayResult[] = [];
  let processed = 0;
  let failed = 0;
  let skipped = 0;

  for (const row of rows.rows) {
    const result = await replayWebhookEventById(app, row.id, options.force);
    results.push(result);
    if (result.status === "processed") processed += 1;
    else if (result.status === "failed") failed += 1;
    else skipped += 1;
  }

  return { attempted: rows.rows.length, processed, failed, skipped, results };
}

export const billingRoutes: FastifyPluginAsync = async (app) => {
  app.post("/reports/exports/:id/ack", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params ?? {});
    const body = z
      .object({
        sinkRef: z.string().max(500).optional(),
        metadata: z.record(z.unknown()).optional(),
      })
      .parse(request.body ?? {});

    const providedToken = headerValue(request.headers["x-fdt-report-ack-token"])?.trim();
    if (!providedToken) {
      return reply.code(401).send({ message: "Missing report ACK token" });
    }

    const row = await app.db.query<{
      id: string;
      org_id: string | null;
      status: "pending" | "running" | "completed" | "failed";
      delivery_ack_status: "not_required" | "pending" | "acknowledged" | "expired";
      delivery_ack_token_hash: string | null;
      delivery_ack_deadline: Date | null;
    }>(
      `
      SELECT
        id,
        org_id,
        status,
        delivery_ack_status,
        delivery_ack_token_hash,
        delivery_ack_deadline
      FROM billing_report_exports
      WHERE id = $1
      LIMIT 1
    `,
      [params.id],
    );
    if (!row.rowCount || !row.rows[0]) {
      return reply.code(404).send({ message: "Report export not found" });
    }
    const exportRow = row.rows[0];

    if (exportRow.status !== "completed") {
      return reply.code(409).send({ message: "Report export is not completed yet" });
    }
    if (exportRow.delivery_ack_status === "acknowledged") {
      return { ok: true, id: params.id, alreadyAcknowledged: true };
    }
    if (exportRow.delivery_ack_status !== "pending" || !exportRow.delivery_ack_token_hash) {
      return reply.code(409).send({ message: "Report export does not require pending acknowledgement" });
    }
    if (exportRow.delivery_ack_deadline && exportRow.delivery_ack_deadline.getTime() <= Date.now()) {
      return reply.code(410).send({ message: "Report acknowledgement deadline has expired" });
    }

    const providedHash = sha256Hex(providedToken);
    if (!safeHexCompare(exportRow.delivery_ack_token_hash, providedHash)) {
      return reply.code(401).send({ message: "Invalid report ACK token" });
    }

    const ackMetadata = {
      acknowledgedAt: new Date().toISOString(),
      sinkRef: body.sinkRef ?? null,
      metadata: body.metadata ?? null,
    };

    await app.db.query(
      `
      UPDATE billing_report_exports
      SET
        delivery_ack_status = 'acknowledged',
        delivery_ack_at = NOW(),
        delivery_ack_token_hash = NULL,
        delivery_ack_deadline = NULL,
        delivery_ack_metadata = COALESCE(delivery_ack_metadata, '{}'::jsonb) || $2::jsonb,
        last_delivery_status = 'acknowledged',
        updated_at = NOW()
      WHERE id = $1
    `,
      [params.id, ackMetadata],
    );

    await app.audit.log({
      actorUserId: null,
      orgId: exportRow.org_id,
      action: "billing.report.export.ack",
      entityType: "billing_report_export",
      entityId: params.id,
      metadata: {
        sinkRef: body.sinkRef ?? null,
      },
    });

    return { ok: true, id: params.id };
  });

  app.post(
    "/settlement-receipts",
    { config: { rawBody: true } },
    async (request, reply) => {
      const signatureCheck = verifySettlementSignature(app, request);
      if (!signatureCheck.ok) {
        const code = signatureCheck.message?.includes("configured") ? 503 : 401;
        return reply.code(code).send({ message: signatureCheck.message ?? "Invalid settlement signature" });
      }

      const body = z
        .object({
          provider: checkoutProviderSchema,
          batchId: z.string().min(2).max(255),
          periodStart: z.coerce.date().optional(),
          periodEnd: z.coerce.date().optional(),
          totalEvents: z.coerce.number().int().min(0).optional().default(0),
          totalAmountCents: z.coerce.number().int().optional(),
          currency: z.string().length(3).optional(),
          eventDigest: z.string().max(255).optional(),
          payload: z.record(z.unknown()).optional(),
        })
        .parse(request.body ?? {});

      if (body.periodStart && body.periodEnd && body.periodEnd <= body.periodStart) {
        return reply.code(400).send({ message: "periodEnd must be greater than periodStart" });
      }

      const payloadDigest = body.eventDigest ?? sha256Hex(getRawBody(request));
      const upsert = await app.db.query<{
        id: string;
        reconciliation_status: "pending" | "matched" | "delta" | "failed";
      }>(
        `
        INSERT INTO billing_settlement_receipts (
          id,
          provider,
          batch_id,
          period_start,
          period_end,
          total_events,
          total_amount_cents,
          currency,
          event_digest,
          payload_json,
          signature_valid,
          reconciliation_status,
          updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, UPPER($8), $9, $10, TRUE, 'pending', NOW())
        ON CONFLICT (provider, batch_id) DO UPDATE
        SET
          period_start = COALESCE(EXCLUDED.period_start, billing_settlement_receipts.period_start),
          period_end = COALESCE(EXCLUDED.period_end, billing_settlement_receipts.period_end),
          total_events = EXCLUDED.total_events,
          total_amount_cents = COALESCE(EXCLUDED.total_amount_cents, billing_settlement_receipts.total_amount_cents),
          currency = COALESCE(EXCLUDED.currency, billing_settlement_receipts.currency),
          event_digest = COALESCE(EXCLUDED.event_digest, billing_settlement_receipts.event_digest),
          payload_json = COALESCE(EXCLUDED.payload_json, billing_settlement_receipts.payload_json),
          signature_valid = TRUE,
          reconciliation_status = CASE
            WHEN billing_settlement_receipts.reconciliation_status = 'failed' THEN 'pending'
            ELSE billing_settlement_receipts.reconciliation_status
          END,
          updated_at = NOW()
        RETURNING id, reconciliation_status
      `,
        [
          uuidv4(),
          body.provider,
          body.batchId,
          body.periodStart ?? null,
          body.periodEnd ?? null,
          body.totalEvents,
          body.totalAmountCents ?? null,
          body.currency ?? null,
          payloadDigest,
          body.payload ?? null,
        ],
      );

      const receipt = upsert.rows[0];
      await app.audit.log({
        actorUserId: null,
        orgId: null,
        action: "billing.settlement.receipt.ingest",
        entityType: "billing_settlement_receipt",
        entityId: receipt.id,
        metadata: {
          provider: body.provider,
          batchId: body.batchId,
          totalEvents: body.totalEvents,
          totalAmountCents: body.totalAmountCents ?? null,
          reconciliationStatus: receipt.reconciliation_status,
        },
      });

      return reply.code(202).send({
        ok: true,
        id: receipt.id,
        provider: body.provider,
        batchId: body.batchId,
        reconciliationStatus: receipt.reconciliation_status,
      });
    },
  );

  app.get(
    "/subscription",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const subscription = await getOrgSubscription(app, request.authUser!.orgId);
      if (!subscription) {
        return reply.code(404).send({ message: "Subscription not found" });
      }

      return {
        subscription: {
          provider: subscription.billing_provider,
          status: subscription.status,
          planCode: subscription.plan_code,
          planName: subscription.plan_name,
          externalSubscriptionId: subscriptionIdForProvider(subscription),
        },
      };
    },
  );

  app.get(
    "/finance-events",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request) => {
      const query = z
        .object({
          type: z.enum(["subscription_cancel", "refund", "payment_failed", "payment_recovered"]).optional(),
          status: z.enum(["pending", "processed", "failed", "mocked"]).optional(),
          limit: z.coerce.number().int().min(1).max(200).default(50),
        })
        .parse(request.query ?? {});

      const events = await app.db.query(
        `
          SELECT
            id,
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
          WHERE org_id = $1
            AND ($2::text IS NULL OR event_type = $2)
            AND ($3::text IS NULL OR status = $3)
          ORDER BY created_at DESC
          LIMIT $4
        `,
        [request.authUser!.orgId, query.type ?? null, query.status ?? null, query.limit],
      );

      return { events: events.rows };
    },
  );

  app.get(
    "/dunning",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request) => {
      const query = z
        .object({
          status: z.enum(["open", "recovered", "closed"]).optional(),
          provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
          limit: z.coerce.number().int().min(1).max(200).default(50),
        })
        .parse(request.query ?? {});

      const cases = await app.db.query(
        `
          SELECT
            id,
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
          WHERE org_id = $1
            AND ($2::text IS NULL OR status = $2)
            AND ($3::text IS NULL OR provider = $3)
          ORDER BY updated_at DESC
          LIMIT $4
        `,
        [request.authUser!.orgId, query.status ?? null, query.provider ?? null, query.limit],
      );

      return { cases: cases.rows };
    },
  );

  app.get(
    "/invoices",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request) => {
      const query = z
        .object({
          status: invoiceStatusSchema.optional(),
          limit: z.coerce.number().int().min(1).max(500).default(50),
          includeTax: z.coerce.boolean().optional().default(false),
        })
        .parse(request.query ?? {});

      const invoices = await listOrgInvoices(app, request.authUser!.orgId, {
        status: query.status,
        limit: query.limit,
      });

      const taxRecords = query.includeTax ? await listTaxRecordsForInvoices(app, invoices.map((row) => row.id)) : [];
      return { invoices, taxRecords };
    },
  );

  app.get(
    "/invoices/export",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const query = z
        .object({
          status: invoiceStatusSchema.optional(),
          limit: z.coerce.number().int().min(1).max(5000).default(2000),
        })
        .parse(request.query ?? {});

      const invoices = await listOrgInvoices(app, request.authUser!.orgId, {
        status: query.status,
        limit: query.limit,
      });

      const csv = toCsv(
        [
          "id",
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
        invoices.map((invoice) => ({
          id: invoice.id,
          provider: invoice.provider,
          provider_invoice_id: invoice.provider_invoice_id,
          provider_subscription_id: invoice.provider_subscription_id,
          provider_payment_id: invoice.provider_payment_id,
          status: invoice.status,
          currency: invoice.currency,
          subtotal_cents: invoice.subtotal_cents,
          tax_cents: invoice.tax_cents,
          total_cents: invoice.total_cents,
          amount_due_cents: invoice.amount_due_cents,
          amount_paid_cents: invoice.amount_paid_cents,
          invoice_url: invoice.invoice_url,
          period_start: invoice.period_start,
          period_end: invoice.period_end,
          issued_at: invoice.issued_at,
          due_at: invoice.due_at,
          paid_at: invoice.paid_at,
          created_at: invoice.created_at,
          updated_at: invoice.updated_at,
        })),
      );

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      reply.header("content-type", "text/csv; charset=utf-8");
      reply.header("content-disposition", `attachment; filename="billing-invoices-${timestamp}.csv"`);
      return reply.send(csv);
    },
  );

  app.post(
    "/subscription/cancel",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const body = z
        .object({
          atPeriodEnd: z.boolean().optional().default(true),
          reason: z.string().min(2).max(500).optional(),
        })
        .parse(request.body ?? {});

      const orgId = request.authUser!.orgId;
      const subscription = await getOrgSubscription(app, orgId);
      if (!subscription) {
        return reply.code(404).send({ message: "Subscription not found" });
      }
      if (subscription.plan_code === "free") {
        return reply.code(409).send({ message: "Free plan has no paid subscription to cancel" });
      }

      const provider = subscription.billing_provider;
      const providerSubId = subscriptionIdForProvider(subscription);
      let mode: "mock" | "provider" = "mock";
      let externalActionId: string | null = null;
      let providerResult: unknown = { mocked: true };

      try {
        if (provider === "stripe" && app.env.STRIPE_SECRET_KEY && subscription.stripe_subscription_id) {
          const stripe = new Stripe(app.env.STRIPE_SECRET_KEY);
          mode = "provider";
          if (body.atPeriodEnd) {
            const updated = await stripe.subscriptions.update(subscription.stripe_subscription_id, {
              cancel_at_period_end: true,
            });
            externalActionId = updated.id;
            providerResult = {
              id: updated.id,
              status: updated.status,
              cancel_at_period_end: updated.cancel_at_period_end,
            };
          } else {
            const canceled = await stripe.subscriptions.cancel(subscription.stripe_subscription_id);
            externalActionId = canceled.id;
            providerResult = {
              id: canceled.id,
              status: canceled.status,
              canceled_at: canceled.canceled_at,
            };
          }
        } else if (provider === "razorpay" && app.env.RAZORPAY_KEY_ID && app.env.RAZORPAY_KEY_SECRET && subscription.razorpay_subscription_id) {
          mode = "provider";
          const response = await fetch(`https://api.razorpay.com/v1/subscriptions/${subscription.razorpay_subscription_id}/cancel`, {
            method: "POST",
            headers: {
              authorization: createBasicAuth(app.env.RAZORPAY_KEY_ID, app.env.RAZORPAY_KEY_SECRET),
              "content-type": "application/json",
            },
            body: JSON.stringify({ cancel_at_cycle_end: body.atPeriodEnd ? 1 : 0 }),
          });
          if (!response.ok) {
            throw new Error(`Razorpay cancel failed with status ${response.status}`);
          }
          const payload = (await response.json()) as { id?: string; status?: string };
          externalActionId = payload.id ?? subscription.razorpay_subscription_id;
          providerResult = payload;
        } else if (provider === "paypal" && app.env.PAYPAL_CLIENT_ID && app.env.PAYPAL_CLIENT_SECRET && subscription.paypal_subscription_id) {
          mode = "provider";
          const token = await paypalAccessToken(app);
          const response = await fetch(
            `${paypalBaseUrl(app.env.PAYPAL_ENVIRONMENT)}/v1/billing/subscriptions/${subscription.paypal_subscription_id}/cancel`,
            {
              method: "POST",
              headers: {
                authorization: `Bearer ${token}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({ reason: body.reason ?? "Customer requested cancellation" }),
            },
          );
          if (![200, 202, 204].includes(response.status)) {
            throw new Error(`PayPal cancel failed with status ${response.status}`);
          }
          externalActionId = subscription.paypal_subscription_id;
          providerResult = response.status === 204 ? { id: externalActionId, status: "CANCELLED" } : await response.json();
        }
      } catch (error) {
        const financeEventId = await recordFinanceEvent(app, {
          orgId,
          provider,
          eventType: "subscription_cancel",
          status: "failed",
          externalRef: providerSubId,
          reason: body.reason ?? null,
          payload: { atPeriodEnd: body.atPeriodEnd },
          error: String(error),
        });

        await app.audit.log({
          actorUserId: request.authUser!.userId,
          orgId,
          action: "billing.subscription.cancel.failed",
          entityType: "subscription",
          entityId: orgId,
          metadata: { provider, atPeriodEnd: body.atPeriodEnd, financeEventId, error: String(error) },
        });

        return reply.code(502).send({ message: `Subscription cancel failed: ${String(error)}` });
      }

      const nextStatus = body.atPeriodEnd ? "cancel_at_period_end" : "canceled";
      if (body.atPeriodEnd) {
        await upsertSubscriptionState(app, {
          orgId,
          provider,
          status: nextStatus,
          planId: subscription.plan_id,
          stripeSubscriptionId: subscription.stripe_subscription_id,
          razorpaySubscriptionId: subscription.razorpay_subscription_id,
          paypalSubscriptionId: subscription.paypal_subscription_id,
        });
      } else {
        await setFreePlan(app, orgId, provider, nextStatus);
      }

      const financeEventId = await recordFinanceEvent(app, {
        orgId,
        provider,
        eventType: "subscription_cancel",
        status: mode === "mock" ? "mocked" : "processed",
        externalId: externalActionId,
        externalRef: providerSubId,
        reason: body.reason ?? null,
        payload: { atPeriodEnd: body.atPeriodEnd },
        result: providerResult,
      });

      await app.audit.log({
        actorUserId: request.authUser!.userId,
        orgId,
        action: "billing.subscription.cancel",
        entityType: "subscription",
        entityId: orgId,
        metadata: { provider, mode, atPeriodEnd: body.atPeriodEnd, financeEventId },
      });

      return {
        ok: true,
        provider,
        mode,
        atPeriodEnd: body.atPeriodEnd,
        status: nextStatus,
        financeEventId,
      };
    },
  );

  app.post(
    "/refund",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const body = z
        .object({
          paymentId: z.string().min(3),
          amountCents: z.coerce.number().int().positive().optional(),
          currency: z.string().length(3).optional().default("USD"),
          reason: z.string().min(2).max(500).optional(),
        })
        .parse(request.body ?? {});

      const orgId = request.authUser!.orgId;
      const subscription = await getOrgSubscription(app, orgId);
      if (!subscription) {
        return reply.code(404).send({ message: "Subscription not found" });
      }

      const provider = subscription.billing_provider;
      const currency = body.currency.toUpperCase();
      let mode: "mock" | "provider" = "mock";
      let externalRefundId: string | null = null;
      let providerResult: unknown = { mocked: true, paymentId: body.paymentId };

      try {
        if (provider === "stripe" && app.env.STRIPE_SECRET_KEY) {
          mode = "provider";
          const stripe = new Stripe(app.env.STRIPE_SECRET_KEY);
          const refundInput: Stripe.RefundCreateParams =
            body.paymentId.startsWith("pi_") ? { payment_intent: body.paymentId } : { charge: body.paymentId };
          if (body.amountCents) {
            refundInput.amount = body.amountCents;
          }
          if (body.reason) {
            refundInput.reason = "requested_by_customer";
          }
          refundInput.metadata = {
            orgId,
            note: body.reason ?? "",
          };

          const refund = await stripe.refunds.create(refundInput);
          externalRefundId = refund.id;
          providerResult = {
            id: refund.id,
            status: refund.status,
            amount: refund.amount,
            currency: refund.currency?.toUpperCase(),
          };
        } else if (provider === "razorpay" && app.env.RAZORPAY_KEY_ID && app.env.RAZORPAY_KEY_SECRET) {
          mode = "provider";
          const payload: Record<string, unknown> = { speed: "normal" };
          if (body.amountCents) payload.amount = body.amountCents;
          if (body.reason) payload.notes = { reason: body.reason };

          const response = await fetch(`https://api.razorpay.com/v1/payments/${encodeURIComponent(body.paymentId)}/refund`, {
            method: "POST",
            headers: {
              authorization: createBasicAuth(app.env.RAZORPAY_KEY_ID, app.env.RAZORPAY_KEY_SECRET),
              "content-type": "application/json",
            },
            body: JSON.stringify(payload),
          });
          if (!response.ok) {
            throw new Error(`Razorpay refund failed with status ${response.status}`);
          }
          const refund = (await response.json()) as { id?: string; status?: string; amount?: number; currency?: string };
          externalRefundId = refund.id ?? null;
          providerResult = refund;
        } else if (provider === "paypal" && app.env.PAYPAL_CLIENT_ID && app.env.PAYPAL_CLIENT_SECRET) {
          mode = "provider";
          const token = await paypalAccessToken(app);
          const payload: Record<string, unknown> = {};
          if (body.amountCents) {
            payload.amount = {
              currency_code: currency,
              value: (body.amountCents / 100).toFixed(2),
            };
          }
          if (body.reason) {
            payload.note_to_payer = body.reason;
          }

          const response = await fetch(
            `${paypalBaseUrl(app.env.PAYPAL_ENVIRONMENT)}/v2/payments/captures/${encodeURIComponent(body.paymentId)}/refund`,
            {
              method: "POST",
              headers: {
                authorization: `Bearer ${token}`,
                "content-type": "application/json",
              },
              body: JSON.stringify(payload),
            },
          );
          if (![200, 201, 202].includes(response.status)) {
            throw new Error(`PayPal refund failed with status ${response.status}`);
          }
          const refund = await response.json();
          externalRefundId = typeof refund?.id === "string" ? refund.id : null;
          providerResult = refund;
        } else {
          externalRefundId = `mock_refund_${uuidv4().replace(/-/g, "").slice(0, 12)}`;
          providerResult = { mocked: true, id: externalRefundId, paymentId: body.paymentId };
        }
      } catch (error) {
        const financeEventId = await recordFinanceEvent(app, {
          orgId,
          provider,
          eventType: "refund",
          status: "failed",
          externalRef: body.paymentId,
          amountCents: body.amountCents ?? null,
          currency,
          reason: body.reason ?? null,
          payload: { paymentId: body.paymentId },
          error: String(error),
        });

        await app.audit.log({
          actorUserId: request.authUser!.userId,
          orgId,
          action: "billing.refund.failed",
          entityType: "payment",
          entityId: body.paymentId,
          metadata: { provider, financeEventId, error: String(error) },
        });

        return reply.code(502).send({ message: `Refund failed: ${String(error)}` });
      }

      const financeEventId = await recordFinanceEvent(app, {
        orgId,
        provider,
        eventType: "refund",
        status: mode === "mock" ? "mocked" : "processed",
        externalId: externalRefundId,
        externalRef: body.paymentId,
        amountCents: body.amountCents ?? null,
        currency,
        reason: body.reason ?? null,
        payload: { paymentId: body.paymentId },
        result: providerResult,
      });

      await app.audit.log({
        actorUserId: request.authUser!.userId,
        orgId,
        action: "billing.refund.create",
        entityType: "payment",
        entityId: body.paymentId,
        metadata: { provider, mode, financeEventId, amountCents: body.amountCents ?? null, currency },
      });

      return {
        ok: true,
        provider,
        mode,
        refundId: externalRefundId,
        financeEventId,
      };
    },
  );

  app.post(
    "/checkout-session",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const body = z
        .object({
          planCode: z.enum(["pro", "team"]),
          provider: checkoutProviderSchema.default("stripe"),
          successUrl: z.string().url().optional(),
          cancelUrl: z.string().url().optional(),
        })
        .parse(request.body);

      const plan = await app.db.query<PlanRow>(
        `SELECT id, stripe_price_id, razorpay_plan_id, paypal_plan_id FROM plans WHERE code = $1 LIMIT 1`,
        [body.planCode],
      );
      const target = plan.rows[0];
      if (!target) {
        return reply.code(404).send({ message: "Plan not found" });
      }

      const successUrl = body.successUrl ?? app.env.BILLING_SUCCESS_URL;
      const cancelUrl = body.cancelUrl ?? app.env.BILLING_CANCEL_URL;

      if (body.provider === "stripe") {
        if (!app.env.STRIPE_SECRET_KEY || !target.stripe_price_id) {
          return {
            mode: "mock",
            provider: "stripe",
            checkoutUrl: paymentMockUrl("stripe", body.planCode),
          };
        }

        try {
          const stripe = new Stripe(app.env.STRIPE_SECRET_KEY);
          const session = await stripe.checkout.sessions.create({
            mode: "subscription",
            line_items: [{ price: target.stripe_price_id, quantity: 1 }],
            success_url: successUrl,
            cancel_url: cancelUrl,
            client_reference_id: request.authUser!.orgId,
            subscription_data: {
              metadata: {
                orgId: request.authUser!.orgId,
                planCode: body.planCode,
              },
            },
          });

          return { mode: "stripe", provider: "stripe", checkoutUrl: session.url };
        } catch (error) {
          return reply.code(502).send({ message: `Stripe checkout failed: ${String(error)}` });
        }
      }

      if (body.provider === "razorpay") {
        if (!app.env.RAZORPAY_KEY_ID || !app.env.RAZORPAY_KEY_SECRET || !target.razorpay_plan_id) {
          return {
            mode: "mock",
            provider: "razorpay",
            checkoutUrl: paymentMockUrl("razorpay", body.planCode),
          };
        }

        try {
          const response = await fetch("https://api.razorpay.com/v1/subscriptions", {
            method: "POST",
            headers: {
              authorization: createBasicAuth(app.env.RAZORPAY_KEY_ID, app.env.RAZORPAY_KEY_SECRET),
              "content-type": "application/json",
            },
            body: JSON.stringify({
              plan_id: target.razorpay_plan_id,
              total_count: 1200,
              quantity: 1,
              customer_notify: 1,
              notes: {
                orgId: request.authUser!.orgId,
                planCode: body.planCode,
              },
              callback_url: successUrl,
              callback_method: "get",
            }),
          });

          if (!response.ok) {
            return reply.code(502).send({ message: `Razorpay checkout failed with status ${response.status}` });
          }

          const payload = (await response.json()) as RazorpaySubscriptionPayload;
          if (!payload.id || !payload.short_url) {
            return reply.code(502).send({ message: "Razorpay response missing checkout URL" });
          }

          await upsertSubscriptionState(app, {
            orgId: request.authUser!.orgId,
            provider: "razorpay",
            status: "created",
            planId: null,
            razorpaySubscriptionId: payload.id,
          });

          return { mode: "razorpay", provider: "razorpay", checkoutUrl: payload.short_url, subscriptionId: payload.id };
        } catch (error) {
          return reply.code(502).send({ message: `Razorpay checkout failed: ${String(error)}` });
        }
      }

      if (!app.env.PAYPAL_CLIENT_ID || !app.env.PAYPAL_CLIENT_SECRET || !target.paypal_plan_id) {
        return {
          mode: "mock",
          provider: "paypal",
          checkoutUrl: paymentMockUrl("paypal", body.planCode),
        };
      }

      try {
        const token = await paypalAccessToken(app);
        const response = await fetch(`${paypalBaseUrl(app.env.PAYPAL_ENVIRONMENT)}/v1/billing/subscriptions`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            plan_id: target.paypal_plan_id,
            custom_id: request.authUser!.orgId,
            application_context: {
              brand_name: "TunnelForge",
              user_action: "SUBSCRIBE_NOW",
              return_url: successUrl,
              cancel_url: cancelUrl,
            },
          }),
        });

        if (!response.ok) {
          return reply.code(502).send({ message: `PayPal checkout failed with status ${response.status}` });
        }

        const payload = (await response.json()) as PaypalCreateSubscriptionResponse;
        const approveUrl = payload.links?.find((link) => link.rel === "approve")?.href;
        if (!payload.id || !approveUrl) {
          return reply.code(502).send({ message: "PayPal response missing approval URL" });
        }

        await upsertSubscriptionState(app, {
          orgId: request.authUser!.orgId,
          provider: "paypal",
          status: "APPROVAL_PENDING",
          planId: null,
          paypalSubscriptionId: payload.id,
        });

        return { mode: "paypal", provider: "paypal", checkoutUrl: approveUrl, subscriptionId: payload.id };
      } catch (error) {
        return reply.code(502).send({ message: `PayPal checkout failed: ${String(error)}` });
      }
    },
  );

  app.post(
    "/runbook/replay",
    { config: { rawBody: true } },
    async (request, reply) => {
      const signatureCheck = verifyRunbookSignature(app, request);
      if (!signatureCheck.ok) {
        const code = signatureCheck.message?.includes("configured") ? 503 : 401;
        return reply.code(code).send({ message: signatureCheck.message ?? "Invalid runbook signature" });
      }

      const body = z
        .object({
          provider: z.enum(["stripe", "razorpay", "paypal"]).optional(),
          eventClass: z.enum(["all", "payment", "subscription"]).optional().default("all"),
          limit: z.coerce.number().int().min(1).max(500).default(50),
          force: z.boolean().optional().default(false),
        })
        .parse(request.body ?? {});

      const rows = await app.db.query<{ id: string }>(
        `
          SELECT id
          FROM billing_webhook_events
          WHERE ($1::text IS NULL OR provider = $1)
            AND status = 'failed'
            AND (
              $2::text = 'all'
              OR (
                $2::text = 'payment'
                AND (
                  provider_event_type ILIKE '%payment%'
                  OR provider_event_type ILIKE '%invoice%'
                )
              )
              OR ($2::text = 'subscription' AND provider_event_type ILIKE '%subscription%')
            )
          ORDER BY received_at ASC
          LIMIT $3
        `,
        [body.provider ?? null, body.eventClass, body.limit],
      );

      let processed = 0;
      let failed = 0;
      let skipped = 0;
      const results: ReplayResult[] = [];
      for (const row of rows.rows) {
        const result = await replayWebhookEventById(app, row.id, body.force);
        results.push(result);
        if (result.status === "processed") processed += 1;
        else if (result.status === "failed") failed += 1;
        else skipped += 1;
      }

      await app.audit.log({
        actorUserId: null,
        orgId: null,
        action: "billing.runbook.replay",
        entityType: "billing_webhook_event",
        entityId: body.provider ?? "all",
        metadata: {
          eventClass: body.eventClass,
          limit: body.limit,
          force: body.force,
          attempted: rows.rows.length,
          processed,
          failed,
          skipped,
        },
      });

      return {
        ok: true,
        attempted: rows.rows.length,
        processed,
        failed,
        skipped,
        results,
      };
    },
  );

  const webhookRouteOptions = { config: { rawBody: true } } as const;

  const handleStripeWebhook = async (request: FastifyRequest, reply: FastifyReply) => {
    if (!app.env.STRIPE_SECRET_KEY || !app.env.STRIPE_WEBHOOK_SECRET) {
      return { ok: true, ignored: true };
    }

    const signature = headerValue(request.headers["stripe-signature"]);
    if (!signature) {
      return reply.code(400).send({ message: "Missing stripe signature" });
    }

    const rawBody = getRawBody(request);
    const stripe = new Stripe(app.env.STRIPE_SECRET_KEY);
    let event: Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(rawBody, signature, app.env.STRIPE_WEBHOOK_SECRET);
    } catch (error) {
      return reply.code(400).send({ message: `Invalid webhook signature: ${String(error)}` });
    }

    const eventDate = new Date(event.created * 1000);
    if (!eventIsFresh(eventDate, app.env.BILLING_WEBHOOK_MAX_AGE_SECONDS)) {
      return reply.code(400).send({ message: "Stripe webhook event too old" });
    }

    const eventId = normalizeEventId("stripe", event.id, rawBody);
    const payloadHash = sha256Hex(rawBody);
    const start = await startWebhookEvent(app, "stripe", eventId, payloadHash, event.type, request.body ?? {});
    if (start.mismatch) {
      return reply.code(409).send({ message: "Conflicting duplicate Stripe event payload" });
    }
    if (start.duplicate) {
      return { ok: true, duplicate: true };
    }

    try {
      await processStripeEvent(app, event);

      await finishWebhookEvent(app, "stripe", eventId, "processed");
      return { ok: true };
    } catch (error) {
      await finishWebhookEvent(app, "stripe", eventId, "failed", error);
      throw error;
    }
  };

  app.post("/webhook", webhookRouteOptions, handleStripeWebhook);
  app.post("/webhook/stripe", webhookRouteOptions, handleStripeWebhook);

  app.post("/webhook/razorpay", webhookRouteOptions, async (request, reply) => {
    const rawBody = getRawBody(request);

    if (app.env.RAZORPAY_WEBHOOK_SECRET) {
      const signature = headerValue(request.headers["x-razorpay-signature"]);
      if (!signature) {
        return reply.code(400).send({ message: "Missing Razorpay signature" });
      }
      const expected = crypto.createHmac("sha256", app.env.RAZORPAY_WEBHOOK_SECRET).update(rawBody).digest("hex");
      if (!safeHexCompare(expected, signature)) {
        return reply.code(400).send({ message: "Invalid Razorpay signature" });
      }
    }

    const parsed = razorpayWebhookSchema.safeParse(request.body ?? {});

    if (!parsed.success) {
      return { ok: true, ignored: true };
    }

    const headerEventId = headerValue(request.headers["x-razorpay-event-id"]);
    const eventId = normalizeEventId("razorpay", headerEventId, rawBody);
    const payloadHash = sha256Hex(rawBody);
    const start = await startWebhookEvent(app, "razorpay", eventId, payloadHash, parsed.data.event, parsed.data);
    if (start.mismatch) {
      return reply.code(409).send({ message: "Conflicting duplicate Razorpay event payload" });
    }
    if (start.duplicate) {
      return { ok: true, duplicate: true };
    }

    try {
      await processRazorpayWebhookPayload(app, parsed.data);

      await finishWebhookEvent(app, "razorpay", eventId, "processed");
      return { ok: true };
    } catch (error) {
      await finishWebhookEvent(app, "razorpay", eventId, "failed", error);
      throw error;
    }
  });

  app.post("/webhook/paypal", webhookRouteOptions, async (request, reply) => {
    const rawBody = getRawBody(request);
    const verified = await verifyPaypalWebhook(app, request.body ?? {}, request.headers);
    if (!verified) {
      return reply.code(400).send({ message: "Invalid PayPal webhook signature" });
    }

    const transmissionTime = headerValue(request.headers["paypal-transmission-time"]);
    if (transmissionTime) {
      const transmissionDate = new Date(transmissionTime);
      if (!eventIsFresh(transmissionDate, app.env.BILLING_WEBHOOK_MAX_AGE_SECONDS)) {
        return reply.code(400).send({ message: "PayPal webhook event too old" });
      }
    }

    const parsed = paypalWebhookSchema.safeParse(request.body ?? {});

    if (!parsed.success) {
      return { ok: true, ignored: true };
    }

    const eventId = normalizeEventId("paypal", parsed.data.id ?? headerValue(request.headers["paypal-transmission-id"]), rawBody);
    const payloadHash = sha256Hex(rawBody);
    const start = await startWebhookEvent(app, "paypal", eventId, payloadHash, parsed.data.event_type, parsed.data);
    if (start.mismatch) {
      return reply.code(409).send({ message: "Conflicting duplicate PayPal event payload" });
    }
    if (start.duplicate) {
      return { ok: true, duplicate: true };
    }

    try {
      await processPaypalWebhookPayload(app, parsed.data);

      await finishWebhookEvent(app, "paypal", eventId, "processed");
      return { ok: true };
    } catch (error) {
      await finishWebhookEvent(app, "paypal", eventId, "failed", error);
      throw error;
    }
  });
};
