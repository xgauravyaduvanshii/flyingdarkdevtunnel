import crypto from "node:crypto";
import dotenv from "dotenv";
import http from "node:http";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { Pool } from "pg";
import Stripe from "stripe";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  STRIPE_SECRET_KEY: z.string().optional(),
  RAZORPAY_KEY_ID: z.string().optional(),
  RAZORPAY_KEY_SECRET: z.string().optional(),
  PAYPAL_CLIENT_ID: z.string().optional(),
  PAYPAL_CLIENT_SECRET: z.string().optional(),
  PAYPAL_ENVIRONMENT: z.enum(["sandbox", "live"]).optional().default("sandbox"),
  BILLING_SYNC_INTERVAL_SECONDS: z.coerce.number().int().positive().default(60),
  BILLING_WEBHOOK_EVENT_RETENTION_DAYS: z.coerce.number().int().positive().default(30),
  BILLING_WEBHOOK_FAILURE_WARN_THRESHOLD: z.coerce.number().int().positive().default(10),
  BILLING_WEBHOOK_SLO_SECONDS: z.coerce.number().positive().default(60),
  BILLING_ALERT_WEBHOOK_URL: z.string().url().optional(),
  BILLING_ALERT_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(600),
  BILLING_METRICS_PORT: z.coerce.number().int().positive().default(9464),
  API_BASE_URL: z.string().url().optional(),
  BILLING_RUNBOOK_SIGNING_SECRET: z.string().optional(),
  BILLING_RUNBOOK_REPLAY_LIMIT: z.coerce.number().int().positive().default(50),
  BILLING_RUNBOOK_REPLAY_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(300),
  BILLING_DUNNING_MAX_STAGE: z.coerce.number().int().positive().default(6),
  BILLING_DUNNING_SCHEDULE_STRIPE: z.string().optional().default("900,3600,21600,86400,172800"),
  BILLING_DUNNING_SCHEDULE_RAZORPAY: z.string().optional().default("1800,7200,28800,86400,172800"),
  BILLING_DUNNING_SCHEDULE_PAYPAL: z.string().optional().default("1800,14400,43200,86400,259200"),
  BILLING_DUNNING_NOTIFICATION_WEBHOOK_URL: z.string().url().optional(),
  BILLING_DUNNING_NOTIFICATION_SECRET: z.string().optional(),
  BILLING_DUNNING_EMAIL_WEBHOOK_URL: z.string().url().optional(),
  BILLING_DUNNING_SLACK_WEBHOOK_URL: z.string().url().optional(),
  BILLING_REPORT_EXPORT_BATCH_SIZE: z.coerce.number().int().positive().default(10),
  BILLING_REPORT_WEBHOOK_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(12),
  BILLING_REPORT_RETRY_SCHEDULE_SECONDS: z.string().optional().default("60,300,900,1800,3600"),
  BILLING_REPORT_RUNNING_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(1800),
  BILLING_REPORT_ACK_ENABLED: z
    .string()
    .optional()
    .default("true")
    .transform((value) => value.trim().toLowerCase() !== "false"),
  BILLING_REPORT_ACK_REQUIRED_DESTINATIONS: z.string().optional().default("webhook,warehouse"),
  BILLING_REPORT_ACK_TTL_SECONDS: z.coerce.number().int().positive().default(3600),
  BILLING_REPORT_DEFAULT_SINK_URL: z.string().url().optional(),
  BILLING_REPORT_WAREHOUSE_SINK_URL: z.string().url().optional(),
  BILLING_REPORT_SIGNING_SECRET: z.string().optional(),
  BILLING_REPORT_S3_BUCKET: z.string().optional(),
  BILLING_REPORT_S3_REGION: z.string().optional().default("us-east-1"),
  BILLING_REPORT_S3_ENDPOINT: z.string().url().optional(),
  BILLING_REPORT_S3_ACCESS_KEY: z.string().optional(),
  BILLING_REPORT_S3_SECRET_KEY: z.string().optional(),
  BILLING_REPORT_S3_FORCE_PATH_STYLE: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value.trim().toLowerCase() === "true"),
  BILLING_REPORT_S3_KEY_PREFIX: z.string().optional().default("billing-exports/"),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });
const stripe = env.STRIPE_SECRET_KEY ? new Stripe(env.STRIPE_SECRET_KEY) : null;
const razorpayEnabled = Boolean(env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET);
const paypalEnabled = Boolean(env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET);
let paypalTokenCache: { token: string; expiresAt: number } | null = null;
let loggedProviderState = false;
const lastAlertAtByProvider: Partial<Record<"stripe" | "razorpay" | "paypal", number>> = {};
const lastRunbookReplayAtByKey = new Map<string, number>();
let runbookReplayTriggerTotal = 0;
let runbookReplayTriggerFailureTotal = 0;
let s3Client: S3Client | null = null;

type BillingProvider = "stripe" | "razorpay" | "paypal";
type DunningChannel = "webhook" | "email" | "slack";
type ReportDestination = "inline" | "webhook" | "s3" | "warehouse";
type AckRequiredDestination = Exclude<ReportDestination, "inline">;
type WebhookHealthSummary = {
  failed1h: number;
  failed24h: number;
  stalePending: number;
  p95LatencySeconds: number;
  processed1h: number;
  sloViolationCount1h: number;
};

const BILLING_PROVIDERS: BillingProvider[] = ["stripe", "razorpay", "paypal"];
const dunningSchedules: Record<BillingProvider, number[]> = {
  stripe: parseDunningSchedule(env.BILLING_DUNNING_SCHEDULE_STRIPE, [15 * 60, 60 * 60, 6 * 60 * 60, 24 * 60 * 60, 48 * 60 * 60]),
  razorpay: parseDunningSchedule(env.BILLING_DUNNING_SCHEDULE_RAZORPAY, [30 * 60, 2 * 60 * 60, 8 * 60 * 60, 24 * 60 * 60, 48 * 60 * 60]),
  paypal: parseDunningSchedule(env.BILLING_DUNNING_SCHEDULE_PAYPAL, [30 * 60, 4 * 60 * 60, 12 * 60 * 60, 24 * 60 * 60, 72 * 60 * 60]),
};
const reportRetrySchedule = parseDunningSchedule(env.BILLING_REPORT_RETRY_SCHEDULE_SECONDS, [60, 300, 900, 1800, 3600]);
const reportAckRequiredDestinations = parseAckDestinationList(env.BILLING_REPORT_ACK_REQUIRED_DESTINATIONS);
let webhookMetricsGeneratedAt = Date.now();
let webhookHealthByProvider: Record<BillingProvider, WebhookHealthSummary> = {
  stripe: { failed1h: 0, failed24h: 0, stalePending: 0, p95LatencySeconds: 0, processed1h: 0, sloViolationCount1h: 0 },
  razorpay: {
    failed1h: 0,
    failed24h: 0,
    stalePending: 0,
    p95LatencySeconds: 0,
    processed1h: 0,
    sloViolationCount1h: 0,
  },
  paypal: { failed1h: 0, failed24h: 0, stalePending: 0, p95LatencySeconds: 0, processed1h: 0, sloViolationCount1h: 0 },
};

function paypalBaseUrl(environment: "sandbox" | "live"): string {
  return environment === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
}

function basicAuth(user: string, password: string): string {
  return `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`;
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

function hmacSignature(secret: string, timestamp: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
}

function parseDunningSchedule(raw: string, fallback: number[]): number[] {
  const parsed = raw
    .split(",")
    .map((value) => Number.parseInt(value.trim(), 10))
    .filter((value) => Number.isFinite(value) && value > 0);
  return parsed.length > 0 ? parsed : fallback;
}

function parseAckDestinationList(raw: string): Set<AckRequiredDestination> {
  const values = raw
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter((item): item is AckRequiredDestination => item === "webhook" || item === "warehouse" || item === "s3");
  return new Set(values);
}

function destinationRequiresAck(destination: ReportDestination): boolean {
  return env.BILLING_REPORT_ACK_ENABLED && destination !== "inline" && reportAckRequiredDestinations.has(destination);
}

function parseNotificationChannels(input: unknown): DunningChannel[] {
  if (!Array.isArray(input)) {
    return ["webhook"];
  }
  const channels = input
    .map((value) => (typeof value === "string" ? value.trim().toLowerCase() : ""))
    .filter((value): value is DunningChannel => value === "webhook" || value === "email" || value === "slack");
  return channels.length > 0 ? Array.from(new Set(channels)) : ["webhook"];
}

function dunningDelaySeconds(provider: BillingProvider, stage: number): number {
  const schedule = dunningSchedules[provider];
  const index = Math.max(0, Math.min(stage - 1, schedule.length - 1));
  return schedule[index] ?? schedule[schedule.length - 1] ?? 24 * 60 * 60;
}

function reportRetryDelaySeconds(attempt: number): number {
  const index = Math.max(0, Math.min(attempt - 1, reportRetrySchedule.length - 1));
  return reportRetrySchedule[index] ?? reportRetrySchedule[reportRetrySchedule.length - 1] ?? 300;
}

function getS3Client(): S3Client {
  if (s3Client) return s3Client;
  if (!env.BILLING_REPORT_S3_BUCKET || !env.BILLING_REPORT_S3_ACCESS_KEY || !env.BILLING_REPORT_S3_SECRET_KEY) {
    throw new Error("S3 export destination requires BILLING_REPORT_S3_BUCKET and S3 credentials");
  }

  s3Client = new S3Client({
    region: env.BILLING_REPORT_S3_REGION,
    endpoint: env.BILLING_REPORT_S3_ENDPOINT,
    forcePathStyle: env.BILLING_REPORT_S3_FORCE_PATH_STYLE,
    credentials: {
      accessKeyId: env.BILLING_REPORT_S3_ACCESS_KEY,
      secretAccessKey: env.BILLING_REPORT_S3_SECRET_KEY,
    },
  });
  return s3Client;
}

function quantile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil(q * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))] ?? 0;
}

function renderMetrics(): string {
  const lines = [
    "# HELP fdt_billing_webhook_failed_events_1h Failed billing webhook events in the last hour.",
    "# TYPE fdt_billing_webhook_failed_events_1h gauge",
  ];

  for (const provider of BILLING_PROVIDERS) {
    lines.push(`fdt_billing_webhook_failed_events_1h{provider="${provider}"} ${webhookHealthByProvider[provider].failed1h}`);
  }

  lines.push("# HELP fdt_billing_webhook_failed_events_24h Failed billing webhook events in the last 24 hours.");
  lines.push("# TYPE fdt_billing_webhook_failed_events_24h gauge");
  for (const provider of BILLING_PROVIDERS) {
    lines.push(
      `fdt_billing_webhook_failed_events_24h{provider="${provider}"} ${webhookHealthByProvider[provider].failed24h}`,
    );
  }

  lines.push("# HELP fdt_billing_webhook_stale_pending Stale pending billing webhooks older than 5 minutes.");
  lines.push("# TYPE fdt_billing_webhook_stale_pending gauge");
  for (const provider of BILLING_PROVIDERS) {
    lines.push(`fdt_billing_webhook_stale_pending{provider="${provider}"} ${webhookHealthByProvider[provider].stalePending}`);
  }

  lines.push("# HELP fdt_billing_webhook_processing_latency_seconds_p95 p95 webhook processing latency over the last hour.");
  lines.push("# TYPE fdt_billing_webhook_processing_latency_seconds_p95 gauge");
  for (const provider of BILLING_PROVIDERS) {
    lines.push(
      `fdt_billing_webhook_processing_latency_seconds_p95{provider="${provider}"} ${webhookHealthByProvider[provider].p95LatencySeconds.toFixed(3)}`,
    );
  }

  lines.push(
    "# HELP fdt_billing_webhook_slo_violations_1h Number of webhooks in the last hour that breached the processing latency SLO.",
  );
  lines.push("# TYPE fdt_billing_webhook_slo_violations_1h gauge");
  for (const provider of BILLING_PROVIDERS) {
    lines.push(
      `fdt_billing_webhook_slo_violations_1h{provider="${provider}"} ${webhookHealthByProvider[provider].sloViolationCount1h}`,
    );
  }

  lines.push("# HELP fdt_billing_webhook_processed_events_1h Processed billing webhook events in the last hour.");
  lines.push("# TYPE fdt_billing_webhook_processed_events_1h gauge");
  for (const provider of BILLING_PROVIDERS) {
    lines.push(
      `fdt_billing_webhook_processed_events_1h{provider="${provider}"} ${webhookHealthByProvider[provider].processed1h}`,
    );
  }

  lines.push("# HELP fdt_billing_webhook_slo_seconds Billing webhook processing SLO threshold in seconds.");
  lines.push("# TYPE fdt_billing_webhook_slo_seconds gauge");
  lines.push(`fdt_billing_webhook_slo_seconds ${env.BILLING_WEBHOOK_SLO_SECONDS}`);
  lines.push("# HELP fdt_billing_runbook_replay_triggers_total Successful automated billing runbook replay triggers.");
  lines.push("# TYPE fdt_billing_runbook_replay_triggers_total counter");
  lines.push(`fdt_billing_runbook_replay_triggers_total ${runbookReplayTriggerTotal}`);
  lines.push("# HELP fdt_billing_runbook_replay_trigger_failures_total Failed billing runbook replay trigger attempts.");
  lines.push("# TYPE fdt_billing_runbook_replay_trigger_failures_total counter");
  lines.push(`fdt_billing_runbook_replay_trigger_failures_total ${runbookReplayTriggerFailureTotal}`);
  lines.push("# HELP fdt_billing_webhook_metrics_generated_at_seconds Last webhook metrics collection timestamp.");
  lines.push("# TYPE fdt_billing_webhook_metrics_generated_at_seconds gauge");
  lines.push(`fdt_billing_webhook_metrics_generated_at_seconds ${Math.floor(webhookMetricsGeneratedAt / 1000)}`);

  return `${lines.join("\n")}\n`;
}

function startMetricsServer(): void {
  const server = http.createServer((req, res) => {
    if (req.url === "/metrics") {
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(renderMetrics());
      return;
    }

    if (req.url === "/healthz") {
      res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
  });

  server.listen(env.BILLING_METRICS_PORT, "0.0.0.0", () => {
    console.log(`[worker-billing] metrics server listening on :${env.BILLING_METRICS_PORT}`);
  });
}

async function applyEntitlementsFromPlan(orgId: string, planId: string): Promise<void> {
  await db.query(
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

async function updateSubscription(input: {
  orgId: string;
  provider: BillingProvider;
  status: string;
  planId: string | null;
  stripeSubscriptionId?: string | null;
  razorpaySubscriptionId?: string | null;
  paypalSubscriptionId?: string | null;
}): Promise<void> {
  await db.query(
    `
      UPDATE subscriptions
      SET
        billing_provider = $1,
        status = $2,
        plan_id = COALESCE($3, plan_id),
        stripe_subscription_id = COALESCE($4, stripe_subscription_id),
        razorpay_subscription_id = COALESCE($5, razorpay_subscription_id),
        paypal_subscription_id = COALESCE($6, paypal_subscription_id),
        updated_at = NOW()
      WHERE org_id = $7
    `,
    [
      input.provider,
      input.status,
      input.planId,
      input.stripeSubscriptionId ?? null,
      input.razorpaySubscriptionId ?? null,
      input.paypalSubscriptionId ?? null,
      input.orgId,
    ],
  );
}

async function findPlanIdByExternalRef(provider: BillingProvider, externalRef: string): Promise<string | null> {
  const column =
    provider === "stripe" ? "stripe_price_id" : provider === "razorpay" ? "razorpay_plan_id" : "paypal_plan_id";
  const plan = await db.query<{ id: string }>(`SELECT id FROM plans WHERE ${column} = $1 LIMIT 1`, [externalRef]);
  return plan.rows[0]?.id ?? null;
}

async function getPaypalToken(): Promise<string> {
  if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) {
    throw new Error("PayPal credentials missing");
  }

  if (paypalTokenCache && Date.now() < paypalTokenCache.expiresAt - 60_000) {
    return paypalTokenCache.token;
  }

  const response = await fetch(`${paypalBaseUrl(env.PAYPAL_ENVIRONMENT)}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      authorization: basicAuth(env.PAYPAL_CLIENT_ID, env.PAYPAL_CLIENT_SECRET),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  if (!response.ok) {
    throw new Error(`PayPal auth failed with status ${response.status}`);
  }

  const payload = (await response.json()) as { access_token?: string; expires_in?: number };
  if (!payload.access_token) {
    throw new Error("PayPal auth missing access token");
  }

  paypalTokenCache = {
    token: payload.access_token,
    expiresAt: Date.now() + (payload.expires_in ?? 300) * 1000,
  };
  return payload.access_token;
}

async function syncSubscriptions(): Promise<void> {
  if (!loggedProviderState) {
    if (!stripe) {
      console.log("[worker-billing] STRIPE_SECRET_KEY missing, stripe sync disabled");
    }
    if (!razorpayEnabled) {
      console.log("[worker-billing] Razorpay credentials missing, razorpay sync disabled");
    }
    if (!paypalEnabled) {
      console.log("[worker-billing] PayPal credentials missing, paypal sync disabled");
    }
    loggedProviderState = true;
  }

  const subs = await db.query<{
    org_id: string;
    stripe_subscription_id: string | null;
    razorpay_subscription_id: string | null;
    paypal_subscription_id: string | null;
  }>(
    `
      SELECT org_id, stripe_subscription_id, razorpay_subscription_id, paypal_subscription_id
      FROM subscriptions
      WHERE stripe_subscription_id IS NOT NULL
         OR razorpay_subscription_id IS NOT NULL
         OR paypal_subscription_id IS NOT NULL
    `,
  );

  for (const sub of subs.rows) {
    if (stripe && sub.stripe_subscription_id) {
      try {
        const stripeSub = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
        const priceId = stripeSub.items.data[0]?.price.id;
        if (!priceId) continue;

        const planId = await findPlanIdByExternalRef("stripe", priceId);
        if (!planId) continue;

        await updateSubscription({
          orgId: sub.org_id,
          provider: "stripe",
          status: stripeSub.status,
          planId,
          stripeSubscriptionId: stripeSub.id,
        });
        await applyEntitlementsFromPlan(sub.org_id, planId);
      } catch (error) {
        console.error("[worker-billing] stripe sync failed", sub.org_id, error);
      }
    }

    if (razorpayEnabled && sub.razorpay_subscription_id) {
      try {
        const razorpayKeyId = env.RAZORPAY_KEY_ID;
        const razorpaySecret = env.RAZORPAY_KEY_SECRET;
        if (!razorpayKeyId || !razorpaySecret) continue;

        const response = await fetch(`https://api.razorpay.com/v1/subscriptions/${sub.razorpay_subscription_id}`, {
          headers: { authorization: basicAuth(razorpayKeyId, razorpaySecret) },
        });
        if (!response.ok) {
          console.error("[worker-billing] razorpay sync status", sub.org_id, response.status);
          continue;
        }

        const payload = (await response.json()) as { id?: string; status?: string; plan_id?: string };
        if (!payload.id || !payload.plan_id || !payload.status) continue;

        const planId = await findPlanIdByExternalRef("razorpay", payload.plan_id);
        await updateSubscription({
          orgId: sub.org_id,
          provider: "razorpay",
          status: payload.status,
          planId,
          razorpaySubscriptionId: payload.id,
        });
        if (planId && ["active", "authenticated"].includes(payload.status)) {
          await applyEntitlementsFromPlan(sub.org_id, planId);
        }
      } catch (error) {
        console.error("[worker-billing] razorpay sync failed", sub.org_id, error);
      }
    }

    if (paypalEnabled && sub.paypal_subscription_id) {
      try {
        const token = await getPaypalToken();
        const response = await fetch(
          `${paypalBaseUrl(env.PAYPAL_ENVIRONMENT)}/v1/billing/subscriptions/${sub.paypal_subscription_id}`,
          { headers: { authorization: `Bearer ${token}` } },
        );
        if (!response.ok) {
          console.error("[worker-billing] paypal sync status", sub.org_id, response.status);
          continue;
        }

        const payload = (await response.json()) as { id?: string; status?: string; plan_id?: string };
        if (!payload.id || !payload.status) continue;

        const planId = payload.plan_id ? await findPlanIdByExternalRef("paypal", payload.plan_id) : null;
        await updateSubscription({
          orgId: sub.org_id,
          provider: "paypal",
          status: payload.status,
          planId,
          paypalSubscriptionId: payload.id,
        });
        if (planId && ["ACTIVE", "APPROVAL_PENDING"].includes(payload.status)) {
          await applyEntitlementsFromPlan(sub.org_id, planId);
        }
      } catch (error) {
        console.error("[worker-billing] paypal sync failed", sub.org_id, error);
      }
    }
  }
}

async function cleanupWebhookEvents(): Promise<void> {
  const result = await db.query(
    `
      DELETE FROM billing_webhook_events
      WHERE received_at < NOW() - make_interval(days => $1::int)
    `,
    [env.BILLING_WEBHOOK_EVENT_RETENTION_DAYS],
  );

  if (result.rowCount && result.rowCount > 0) {
    console.log(
      `[worker-billing] pruned ${result.rowCount} webhook events older than ${env.BILLING_WEBHOOK_EVENT_RETENTION_DAYS}d`,
    );
  }
}

async function triggerRunbookReplay(provider: BillingProvider, eventClass: "payment" | "subscription"): Promise<void> {
  if (!env.API_BASE_URL || !env.BILLING_RUNBOOK_SIGNING_SECRET) return;

  const cooldownKey = `${provider}:${eventClass}`;
  const now = Date.now();
  const last = lastRunbookReplayAtByKey.get(cooldownKey) ?? 0;
  if (now - last < env.BILLING_RUNBOOK_REPLAY_COOLDOWN_SECONDS * 1000) {
    return;
  }

  const payload = JSON.stringify({
    provider,
    eventClass,
    limit: env.BILLING_RUNBOOK_REPLAY_LIMIT,
    force: false,
  });
  const timestamp = `${Math.floor(Date.now() / 1000)}`;
  const signature = hmacSignature(env.BILLING_RUNBOOK_SIGNING_SECRET, timestamp, payload);
  const response = await fetch(`${env.API_BASE_URL.replace(/\/+$/, "")}/v1/billing/runbook/replay`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-fdt-runbook-timestamp": timestamp,
      "x-fdt-runbook-signature": signature,
    },
    body: payload,
  });

  if (!response.ok) {
    throw new Error(`runbook replay failed with status ${response.status}`);
  }
  runbookReplayTriggerTotal += 1;
  lastRunbookReplayAtByKey.set(cooldownKey, now);
}

async function collectWebhookHealthSummary(): Promise<Record<BillingProvider, WebhookHealthSummary>> {
  const summary: Record<BillingProvider, WebhookHealthSummary> = {
    stripe: {
      failed1h: 0,
      failed24h: 0,
      stalePending: 0,
      p95LatencySeconds: 0,
      processed1h: 0,
      sloViolationCount1h: 0,
    },
    razorpay: {
      failed1h: 0,
      failed24h: 0,
      stalePending: 0,
      p95LatencySeconds: 0,
      processed1h: 0,
      sloViolationCount1h: 0,
    },
    paypal: {
      failed1h: 0,
      failed24h: 0,
      stalePending: 0,
      p95LatencySeconds: 0,
      processed1h: 0,
      sloViolationCount1h: 0,
    },
  };

  const countRows = await db.query<{
    provider: BillingProvider;
    failed_1h: string;
    failed_24h: string;
    stale_pending: string;
  }>(
    `
      SELECT
        provider,
        COUNT(*) FILTER (WHERE status = 'failed' AND received_at > NOW() - INTERVAL '1 hour')::text AS failed_1h,
        COUNT(*) FILTER (WHERE status = 'failed' AND received_at > NOW() - INTERVAL '24 hours')::text AS failed_24h,
        COUNT(*) FILTER (WHERE status = 'pending' AND received_at < NOW() - INTERVAL '5 minutes')::text AS stale_pending
      FROM billing_webhook_events
      GROUP BY provider
    `,
  );

  for (const row of countRows.rows) {
    summary[row.provider].failed1h = Number.parseInt(row.failed_1h, 10) || 0;
    summary[row.provider].failed24h = Number.parseInt(row.failed_24h, 10) || 0;
    summary[row.provider].stalePending = Number.parseInt(row.stale_pending, 10) || 0;
  }

  const latencyRows = await db.query<{ provider: BillingProvider; latency_seconds: number }>(
    `
      SELECT
        provider,
        GREATEST(0, EXTRACT(EPOCH FROM (processed_at - received_at)))::float8 AS latency_seconds
      FROM billing_webhook_events
      WHERE processed_at IS NOT NULL
        AND received_at > NOW() - INTERVAL '1 hour'
    `,
  );

  const latencyByProvider: Record<BillingProvider, number[]> = { stripe: [], razorpay: [], paypal: [] };
  for (const row of latencyRows.rows) {
    if (!Number.isFinite(row.latency_seconds)) {
      continue;
    }
    latencyByProvider[row.provider].push(row.latency_seconds);
  }

  for (const provider of BILLING_PROVIDERS) {
    const values = latencyByProvider[provider];
    summary[provider].processed1h = values.length;
    summary[provider].p95LatencySeconds = quantile(values, 0.95);
    summary[provider].sloViolationCount1h = values.reduce(
      (count, value) => count + (value > env.BILLING_WEBHOOK_SLO_SECONDS ? 1 : 0),
      0,
    );
  }

  return summary;
}

async function reportWebhookHealth(): Promise<void> {
  webhookHealthByProvider = await collectWebhookHealthSummary();
  webhookMetricsGeneratedAt = Date.now();

  for (const provider of BILLING_PROVIDERS) {
    const summary = webhookHealthByProvider[provider];
    const hasFailureSignal = summary.failed1h >= env.BILLING_WEBHOOK_FAILURE_WARN_THRESHOLD || summary.stalePending > 0;
    const hasSloSignal = summary.processed1h > 0 && summary.p95LatencySeconds > env.BILLING_WEBHOOK_SLO_SECONDS;
    if (!hasFailureSignal && !hasSloSignal) {
      continue;
    }

    const alertMessage = `[worker-billing] webhook health warning provider=${provider} failed_1h=${summary.failed1h} failed_24h=${summary.failed24h} stale_pending=${summary.stalePending} p95_latency_s=${summary.p95LatencySeconds.toFixed(3)} slo_seconds=${env.BILLING_WEBHOOK_SLO_SECONDS}`;
    console.warn(alertMessage);

    try {
      await triggerRunbookReplay(provider, "payment");
      if (summary.stalePending > 0 || hasSloSignal) {
        await triggerRunbookReplay(provider, "subscription");
      }
    } catch (error) {
      runbookReplayTriggerFailureTotal += 1;
      console.error("[worker-billing] runbook replay trigger failed", provider, error);
    }

    if (!env.BILLING_ALERT_WEBHOOK_URL) continue;

    const now = Date.now();
    const last = lastAlertAtByProvider[provider] ?? 0;
    if (now - last < env.BILLING_ALERT_COOLDOWN_SECONDS * 1000) {
      continue;
    }

    try {
      await fetch(env.BILLING_ALERT_WEBHOOK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          source: "worker-billing",
          severity: "warning",
          provider,
          failed1h: summary.failed1h,
          failed24h: summary.failed24h,
          stalePending: summary.stalePending,
          processed1h: summary.processed1h,
          p95LatencySeconds: summary.p95LatencySeconds,
          sloViolationCount1h: summary.sloViolationCount1h,
          threshold: env.BILLING_WEBHOOK_FAILURE_WARN_THRESHOLD,
          sloThresholdSeconds: env.BILLING_WEBHOOK_SLO_SECONDS,
          timestamp: new Date().toISOString(),
        }),
      });
      lastAlertAtByProvider[provider] = now;
    } catch (error) {
      console.error("[worker-billing] alert webhook delivery failed", error);
    }
  }
}

async function processDunningCases(): Promise<void> {
  const dueCases = await db.query<{
    id: string;
    org_id: string;
    provider: BillingProvider;
    subscription_ref: string;
    status: "open" | "recovered" | "closed";
    stage: number;
    retry_count: number;
    notification_count: number;
    notification_channels: unknown;
  }>(
    `
      SELECT
        id,
        org_id,
        provider,
        subscription_ref,
        status,
        stage,
        retry_count,
        notification_count,
        notification_channels
      FROM billing_dunning_cases
      WHERE status = 'open'
        AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
      ORDER BY next_attempt_at ASC NULLS FIRST, updated_at ASC
      LIMIT 200
    `,
  );

  async function sendDunningNotification(
    channel: DunningChannel,
    row: {
      id: string;
      org_id: string;
      provider: BillingProvider;
      subscription_ref: string;
    },
    stage: number,
  ): Promise<void> {
    const url =
      channel === "webhook"
        ? env.BILLING_DUNNING_NOTIFICATION_WEBHOOK_URL
        : channel === "email"
          ? env.BILLING_DUNNING_EMAIL_WEBHOOK_URL
          : env.BILLING_DUNNING_SLACK_WEBHOOK_URL;

    if (!url) {
      throw new Error(`dunning ${channel} channel URL is not configured`);
    }

    const payload = JSON.stringify({
      source: "worker-billing",
      type: "dunning.notice",
      channel,
      caseId: row.id,
      orgId: row.org_id,
      provider: row.provider,
      subscriptionRef: row.subscription_ref,
      stage,
      maxStage: env.BILLING_DUNNING_MAX_STAGE,
      timestamp: new Date().toISOString(),
    });

    const headers: Record<string, string> = { "content-type": "application/json" };
    if (env.BILLING_DUNNING_NOTIFICATION_SECRET) {
      const ts = `${Math.floor(Date.now() / 1000)}`;
      headers["x-fdt-timestamp"] = ts;
      headers["x-fdt-signature"] = hmacSignature(env.BILLING_DUNNING_NOTIFICATION_SECRET, ts, payload);
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: payload,
    });
    if (!response.ok) {
      throw new Error(`${channel} notification webhook returned ${response.status}`);
    }
  }

  for (const row of dueCases.rows) {
    if (row.stage >= env.BILLING_DUNNING_MAX_STAGE) {
      await db.query(
        `
          UPDATE billing_dunning_cases
          SET
            status = 'closed',
            next_attempt_at = NULL,
            last_attempt_at = NOW(),
            last_error = COALESCE(last_error, 'max dunning stage reached'),
            updated_at = NOW()
          WHERE id = $1
        `,
        [row.id],
      );
      continue;
    }

    const nextStage = row.stage + 1;
    const nextRetryAt = new Date(Date.now() + dunningDelaySeconds(row.provider, nextStage) * 1000);
    const channels = parseNotificationChannels(row.notification_channels);
    const deliveryErrors: string[] = [];
    let deliveredCount = 0;

    for (const channel of channels) {
      try {
        await sendDunningNotification(channel, row, nextStage);
        deliveredCount += 1;
      } catch (error) {
        deliveryErrors.push(String(error));
      }
    }

    const deliveryError = deliveryErrors.length > 0 ? deliveryErrors.join(" | ") : null;

    await db.query(
      `
        UPDATE billing_dunning_cases
        SET
          stage = $2,
          retry_count = retry_count + 1,
          next_attempt_at = $3,
          last_attempt_at = NOW(),
          notification_count = notification_count + $4,
          last_error = $5,
          updated_at = NOW()
        WHERE id = $1
      `,
      [row.id, nextStage, nextRetryAt, deliveredCount, deliveryError],
    );
  }
}

async function buildReportCsv(dataset: "finance_events" | "invoices" | "dunning", orgId: string | null): Promise<{ csv: string; rowCount: number }> {
  if (dataset === "finance_events") {
    const rows = await db.query(
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
        WHERE ($1::uuid IS NULL OR org_id = $1)
        ORDER BY created_at DESC
        LIMIT 10000
      `,
      [orgId],
    );
    return {
      csv: toCsv(
        [
          "id",
          "org_id",
          "provider",
          "event_type",
          "status",
          "external_id",
          "external_ref",
          "amount_cents",
          "currency",
          "reason",
          "error",
          "created_at",
          "updated_at",
        ],
        rows.rows as Array<Record<string, unknown>>,
      ),
      rowCount: rows.rows.length,
    };
  }

  if (dataset === "invoices") {
    const rows = await db.query(
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
        WHERE ($1::uuid IS NULL OR org_id = $1)
        ORDER BY created_at DESC
        LIMIT 10000
      `,
      [orgId],
    );
    return {
      csv: toCsv(
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
        rows.rows as Array<Record<string, unknown>>,
      ),
      rowCount: rows.rows.length,
    };
  }

  const rows = await db.query(
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
        notification_channels,
        last_error,
        latest_event_id,
        latest_event_type,
        created_at,
        updated_at
      FROM billing_dunning_cases
      WHERE ($1::uuid IS NULL OR org_id = $1)
      ORDER BY updated_at DESC
      LIMIT 10000
    `,
    [orgId],
  );
  return {
    csv: toCsv(
      [
        "id",
        "org_id",
        "provider",
        "subscription_ref",
        "status",
        "stage",
        "retry_count",
        "next_attempt_at",
        "last_attempt_at",
        "notification_count",
        "notification_channels",
        "last_error",
        "latest_event_id",
        "latest_event_type",
        "created_at",
        "updated_at",
      ],
      rows.rows as Array<Record<string, unknown>>,
    ),
    rowCount: rows.rows.length,
  };
}

async function processReportExports(): Promise<void> {
  await db.query(
    `
      UPDATE billing_report_exports
      SET
        status = 'pending',
        next_attempt_at = NOW(),
        error = COALESCE(error, 'stale running export reconciled'),
        last_delivery_status = 'stale_recovered',
        updated_at = NOW()
      WHERE status = 'running'
        AND started_at IS NOT NULL
        AND started_at <= NOW() - make_interval(secs => $1::int)
    `,
    [env.BILLING_REPORT_RUNNING_TIMEOUT_SECONDS],
  );

  await db.query(
    `
      UPDATE billing_report_exports
      SET
        delivery_ack_status = 'expired',
        delivery_ack_token_hash = NULL,
        delivery_ack_deadline = NULL,
        delivery_ack_metadata = COALESCE(delivery_ack_metadata, '{}'::jsonb) || jsonb_build_object(
          'expiredAt', NOW(),
          'reason', 'ack_timeout'
        ),
        last_delivery_status = CASE
          WHEN last_delivery_status = 'acknowledged' THEN last_delivery_status
          ELSE 'ack_expired'
        END,
        error = COALESCE(error, 'delivery acknowledgement expired'),
        updated_at = NOW()
      WHERE status = 'completed'
        AND delivery_ack_status = 'pending'
        AND delivery_ack_deadline IS NOT NULL
        AND delivery_ack_deadline <= NOW()
    `,
  );

  const jobs = await db.query<{
    id: string;
    org_id: string | null;
    dataset: "finance_events" | "invoices" | "dunning";
    destination: ReportDestination;
    sink_url: string | null;
    payload_json: unknown;
    attempts: number;
    max_attempts: number;
  }>(
    `
      SELECT id, org_id, dataset, destination, sink_url, payload_json, attempts, max_attempts
      FROM billing_report_exports
      WHERE status IN ('pending', 'failed')
        AND COALESCE(next_attempt_at, scheduled_for) <= NOW()
        AND attempts < max_attempts
      ORDER BY COALESCE(next_attempt_at, scheduled_for, created_at) ASC, created_at ASC
      LIMIT $1
    `,
    [env.BILLING_REPORT_EXPORT_BATCH_SIZE],
  );

  for (const job of jobs.rows) {
    await db.query(
      `
        UPDATE billing_report_exports
        SET
          status = 'running',
          started_at = NOW(),
          attempts = attempts + 1,
          last_delivery_status = 'running',
          updated_at = NOW()
        WHERE id = $1
      `,
      [job.id],
    );

    try {
      const report = await buildReportCsv(job.dataset, job.org_id ?? null);
      const contentHash = crypto.createHash("sha256").update(report.csv).digest("hex");
      const payloadJson = (job.payload_json ?? {}) as Record<string, unknown>;
      const ackRequired = destinationRequiresAck(job.destination);
      const ackToken = ackRequired ? crypto.randomBytes(24).toString("hex") : null;
      const ackTokenHash = ackToken ? crypto.createHash("sha256").update(ackToken).digest("hex") : null;
      const ackDeadline = ackRequired ? new Date(Date.now() + env.BILLING_REPORT_ACK_TTL_SECONDS * 1000) : null;
      const ackStatus: "pending" | "not_required" = ackRequired ? "pending" : "not_required";
      const ackMetadataBase = ackRequired
        ? {
            issuedAt: new Date().toISOString(),
            destination: job.destination,
          }
        : null;

      if (job.destination === "webhook" || job.destination === "warehouse") {
        const sinkUrl =
          job.sink_url ??
          (job.destination === "warehouse" ? env.BILLING_REPORT_WAREHOUSE_SINK_URL : env.BILLING_REPORT_DEFAULT_SINK_URL) ??
          env.BILLING_REPORT_DEFAULT_SINK_URL;
        if (!sinkUrl) {
          throw new Error(`report export destination ${job.destination} requires sink URL`);
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), env.BILLING_REPORT_WEBHOOK_TIMEOUT_SECONDS * 1000);
        try {
          if (job.destination === "webhook") {
            const headers: Record<string, string> = {
              "content-type": "text/csv; charset=utf-8",
              "x-fdt-report-id": job.id,
              "x-fdt-report-dataset": job.dataset,
            };
            if (ackRequired && ackToken && ackDeadline) {
              headers["x-fdt-report-ack-token"] = ackToken;
              headers["x-fdt-report-ack-deadline"] = ackDeadline.toISOString();
            }
            if (env.BILLING_REPORT_SIGNING_SECRET) {
              const ts = `${Math.floor(Date.now() / 1000)}`;
              headers["x-fdt-timestamp"] = ts;
              headers["x-fdt-signature"] = hmacSignature(env.BILLING_REPORT_SIGNING_SECRET, ts, report.csv);
            }

            const response = await fetch(sinkUrl, {
              method: "POST",
              headers,
              body: report.csv,
              signal: controller.signal,
            });
            if (!response.ok) {
              throw new Error(`report sink responded with status ${response.status}`);
            }
          } else {
            const body = JSON.stringify({
              reportId: job.id,
              dataset: job.dataset,
              format: "csv",
              rowCount: report.rowCount,
              contentHash,
              generatedAt: new Date().toISOString(),
              csvBase64: Buffer.from(report.csv).toString("base64"),
            });

            const headers: Record<string, string> = {
              "content-type": "application/json; charset=utf-8",
              "x-fdt-report-id": job.id,
              "x-fdt-report-dataset": job.dataset,
              "x-fdt-report-format": "csv",
            };
            if (ackRequired && ackToken && ackDeadline) {
              headers["x-fdt-report-ack-token"] = ackToken;
              headers["x-fdt-report-ack-deadline"] = ackDeadline.toISOString();
            }
            if (env.BILLING_REPORT_SIGNING_SECRET) {
              const ts = `${Math.floor(Date.now() / 1000)}`;
              headers["x-fdt-timestamp"] = ts;
              headers["x-fdt-signature"] = hmacSignature(env.BILLING_REPORT_SIGNING_SECRET, ts, body);
            }

            const response = await fetch(sinkUrl, {
              method: "POST",
              headers,
              body,
              signal: controller.signal,
            });
            if (!response.ok) {
              throw new Error(`warehouse sink responded with status ${response.status}`);
            }
          }
        } finally {
          clearTimeout(timeout);
        }

        await db.query(
          `
            UPDATE billing_report_exports
            SET
              status = 'completed',
              completed_at = NOW(),
              next_attempt_at = NULL,
              row_count = $2,
              content_hash = $3,
              content_text = NULL,
              sink_url = $4,
              delivery_ack_status = $5,
              delivery_ack_token_hash = $6,
              delivery_ack_deadline = $7,
              delivery_ack_at = NULL,
              delivery_ack_metadata = $8,
              last_delivery_status = CASE WHEN $5 = 'pending' THEN 'delivered_pending_ack' ELSE 'delivered' END,
              error = NULL,
              updated_at = NOW()
            WHERE id = $1
          `,
          [job.id, report.rowCount, contentHash, sinkUrl, ackStatus, ackTokenHash, ackDeadline, ackMetadataBase],
        );
      } else if (job.destination === "s3") {
        if (!env.BILLING_REPORT_S3_BUCKET) {
          throw new Error("BILLING_REPORT_S3_BUCKET is required for s3 report destination");
        }
        const keyFromPayload = typeof payloadJson.key === "string" ? payloadJson.key.trim() : "";
        const keyPrefixRaw = typeof payloadJson.keyPrefix === "string" ? payloadJson.keyPrefix : env.BILLING_REPORT_S3_KEY_PREFIX;
        const keyPrefix = keyPrefixRaw.endsWith("/") ? keyPrefixRaw : `${keyPrefixRaw}/`;
        const key = keyFromPayload || `${keyPrefix}${job.dataset}/${new Date().toISOString().slice(0, 10)}/${job.id}.csv`;

        const client = getS3Client();
        await client.send(
          new PutObjectCommand({
            Bucket: env.BILLING_REPORT_S3_BUCKET,
            Key: key,
            Body: report.csv,
            ContentType: "text/csv; charset=utf-8",
            Metadata:
              ackRequired && ackToken && ackDeadline
                ? {
                    fdt_report_ack_token: ackToken,
                    fdt_report_ack_deadline: ackDeadline.toISOString(),
                    fdt_report_id: job.id,
                    fdt_report_dataset: job.dataset,
                  }
                : undefined,
          }),
        );

        const sinkRef = `s3://${env.BILLING_REPORT_S3_BUCKET}/${key}`;
        const ackMetadata = ackMetadataBase
          ? {
              ...ackMetadataBase,
              sinkRef,
            }
          : null;
        await db.query(
          `
            UPDATE billing_report_exports
            SET
              status = 'completed',
              completed_at = NOW(),
              next_attempt_at = NULL,
              row_count = $2,
              content_hash = $3,
              content_text = NULL,
              sink_url = $4,
              delivery_ack_status = $5,
              delivery_ack_token_hash = $6,
              delivery_ack_deadline = $7,
              delivery_ack_at = NULL,
              delivery_ack_metadata = $8,
              last_delivery_status = CASE WHEN $5 = 'pending' THEN 'delivered_pending_ack' ELSE 'delivered' END,
              error = NULL,
              updated_at = NOW()
            WHERE id = $1
          `,
          [job.id, report.rowCount, contentHash, sinkRef, ackStatus, ackTokenHash, ackDeadline, ackMetadata],
        );
      } else {
        await db.query(
          `
            UPDATE billing_report_exports
            SET
              status = 'completed',
              completed_at = NOW(),
              next_attempt_at = NULL,
              row_count = $2,
              content_hash = $3,
              content_text = $4,
              delivery_ack_status = 'not_required',
              delivery_ack_token_hash = NULL,
              delivery_ack_deadline = NULL,
              delivery_ack_at = NULL,
              delivery_ack_metadata = NULL,
              last_delivery_status = 'delivered',
              error = NULL,
              updated_at = NOW()
            WHERE id = $1
          `,
          [job.id, report.rowCount, contentHash, report.csv],
        );
      }
    } catch (error) {
      const attemptNumber = job.attempts + 1;
      const errorText = String(error);
      if (attemptNumber >= job.max_attempts) {
        await db.query(
          `
            UPDATE billing_report_exports
            SET
              status = 'failed',
              completed_at = NOW(),
              next_attempt_at = NULL,
              delivery_ack_status = CASE WHEN delivery_ack_status = 'acknowledged' THEN delivery_ack_status ELSE 'expired' END,
              delivery_ack_token_hash = NULL,
              delivery_ack_deadline = NULL,
              last_delivery_status = 'exhausted',
              error = $2,
              updated_at = NOW()
            WHERE id = $1
          `,
          [job.id, errorText],
        );
      } else {
        const retryDelaySeconds = reportRetryDelaySeconds(attemptNumber);
        const nextAttemptAt = new Date(Date.now() + retryDelaySeconds * 1000);
        await db.query(
          `
            UPDATE billing_report_exports
            SET
              status = 'pending',
              completed_at = NULL,
              next_attempt_at = $2,
              delivery_ack_status = 'not_required',
              delivery_ack_token_hash = NULL,
              delivery_ack_deadline = NULL,
              delivery_ack_at = NULL,
              last_delivery_status = 'retry_scheduled',
              error = $3,
              updated_at = NOW()
            WHERE id = $1
          `,
          [job.id, nextAttemptAt, errorText],
        );
      }
    }
  }
}

async function loop(): Promise<void> {
  while (true) {
    try {
      await syncSubscriptions();
      await cleanupWebhookEvents();
      await reportWebhookHealth();
      await processDunningCases();
      await processReportExports();
    } catch (error) {
      console.error("[worker-billing] loop error", error);
    }

    await new Promise((resolve) => setTimeout(resolve, env.BILLING_SYNC_INTERVAL_SECONDS * 1000));
  }
}

startMetricsServer();

loop().catch((error) => {
  console.error("[worker-billing] fatal", error);
  process.exit(1);
});
