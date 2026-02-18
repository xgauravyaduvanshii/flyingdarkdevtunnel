import dotenv from "dotenv";
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
  BILLING_ALERT_WEBHOOK_URL: z.string().url().optional(),
  BILLING_ALERT_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(600),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });
const stripe = env.STRIPE_SECRET_KEY ? new Stripe(env.STRIPE_SECRET_KEY) : null;
const razorpayEnabled = Boolean(env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET);
const paypalEnabled = Boolean(env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET);
let paypalTokenCache: { token: string; expiresAt: number } | null = null;
let loggedProviderState = false;
const lastAlertAtByProvider: Partial<Record<"stripe" | "razorpay" | "paypal", number>> = {};

function paypalBaseUrl(environment: "sandbox" | "live"): string {
  return environment === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
}

function basicAuth(user: string, password: string): string {
  return `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`;
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
  provider: "stripe" | "razorpay" | "paypal";
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

async function findPlanIdByExternalRef(
  provider: "stripe" | "razorpay" | "paypal",
  externalRef: string,
): Promise<string | null> {
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
        if (!priceId) {
          continue;
        }

        const planId = await findPlanIdByExternalRef("stripe", priceId);
        if (!planId) {
          continue;
        }

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
        if (!razorpayKeyId || !razorpaySecret) {
          continue;
        }
        const response = await fetch(`https://api.razorpay.com/v1/subscriptions/${sub.razorpay_subscription_id}`, {
          headers: {
            authorization: basicAuth(razorpayKeyId, razorpaySecret),
          },
        });
        if (!response.ok) {
          console.error("[worker-billing] razorpay sync status", sub.org_id, response.status);
          continue;
        }

        const payload = (await response.json()) as { id?: string; status?: string; plan_id?: string };
        if (!payload.id || !payload.plan_id || !payload.status) {
          continue;
        }

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
          {
            headers: { authorization: `Bearer ${token}` },
          },
        );
        if (!response.ok) {
          console.error("[worker-billing] paypal sync status", sub.org_id, response.status);
          continue;
        }

        const payload = (await response.json()) as { id?: string; status?: string; plan_id?: string };
        if (!payload.id || !payload.status) {
          continue;
        }

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

async function reportWebhookHealth(): Promise<void> {
  const stats = await db.query<{
    provider: "stripe" | "razorpay" | "paypal";
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

  for (const row of stats.rows) {
    const failed1h = Number.parseInt(row.failed_1h, 10) || 0;
    const failed24h = Number.parseInt(row.failed_24h, 10) || 0;
    const stalePending = Number.parseInt(row.stale_pending, 10) || 0;

    if (failed1h < env.BILLING_WEBHOOK_FAILURE_WARN_THRESHOLD && stalePending === 0) {
      continue;
    }

    const alertMessage = `[worker-billing] webhook health warning provider=${row.provider} failed_1h=${failed1h} failed_24h=${failed24h} stale_pending=${stalePending}`;
    console.warn(alertMessage);

    if (!env.BILLING_ALERT_WEBHOOK_URL) {
      continue;
    }

    const now = Date.now();
    const last = lastAlertAtByProvider[row.provider] ?? 0;
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
          provider: row.provider,
          failed1h,
          failed24h,
          stalePending,
          threshold: env.BILLING_WEBHOOK_FAILURE_WARN_THRESHOLD,
          timestamp: new Date().toISOString(),
        }),
      });
      lastAlertAtByProvider[row.provider] = now;
    } catch (error) {
      console.error("[worker-billing] alert webhook delivery failed", error);
    }
  }
}

async function loop(): Promise<void> {
  while (true) {
    await syncSubscriptions();
    await cleanupWebhookEvents();
    await reportWebhookHealth();
    await new Promise((resolve) => setTimeout(resolve, env.BILLING_SYNC_INTERVAL_SECONDS * 1000));
  }
}

loop().catch((error) => {
  console.error("[worker-billing] fatal", error);
  process.exit(1);
});
