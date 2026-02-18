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
