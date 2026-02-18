import { FastifyPluginAsync } from "fastify";
import Stripe from "stripe";
import { z } from "zod";

export const billingRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    "/checkout-session",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const body = z.object({ planCode: z.enum(["pro", "team"]) }).parse(request.body);

      const plan = await app.db.query<{ id: string; stripe_price_id: string | null }>(
        `SELECT id, stripe_price_id FROM plans WHERE code = $1 LIMIT 1`,
        [body.planCode],
      );
      const target = plan.rows[0];
      if (!target) {
        return reply.code(404).send({ message: "Plan not found" });
      }

      if (!app.env.STRIPE_SECRET_KEY || !target.stripe_price_id) {
        return {
          mode: "mock",
          checkoutUrl: `https://billing.mock/checkout?plan=${body.planCode}`,
        };
      }

      const stripe = new Stripe(app.env.STRIPE_SECRET_KEY);
      const session = await stripe.checkout.sessions.create({
        mode: "subscription",
        line_items: [{ price: target.stripe_price_id, quantity: 1 }],
        success_url: "https://console.yourdomain.com/billing/success",
        cancel_url: "https://console.yourdomain.com/billing/cancel",
        client_reference_id: request.authUser!.orgId,
      });

      return { mode: "stripe", checkoutUrl: session.url };
    },
  );

  app.post("/webhook", async (request, reply) => {
    if (!app.env.STRIPE_SECRET_KEY || !app.env.STRIPE_WEBHOOK_SECRET) {
      return { ok: true, ignored: true };
    }

    const signature = request.headers["stripe-signature"];
    if (!signature) {
      return reply.code(400).send({ message: "Missing stripe signature" });
    }

    const stripe = new Stripe(app.env.STRIPE_SECRET_KEY);
    let event: Stripe.Event;

    try {
      event = stripe.webhooks.constructEvent(
        JSON.stringify(request.body ?? {}),
        signature,
        app.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (error) {
      return reply.code(400).send({ message: `Invalid webhook signature: ${String(error)}` });
    }

    if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.created") {
      const sub = event.data.object as Stripe.Subscription;
      const orgId = sub.metadata.orgId;
      const priceId = sub.items.data[0]?.price.id;
      if (orgId && priceId) {
        const plan = await app.db.query<{ id: string }>(`SELECT id FROM plans WHERE stripe_price_id = $1 LIMIT 1`, [priceId]);
        if (plan.rowCount) {
          const planId = plan.rows[0].id;
          await app.db.query(
            `UPDATE subscriptions SET stripe_subscription_id = $1, status = $2, plan_id = $3, updated_at = NOW() WHERE org_id = $4`,
            [sub.id, sub.status, planId, orgId],
          );

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
      }
    }

    return { ok: true };
  });
};
