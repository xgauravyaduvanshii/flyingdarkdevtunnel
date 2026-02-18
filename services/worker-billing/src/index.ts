import dotenv from "dotenv";
import { Pool } from "pg";
import Stripe from "stripe";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  STRIPE_SECRET_KEY: z.string().optional(),
  BILLING_SYNC_INTERVAL_SECONDS: z.coerce.number().int().positive().default(60),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });
const stripe = env.STRIPE_SECRET_KEY ? new Stripe(env.STRIPE_SECRET_KEY) : null;

async function syncSubscriptions(): Promise<void> {
  if (!stripe) {
    console.log("[worker-billing] STRIPE_SECRET_KEY missing, running in no-op mode");
    return;
  }

  const subs = await db.query<{
    org_id: string;
    stripe_subscription_id: string | null;
  }>(`SELECT org_id, stripe_subscription_id FROM subscriptions WHERE stripe_subscription_id IS NOT NULL`);

  for (const sub of subs.rows) {
    if (!sub.stripe_subscription_id) continue;
    try {
      const stripeSub = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
      const priceId = stripeSub.items.data[0]?.price.id;
      if (!priceId) continue;

      const plan = await db.query<{ id: string }>(`SELECT id FROM plans WHERE stripe_price_id = $1 LIMIT 1`, [priceId]);
      if (!plan.rowCount) continue;

      const planId = plan.rows[0].id;

      await db.query(`UPDATE subscriptions SET status = $1, plan_id = $2, updated_at = NOW() WHERE org_id = $3`, [
        stripeSub.status,
        planId,
        sub.org_id,
      ]);

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
        [sub.org_id, planId],
      );
    } catch (error) {
      console.error("[worker-billing] sync failed", sub.org_id, error);
    }
  }
}

async function loop(): Promise<void> {
  while (true) {
    await syncSubscriptions();
    await new Promise((resolve) => setTimeout(resolve, env.BILLING_SYNC_INTERVAL_SECONDS * 1000));
  }
}

loop().catch((error) => {
  console.error("[worker-billing] fatal", error);
  process.exit(1);
});
