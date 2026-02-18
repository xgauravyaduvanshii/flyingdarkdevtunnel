-- Multi-provider billing support (Stripe, Razorpay, PayPal)

ALTER TABLE plans
  ADD COLUMN IF NOT EXISTS razorpay_plan_id TEXT;

ALTER TABLE plans
  ADD COLUMN IF NOT EXISTS paypal_plan_id TEXT;

ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS billing_provider TEXT NOT NULL DEFAULT 'stripe';

ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_billing_provider_check;

ALTER TABLE subscriptions
  ADD CONSTRAINT subscriptions_billing_provider_check
  CHECK (billing_provider IN ('stripe', 'razorpay', 'paypal'));

ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS external_customer_id TEXT;

ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS razorpay_subscription_id TEXT;

ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS paypal_subscription_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription_id
ON subscriptions(stripe_subscription_id)
WHERE stripe_subscription_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_razorpay_subscription_id
ON subscriptions(razorpay_subscription_id)
WHERE razorpay_subscription_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_paypal_subscription_id
ON subscriptions(paypal_subscription_id)
WHERE paypal_subscription_id IS NOT NULL;
