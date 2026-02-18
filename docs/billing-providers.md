# Billing Providers

## Scope
Control-plane billing now supports three checkout providers:
- Stripe
- Razorpay
- PayPal

## API checkout
- Endpoint: `POST /v1/billing/checkout-session`
- Auth: required
- Body:
  - `planCode`: `pro` | `team`
  - `provider`: `stripe` | `razorpay` | `paypal` (default: `stripe`)
  - `successUrl` (optional)
  - `cancelUrl` (optional)

If provider credentials or mapped plan IDs are missing, the API returns a mock checkout URL.

## Webhooks
- Stripe: `POST /v1/billing/webhook/stripe` (legacy alias: `POST /v1/billing/webhook`)
- Razorpay: `POST /v1/billing/webhook/razorpay`
- PayPal: `POST /v1/billing/webhook/paypal`

Webhook handlers map external subscription state to:
- `subscriptions.billing_provider`
- provider subscription IDs (`stripe_subscription_id`, `razorpay_subscription_id`, `paypal_subscription_id`)
- `subscriptions.status`
- `subscriptions.plan_id`

Entitlements are refreshed from `plans` when a paid plan is active.

## DB mapping
- `plans`:
  - `stripe_price_id`
  - `razorpay_plan_id`
  - `paypal_plan_id`
- `subscriptions`:
  - `billing_provider`
  - `external_customer_id`
  - `stripe_subscription_id`
  - `razorpay_subscription_id`
  - `paypal_subscription_id`

## Worker sync
`services/worker-billing` polls Stripe/Razorpay/PayPal subscriptions (when credentials exist) and reconciles status + plan entitlements to reduce drift from missed webhook deliveries.

## Env
- Stripe: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- Razorpay: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`
- PayPal: `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_ENVIRONMENT`
- Optional return URLs: `BILLING_SUCCESS_URL`, `BILLING_CANCEL_URL`
