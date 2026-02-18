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

## Finance operations
- Subscription state:
  - `GET /v1/billing/subscription`
- Cancel flow:
  - `POST /v1/billing/subscription/cancel`
  - body: `atPeriodEnd` (default `true`), `reason` (optional)
  - updates local subscription state and writes `billing_finance_events`.
- Refund flow:
  - `POST /v1/billing/refund`
  - body: `paymentId`, `amountCents` (optional), `currency` (optional), `reason` (optional)
  - uses provider APIs when keys are present, otherwise safe mock mode.
- User finance history:
  - `GET /v1/billing/finance-events`

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

## Webhook hardening
- Signature verification now uses raw request body bytes for Stripe and Razorpay.
- PayPal signature verification uses PayPal verify-webhook API path.
- Replay/idempotency protection is backed by `billing_webhook_events` with unique `(provider, event_id)`.
- Duplicate event deliveries return success and do not re-apply entitlements.
- `BILLING_WEBHOOK_MAX_AGE_SECONDS` enforces max age for signed webhook events.
- Worker cleanup/ops:
  - `services/worker-billing` prunes old webhook events by retention policy.
  - worker emits warning logs when failed/stale pending events cross thresholds.

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
- `billing_finance_events`:
  - finance op trail (`subscription_cancel`, `refund`, `payment_failed`, `payment_recovered`)
  - provider status (`processed`, `failed`, `mocked`)
  - external references, amount/currency, payload/result snapshots

## Worker sync
`services/worker-billing` polls Stripe/Razorpay/PayPal subscriptions (when credentials exist) and reconciles status + plan entitlements to reduce drift from missed webhook deliveries.

## Env
- Stripe: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- Razorpay: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`
- PayPal: `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_ENVIRONMENT`
- Optional return URLs: `BILLING_SUCCESS_URL`, `BILLING_CANCEL_URL`
- Webhook replay window: `BILLING_WEBHOOK_MAX_AGE_SECONDS`
- Event retention days: `BILLING_WEBHOOK_EVENT_RETENTION_DAYS`
- Warning threshold: `BILLING_WEBHOOK_FAILURE_WARN_THRESHOLD`

## Admin operations
- Admin API:
  - `GET /v1/admin/billing-webhooks?provider=&status=&limit=`
  - `POST /v1/admin/billing-webhooks/:id/replay`
  - `POST /v1/admin/billing-webhooks/reconcile`
  - `GET /v1/admin/billing-finance-events?provider=&type=&status=&orgId=&limit=`
- Admin UI:
  - `apps/console-web/app/admin/billing-webhooks/page.tsx`
  - `apps/console-web/app/admin/billing-finance-events/page.tsx`

## Replay and reconciliation
- Failed webhook events can be replayed from stored payloads.
- Reconcile endpoint can batch replay failed events by provider/limit.
- Replay metadata is tracked in `billing_webhook_events.replay_count`.

## External alerting
- Worker can send provider-scoped warning alerts to a webhook:
  - `BILLING_ALERT_WEBHOOK_URL`
  - `BILLING_ALERT_COOLDOWN_SECONDS`
