import { z } from "zod";

export const planEntitlementsSchema = z.object({
  maxTunnels: z.number().int().nonnegative(),
  maxConcurrentConns: z.number().int().nonnegative(),
  reservedDomains: z.boolean(),
  customDomains: z.boolean(),
  ipAllowlist: z.boolean(),
  retentionHours: z.number().int().positive()
});

export type PlanEntitlements = z.infer<typeof planEntitlementsSchema>;

export const tunnelRouteSchema = z.object({
  id: z.string().uuid(),
  protocol: z.enum(["http", "tcp", "https"]),
  hostname: z.string().optional(),
  pathPrefix: z.string().optional(),
  target: z.string(),
  inspect: z.boolean()
});

export type TunnelRoute = z.infer<typeof tunnelRouteSchema>;

export const apiEnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  RAZORPAY_KEY_ID: z.string().optional(),
  RAZORPAY_KEY_SECRET: z.string().optional(),
  RAZORPAY_WEBHOOK_SECRET: z.string().optional(),
  PAYPAL_CLIENT_ID: z.string().optional(),
  PAYPAL_CLIENT_SECRET: z.string().optional(),
  PAYPAL_WEBHOOK_ID: z.string().optional(),
  PAYPAL_ENVIRONMENT: z.enum(["sandbox", "live"]).optional().default("sandbox"),
  BILLING_SUCCESS_URL: z.string().url().optional().default("https://console.yourdomain.com/billing/success"),
  BILLING_CANCEL_URL: z.string().url().optional().default("https://console.yourdomain.com/billing/cancel"),
  BILLING_WEBHOOK_MAX_AGE_SECONDS: z.coerce.number().int().positive().optional().default(86400),
  BILLING_RUNBOOK_SIGNING_SECRET: z.string().optional(),
  BILLING_RUNBOOK_MAX_AGE_SECONDS: z.coerce.number().int().positive().optional().default(300),
  CERT_EVENT_INGEST_TOKEN: z.string().optional(),
  CERT_EVENT_SOURCE_KEYS: z.string().optional(),
  CERT_EVENT_MAX_AGE_SECONDS: z.coerce.number().int().positive().optional().default(300),
  CERT_EVENT_REQUIRE_PROVENANCE: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value.trim().toLowerCase() === "true"),
  BASE_DOMAIN: z.string().default("tunnel.yourdomain.com"),
  ALLOWED_REGIONS: z.string().optional().default("us"),
  RELAY_HEARTBEAT_TOKEN: z.string().optional(),
  RELAY_HEARTBEAT_MAX_AGE_SECONDS: z.coerce.number().int().positive().optional().default(90),
  AGENT_JWT_SECRET: z.string().min(32),
  DOMAIN_VERIFY_STRICT: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value.trim().toLowerCase() === "true"),
  S3_ENDPOINT: z.string().optional(),
  S3_ACCESS_KEY: z.string().optional(),
  S3_SECRET_KEY: z.string().optional(),
  S3_BUCKET: z.string().optional(),
  CLOUDFLARE_API_TOKEN: z.string().optional(),
  CLOUDFLARE_ZONE_ID: z.string().optional()
});

export type ApiEnv = z.infer<typeof apiEnvSchema>;

export const relayEnvSchema = z.object({
  RELAY_HTTP_PORT: z.coerce.number().default(8080),
  RELAY_CONTROL_PORT: z.coerce.number().default(8081),
  RELAY_BASE_DOMAIN: z.string().default("tunnel.yourdomain.com"),
  RELAY_AGENT_JWT_SECRET: z.string().min(32),
  RELAY_REGION: z.string().default("us"),
  RELAY_EDGE_POOL: z.string().optional().default("us=us-edge-1|us-edge-2|us-edge-3"),
  RELAY_HEARTBEAT_API_URL: z.string().url().optional(),
  RELAY_HEARTBEAT_TOKEN: z.string().optional(),
  RELAY_HEARTBEAT_INTERVAL_SECONDS: z.coerce.number().int().positive().default(15),
  RELAY_ID: z.string().optional(),
});

export type RelayEnv = z.infer<typeof relayEnvSchema>;
