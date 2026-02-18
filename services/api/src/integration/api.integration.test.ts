import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../app.js";

const defaults: Record<string, string> = {
  NODE_ENV: "test",
  API_PORT: "4000",
  DATABASE_URL: "postgres://postgres:postgres@127.0.0.1:5432/fdt",
  REDIS_URL: "redis://127.0.0.1:6379",
  JWT_SECRET: "12345678901234567890123456789012",
  JWT_REFRESH_SECRET: "12345678901234567890123456789012",
  AGENT_JWT_SECRET: "12345678901234567890123456789012",
  BASE_DOMAIN: "tunnel.yourdomain.com",
  DOMAIN_VERIFY_STRICT: "false",
};

for (const [key, value] of Object.entries(defaults)) {
  if (!process.env[key]) {
    process.env[key] = value;
  }
}

describe("api integration", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  }, 30_000);

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it("supports paid custom domain routing and enriched agent token claims", async () => {
    const email = `integration-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as {
      accessToken: string;
      authtoken: string;
    };

    const accessToken = registerBody.accessToken;

    const usersRes = await app.inject({
      method: "GET",
      url: "/v1/admin/users",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(usersRes.statusCode).toBe(200);

    const usersBody = usersRes.json() as { users: Array<{ id: string; email: string }> };
    const me = usersBody.users.find((user) => user.email === email);
    expect(me).toBeTruthy();

    const promoteRes = await app.inject({
      method: "PATCH",
      url: `/v1/admin/users/${me!.id}/plan`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { planCode: "pro" },
    });
    expect(promoteRes.statusCode).toBe(200);

    const tunnelRes = await app.inject({
      method: "POST",
      url: "/v1/tunnels",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        name: "integration-http",
        protocol: "http",
        localAddr: "http://localhost:3000",
        inspect: true,
        basicAuthUser: "demo",
        basicAuthPassword: "secret",
        ipAllowlist: ["127.0.0.1/32"],
      },
    });
    expect(tunnelRes.statusCode).toBe(201);
    const tunnelBody = tunnelRes.json() as { id: string; subdomain: string | null };

    const domainName = `api-${randomUUID().slice(0, 8)}.example.com`;

    const customDomainRes = await app.inject({
      method: "POST",
      url: "/v1/domains/custom",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { domain: domainName, tlsMode: "termination" },
    });
    expect(customDomainRes.statusCode).toBe(201);
    const customDomainBody = customDomainRes.json() as { id: string; verificationHost: string };
    expect(customDomainBody.verificationHost).toContain("_fdt-verify");

    const verifyRes = await app.inject({
      method: "POST",
      url: `/v1/domains/custom/${customDomainBody.id}/verify`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    });
    expect(verifyRes.statusCode).toBe(200);

    const routeRes = await app.inject({
      method: "POST",
      url: `/v1/domains/custom/${customDomainBody.id}/route`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { tunnelId: tunnelBody.id, tlsMode: "termination" },
    });
    expect(routeRes.statusCode).toBe(200);

    const startRes = await app.inject({
      method: "POST",
      url: `/v1/tunnels/${tunnelBody.id}/start`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    });
    expect(startRes.statusCode).toBe(200);
    const startBody = startRes.json() as {
      agentToken: string;
      hosts: string[];
      tlsModes: Record<string, "termination" | "passthrough">;
    };

    const claims = jwt.verify(startBody.agentToken, process.env.AGENT_JWT_SECRET!) as {
      hosts: string[];
      tlsModes: Record<string, "termination" | "passthrough">;
      basicAuthUser: string;
      basicAuthPassword: string;
      ipAllowlist: string[];
      tokenType: string;
    };

    expect(claims.tokenType).toBe("agent");
    expect(claims.basicAuthUser).toBe("demo");
    expect(claims.basicAuthPassword).toBe("secret");
    expect(claims.ipAllowlist).toContain("127.0.0.1/32");
    expect(claims.hosts).toContain(domainName);
    expect(claims.hosts.some((host) => host.endsWith(`.${process.env.BASE_DOMAIN}`))).toBe(true);
    expect(claims.tlsModes[domainName]).toBe("termination");
    expect(startBody.hosts).toContain(domainName);

    const adminDomainsRes = await app.inject({
      method: "GET",
      url: "/v1/admin/domains",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminDomainsRes.statusCode).toBe(200);
    const adminDomainsBody = adminDomainsRes.json() as {
      domains: Array<{ domain: string; tls_status: string; tls_mode: string }>;
    };
    const adminDomain = adminDomainsBody.domains.find((item) => item.domain === domainName);
    expect(adminDomain).toBeTruthy();
    expect(adminDomain?.tls_mode).toBe("termination");
    expect(adminDomain?.tls_status).toBe("pending_issue");
  }, 30_000);

  it("returns provider-specific mock checkout URLs when provider credentials are missing", async () => {
    const email = `integration-billing-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Billing Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as { accessToken: string };
    const accessToken = registerBody.accessToken;

    const providers = ["stripe", "razorpay", "paypal"] as const;
    for (const provider of providers) {
      const checkoutRes = await app.inject({
        method: "POST",
        url: "/v1/billing/checkout-session",
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { planCode: "pro", provider },
      });
      expect(checkoutRes.statusCode).toBe(200);
      const checkoutBody = checkoutRes.json() as { mode: string; provider: string; checkoutUrl: string };
      expect(checkoutBody.mode).toBe("mock");
      expect(checkoutBody.provider).toBe(provider);
      expect(checkoutBody.checkoutUrl).toContain(`provider=${provider}`);
    }
  }, 30_000);

  it("supports mock subscription cancel + refund finance operations with audit visibility", async () => {
    const email = `integration-finops-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Finance Org" },
    });
    expect(registerRes.statusCode).toBe(201);

    const registerBody = registerRes.json() as { accessToken: string };
    const accessToken = registerBody.accessToken;
    const accessClaims = jwt.verify(accessToken, process.env.JWT_SECRET!) as { orgId: string };
    const orgId = accessClaims.orgId;

    await app.db.query(
      `
        UPDATE subscriptions
        SET
          billing_provider = 'stripe',
          status = 'active',
          plan_id = '22222222-2222-2222-2222-222222222222',
          stripe_subscription_id = $2
        WHERE org_id = $1
      `,
      [orgId, `sub_mock_finops_${randomUUID().replace(/-/g, "")}`],
    );
    await app.db.query(
      `
        UPDATE entitlements
        SET
          plan_id = '22222222-2222-2222-2222-222222222222',
          max_tunnels = 25,
          max_concurrent_conns = 500,
          reserved_domains = TRUE,
          custom_domains = TRUE,
          ip_allowlist = TRUE,
          retention_hours = 168,
          updated_at = NOW()
        WHERE org_id = $1
      `,
      [orgId],
    );

    const subscriptionRes = await app.inject({
      method: "GET",
      url: "/v1/billing/subscription",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(subscriptionRes.statusCode).toBe(200);
    const subscriptionBody = subscriptionRes.json() as {
      subscription: { provider: string; status: string; planCode: string | null };
    };
    expect(subscriptionBody.subscription.provider).toBe("stripe");
    expect(subscriptionBody.subscription.planCode).toBe("pro");

    const cancelRes = await app.inject({
      method: "POST",
      url: "/v1/billing/subscription/cancel",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { atPeriodEnd: false, reason: "integration cancel now" },
    });
    expect(cancelRes.statusCode).toBe(200);
    const cancelBody = cancelRes.json() as {
      ok: boolean;
      mode: "mock" | "provider";
      status: string;
    };
    expect(cancelBody.ok).toBe(true);
    expect(cancelBody.mode).toBe("mock");
    expect(cancelBody.status).toBe("canceled");

    const refundRes = await app.inject({
      method: "POST",
      url: "/v1/billing/refund",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { paymentId: "pi_mock_payment_123", amountCents: 1200, reason: "integration refund request" },
    });
    expect(refundRes.statusCode).toBe(200);
    const refundBody = refundRes.json() as {
      ok: boolean;
      mode: "mock" | "provider";
      refundId: string | null;
    };
    expect(refundBody.ok).toBe(true);
    expect(refundBody.mode).toBe("mock");
    expect(refundBody.refundId).toContain("mock_refund_");

    const financeEventsRes = await app.inject({
      method: "GET",
      url: "/v1/billing/finance-events?limit=20",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(financeEventsRes.statusCode).toBe(200);
    const financeEventsBody = financeEventsRes.json() as {
      events: Array<{ event_type: string; status: string }>;
    };
    expect(financeEventsBody.events.some((event) => event.event_type === "subscription_cancel")).toBe(true);
    expect(financeEventsBody.events.some((event) => event.event_type === "refund")).toBe(true);

    const adminFinanceRes = await app.inject({
      method: "GET",
      url: "/v1/admin/billing-finance-events?limit=100",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminFinanceRes.statusCode).toBe(200);
    const adminFinanceBody = adminFinanceRes.json() as {
      events: Array<{ org_id: string; event_type: string }>;
      stats: { total: string; refunds: string; cancellations: string };
    };
    expect(adminFinanceBody.events.some((event) => event.org_id === orgId && event.event_type === "refund")).toBe(true);
    expect(Number.parseInt(adminFinanceBody.stats.total, 10)).toBeGreaterThan(0);
    expect(Number.parseInt(adminFinanceBody.stats.refunds, 10)).toBeGreaterThan(0);
    expect(Number.parseInt(adminFinanceBody.stats.cancellations, 10)).toBeGreaterThan(0);
  }, 30_000);

  it("lists and exports invoice and tax records for user and admin scopes", async () => {
    const email = `integration-invoice-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Invoice Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as { accessToken: string };
    const accessToken = registerBody.accessToken;
    const accessClaims = jwt.verify(accessToken, process.env.JWT_SECRET!) as { orgId: string };
    const orgId = accessClaims.orgId;

    const otherRegisterRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email: `integration-invoice-other-${randomUUID()}@example.com`, password, orgName: "Other Org" },
    });
    expect(otherRegisterRes.statusCode).toBe(201);
    const otherClaims = jwt.verify((otherRegisterRes.json() as { accessToken: string }).accessToken, process.env.JWT_SECRET!) as {
      orgId: string;
    };
    const otherOrgId = otherClaims.orgId;

    const invoiceId = randomUUID();
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
          issued_at
        )
        VALUES
          ($1, $2, 'stripe', $3, $4, $5, 'paid', 'USD', 1000, 180, 1180, 0, 1180, NOW()),
          ($6, $7, 'stripe', $8, $9, $10, 'open', 'USD', 500, 90, 590, 590, 0, NOW())
      `,
      [
        invoiceId,
        orgId,
        `in_main_${randomUUID().replace(/-/g, "")}`,
        `sub_main_${randomUUID().replace(/-/g, "")}`,
        `pi_main_${randomUUID().replace(/-/g, "")}`,
        randomUUID(),
        otherOrgId,
        `in_other_${randomUUID().replace(/-/g, "")}`,
        `sub_other_${randomUUID().replace(/-/g, "")}`,
        `pi_other_${randomUUID().replace(/-/g, "")}`,
      ],
    );

    const taxId = randomUUID();
    await app.db.query(
      `
        INSERT INTO billing_tax_records (id, invoice_id, org_id, provider, tax_type, jurisdiction, rate_bps, amount_cents, currency)
        VALUES ($1, $2, $3, 'stripe', 'provider_total_tax', 'unknown', 1800, 180, 'USD')
      `,
      [taxId, invoiceId, orgId],
    );

    const listRes = await app.inject({
      method: "GET",
      url: "/v1/billing/invoices?includeTax=true&limit=20",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(listRes.statusCode).toBe(200);
    const listBody = listRes.json() as {
      invoices: Array<{ id: string; org_id: string; tax_cents: string | null }>;
      taxRecords: Array<{ invoice_id: string; amount_cents: string }>;
    };
    expect(listBody.invoices.some((row) => row.id === invoiceId && row.org_id === orgId)).toBe(true);
    expect(listBody.invoices.some((row) => row.org_id === otherOrgId)).toBe(false);
    expect(listBody.taxRecords.some((row) => row.invoice_id === invoiceId)).toBe(true);

    const exportUserRes = await app.inject({
      method: "GET",
      url: "/v1/billing/invoices/export?limit=20",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(exportUserRes.statusCode).toBe(200);
    expect(String(exportUserRes.headers["content-type"])).toContain("text/csv");
    expect(exportUserRes.body).toContain("provider_invoice_id");
    expect(exportUserRes.body).toContain(invoiceId);

    const adminListRes = await app.inject({
      method: "GET",
      url: `/v1/admin/billing-invoices?orgId=${orgId}&includeTax=true&limit=50`,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminListRes.statusCode).toBe(200);
    const adminListBody = adminListRes.json() as {
      invoices: Array<{ org_id: string; id: string }>;
      taxRecords: Array<{ invoice_id: string }>;
      stats: { total: string; total_tax_cents: string };
    };
    expect(adminListBody.invoices.every((row) => row.org_id === orgId)).toBe(true);
    expect(adminListBody.taxRecords.some((row) => row.invoice_id === invoiceId)).toBe(true);
    expect(Number.parseInt(adminListBody.stats.total, 10)).toBeGreaterThan(0);

    const adminExportInvoicesRes = await app.inject({
      method: "GET",
      url: `/v1/admin/billing-invoices/export?orgId=${orgId}&dataset=invoices&limit=50`,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminExportInvoicesRes.statusCode).toBe(200);
    expect(adminExportInvoicesRes.body).toContain("provider_invoice_id");
    expect(adminExportInvoicesRes.body).toContain(invoiceId);

    const adminExportTaxRes = await app.inject({
      method: "GET",
      url: `/v1/admin/billing-invoices/export?orgId=${orgId}&dataset=tax&limit=50`,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminExportTaxRes.statusCode).toBe(200);
    expect(adminExportTaxRes.body).toContain("tax_type");
    expect(adminExportTaxRes.body).toContain(taxId);
  }, 30_000);

  it("deduplicates Razorpay webhook events with idempotent processing", async () => {
    const email = `integration-rzp-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Razorpay Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as { accessToken: string };
    const accessClaims = jwt.verify(registerBody.accessToken, process.env.JWT_SECRET!) as { orgId: string };
    const orgId = accessClaims.orgId;

    const razorpayPlanId = `plan_${randomUUID().slice(0, 8)}`;
    await app.db.query(`UPDATE plans SET razorpay_plan_id = $1 WHERE code = 'pro'`, [razorpayPlanId]);

    const eventId = `evt_${randomUUID().replace(/-/g, "")}`;
    const subId = `sub_${randomUUID().replace(/-/g, "")}`;
    const webhookPayload = {
      event: "subscription.activated",
      payload: {
        subscription: {
          entity: {
            id: subId,
            plan_id: razorpayPlanId,
            status: "active",
            customer_id: "cust_demo",
            notes: { orgId },
          },
        },
      },
    };

    const first = await app.inject({
      method: "POST",
      url: "/v1/billing/webhook/razorpay",
      headers: { "x-razorpay-event-id": eventId },
      payload: webhookPayload,
    });
    expect(first.statusCode).toBe(200);
    expect((first.json() as { ok?: boolean }).ok).toBe(true);

    const second = await app.inject({
      method: "POST",
      url: "/v1/billing/webhook/razorpay",
      headers: { "x-razorpay-event-id": eventId },
      payload: webhookPayload,
    });
    expect(second.statusCode).toBe(200);
    const secondBody = second.json() as { ok?: boolean; duplicate?: boolean };
    expect(secondBody.ok).toBe(true);
    expect(secondBody.duplicate).toBe(true);

    const eventRow = await app.db.query<{ attempts: number; status: string }>(
      `
        SELECT attempts, status
        FROM billing_webhook_events
        WHERE provider = 'razorpay' AND event_id = $1
        LIMIT 1
      `,
      [eventId],
    );
    expect(eventRow.rowCount).toBe(1);
    expect(eventRow.rows[0].status).toBe("processed");
    expect(eventRow.rows[0].attempts).toBe(2);

    const entitlement = await app.db.query<{ plan_code: string }>(
      `
        SELECT p.code AS plan_code
        FROM entitlements e
        JOIN plans p ON p.id = e.plan_id
        WHERE e.org_id = $1
        LIMIT 1
      `,
      [orgId],
    );
    expect(entitlement.rowCount).toBe(1);
    expect(entitlement.rows[0].plan_code).toBe("pro");

    const adminWebhookRes = await app.inject({
      method: "GET",
      url: "/v1/admin/billing-webhooks?provider=razorpay&status=processed&limit=50",
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
    });
    expect(adminWebhookRes.statusCode).toBe(200);
    const adminWebhookBody = adminWebhookRes.json() as {
      events: Array<{ provider: string; event_id: string; status: string }>;
      stats: { failed: string; pending: string; processed: string };
    };
    expect(adminWebhookBody.events.some((row) => row.event_id === eventId && row.provider === "razorpay")).toBe(true);
    expect(Number.parseInt(adminWebhookBody.stats.processed, 10)).toBeGreaterThan(0);

    const replayTargetId = randomUUID();
    const replayEventId = `evt_replay_${randomUUID().replace(/-/g, "")}`;
    await app.db.query(
      `
        INSERT INTO billing_webhook_events
          (id, provider, event_id, provider_event_type, payload_hash, payload_json, status, attempts, replay_count)
        VALUES
          ($1, 'razorpay', $2, 'subscription.activated', $3, $4::jsonb, 'failed', 1, 0)
      `,
      [
        replayTargetId,
        replayEventId,
        `hash_${randomUUID().replace(/-/g, "")}`,
        JSON.stringify({
          event: "subscription.activated",
          payload: {
            subscription: {
              entity: {
                id: `sub_replay_${randomUUID().replace(/-/g, "")}`,
                plan_id: razorpayPlanId,
                status: "active",
                customer_id: "cust_replay",
                notes: { orgId },
              },
            },
          },
        }),
      ],
    );

    const replayRes = await app.inject({
      method: "POST",
      url: `/v1/admin/billing-webhooks/${replayTargetId}/replay`,
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
      payload: {},
    });
    expect(replayRes.statusCode).toBe(200);
    const replayBody = replayRes.json() as { ok: boolean; result: { status: string } };
    expect(replayBody.ok).toBe(true);
    expect(replayBody.result.status).toBe("processed");

    const reconcileTargetId = randomUUID();
    await app.db.query(
      `
        INSERT INTO billing_webhook_events
          (id, provider, event_id, provider_event_type, payload_hash, payload_json, status, attempts, replay_count)
        VALUES
          ($1, 'razorpay', $2, 'subscription.activated', $3, $4::jsonb, 'failed', 1, 0)
      `,
      [
        reconcileTargetId,
        `evt_reconcile_${randomUUID().replace(/-/g, "")}`,
        `hash_${randomUUID().replace(/-/g, "")}`,
        JSON.stringify({
          event: "subscription.activated",
          payload: {
            subscription: {
              entity: {
                id: `sub_reconcile_${randomUUID().replace(/-/g, "")}`,
                plan_id: razorpayPlanId,
                status: "active",
                customer_id: "cust_reconcile",
                notes: { orgId },
              },
            },
          },
        }),
      ],
    );

    const reconcileRes = await app.inject({
      method: "POST",
      url: "/v1/admin/billing-webhooks/reconcile",
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
      payload: { provider: "razorpay", limit: 20 },
    });
    expect(reconcileRes.statusCode).toBe(200);
    const reconcileBody = reconcileRes.json() as { ok: boolean; attempted: number; processed: number };
    expect(reconcileBody.ok).toBe(true);
    expect(reconcileBody.attempted).toBeGreaterThan(0);
    expect(reconcileBody.processed).toBeGreaterThan(0);
  }, 30_000);
});
