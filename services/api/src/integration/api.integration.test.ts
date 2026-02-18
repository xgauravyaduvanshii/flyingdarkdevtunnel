import { createHash, createHmac, randomUUID } from "node:crypto";
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
  ALLOWED_REGIONS: "us,eu,ap",
  RELAY_REGION_WEIGHTS: "eu=eu-edge-integration-1:10|eu-edge-integration-2:1",
  RELAY_FAILOVER_REGIONS: "ap=eu,us;eu=us",
  BILLING_RUNBOOK_SIGNING_SECRET: "integration_runbook_secret_32_chars_minimum",
  BILLING_SETTLEMENT_SIGNING_SECRET: "integration_settlement_secret_32_chars_minimum",
  BILLING_SETTLEMENT_MAX_AGE_SECONDS: "300",
  AUTH_ABUSE_BLOCK_THRESHOLD: "1",
  AUTH_ABUSE_BLOCK_WINDOW_MINUTES: "30",
  CERT_EVENT_INGEST_TOKEN: "integration_cert_ingest_token",
  CERT_EVENT_SOURCE_KEYS: "cert_manager:cluster-eu=integration_cert_source_secret",
  CERT_EVENT_REQUIRE_PROVENANCE: "true",
  CERT_EVENT_MAX_AGE_SECONDS: "300",
  RELAY_HEARTBEAT_TOKEN: "integration_relay_heartbeat_token",
  RELAY_HEARTBEAT_MAX_AGE_SECONDS: "120",
};

for (const [key, value] of Object.entries(defaults)) {
  if (!process.env[key]) {
    process.env[key] = value;
  }
}

function randomTestIp(): string {
  const hex = randomUUID().replace(/-/g, "");
  const octet = (offset: number) => (Number.parseInt(hex.slice(offset, offset + 2), 16) % 254) + 1;
  return `10.${octet(0)}.${octet(2)}.${octet(4)}`;
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
      maxConcurrentConns: number;
    };

    const claims = jwt.verify(startBody.agentToken, process.env.AGENT_JWT_SECRET!) as {
      hosts: string[];
      tlsModes: Record<string, "termination" | "passthrough">;
      basicAuthUser: string;
      basicAuthPassword: string;
      ipAllowlist: string[];
      maxConcurrentConns: number;
      tokenType: string;
    };

    expect(claims.tokenType).toBe("agent");
    expect(claims.basicAuthUser).toBe("demo");
    expect(claims.basicAuthPassword).toBe("secret");
    expect(claims.ipAllowlist).toContain("127.0.0.1/32");
    expect(claims.maxConcurrentConns).toBe(500);
    expect(claims.hosts).toContain(domainName);
    expect(claims.hosts.some((host) => host.endsWith(`.${process.env.BASE_DOMAIN}`))).toBe(true);
    expect(claims.tlsModes[domainName]).toBe("termination");
    expect(startBody.hosts).toContain(domainName);
    expect(startBody.maxConcurrentConns).toBe(500);

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

  it("ingests signed settlement receipts and reconciles them through admin controls", async () => {
    const email = `integration-settlement-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Settlement Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const accessToken = (registerRes.json() as { accessToken: string }).accessToken;
    const claims = jwt.verify(accessToken, process.env.JWT_SECRET!) as { orgId: string };

    const settlementOffsetMs = Number.parseInt(randomUUID().replace(/-/g, "").slice(0, 6), 16);
    const settlementBaseAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000 + settlementOffsetMs);
    const periodStart = new Date(settlementBaseAt.getTime() - 60 * 1000);
    const periodEnd = new Date(settlementBaseAt.getTime() + 60 * 1000);
    await app.db.query(
      `
        INSERT INTO billing_finance_events (
          id,
          org_id,
          provider,
          event_type,
          status,
          external_id,
          amount_cents,
          currency,
          created_at,
          updated_at
        )
        VALUES
          ($1, $2, 'stripe', 'refund', 'processed', $3, 1500, 'USD', $6, $6),
          ($4, $2, 'stripe', 'refund', 'processed', $5, 2500, 'USD', $6, $6)
      `,
      [
        randomUUID(),
        claims.orgId,
        `settlement_evt_${randomUUID().replace(/-/g, "")}`,
        randomUUID(),
        `settlement_evt_${randomUUID().replace(/-/g, "")}`,
        settlementBaseAt,
      ],
    );

    const batchIdMatched = `batch_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const matchedPayload = JSON.stringify({
      provider: "stripe",
      batchId: batchIdMatched,
      periodStart: periodStart.toISOString(),
      periodEnd: periodEnd.toISOString(),
      totalEvents: 2,
      totalAmountCents: 4000,
      currency: "USD",
      payload: { source: "integration-test", mode: "matched" },
    });
    const matchedTimestamp = `${Math.floor(Date.now() / 1000)}`;
    const matchedSignature = createHmac("sha256", process.env.BILLING_SETTLEMENT_SIGNING_SECRET!)
      .update(`${matchedTimestamp}.${matchedPayload}`)
      .digest("hex");

    const ingestMatchedRes = await app.inject({
      method: "POST",
      url: "/v1/billing/settlement-receipts",
      headers: {
        "content-type": "application/json",
        "x-fdt-settlement-timestamp": matchedTimestamp,
        "x-fdt-settlement-signature": matchedSignature,
      },
      payload: matchedPayload,
    });
    expect(ingestMatchedRes.statusCode).toBe(202);
    const ingestMatchedBody = ingestMatchedRes.json() as { id: string; reconciliationStatus: string };
    expect(ingestMatchedBody.reconciliationStatus).toBe("pending");

    const invalidSignatureRes = await app.inject({
      method: "POST",
      url: "/v1/billing/settlement-receipts",
      headers: {
        "content-type": "application/json",
        "x-fdt-settlement-timestamp": `${Math.floor(Date.now() / 1000)}`,
        "x-fdt-settlement-signature": "deadbeef",
      },
      payload: matchedPayload,
    });
    expect(invalidSignatureRes.statusCode).toBe(401);

    const listRes = await app.inject({
      method: "GET",
      url: "/v1/admin/billing-settlement-receipts?provider=stripe&limit=20",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(listRes.statusCode).toBe(200);
    const listBody = listRes.json() as {
      receipts: Array<{ id: string; batch_id: string; reconciliation_status: string }>;
    };
    expect(listBody.receipts.some((row) => row.id === ingestMatchedBody.id && row.batch_id === batchIdMatched)).toBe(true);

    const reconcileMatchedRes = await app.inject({
      method: "POST",
      url: `/v1/admin/billing-settlement-receipts/${ingestMatchedBody.id}/reconcile`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { toleranceEvents: 0, toleranceAmountCents: 0 },
    });
    expect(reconcileMatchedRes.statusCode).toBe(200);
    const reconcileMatchedBody = reconcileMatchedRes.json() as {
      receipt: { reconciliationStatus: string; deltaEvents: number; deltaAmountCents: number };
    };
    expect(reconcileMatchedBody.receipt.reconciliationStatus).toBe("matched");
    expect(reconcileMatchedBody.receipt.deltaEvents).toBe(0);
    expect(reconcileMatchedBody.receipt.deltaAmountCents).toBe(0);

    const batchIdDelta = `batch_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const deltaPayload = JSON.stringify({
      provider: "stripe",
      batchId: batchIdDelta,
      periodStart: periodStart.toISOString(),
      periodEnd: periodEnd.toISOString(),
      totalEvents: 1,
      totalAmountCents: 1000,
      currency: "USD",
      payload: { source: "integration-test", mode: "delta" },
    });
    const deltaTimestamp = `${Math.floor(Date.now() / 1000)}`;
    const deltaSignature = createHmac("sha256", process.env.BILLING_SETTLEMENT_SIGNING_SECRET!)
      .update(`${deltaTimestamp}.${deltaPayload}`)
      .digest("hex");

    const ingestDeltaRes = await app.inject({
      method: "POST",
      url: "/v1/billing/settlement-receipts",
      headers: {
        "content-type": "application/json",
        "x-fdt-settlement-timestamp": deltaTimestamp,
        "x-fdt-settlement-signature": deltaSignature,
      },
      payload: deltaPayload,
    });
    expect(ingestDeltaRes.statusCode).toBe(202);
    const ingestDeltaBody = ingestDeltaRes.json() as { id: string };

    const reconcileDeltaRes = await app.inject({
      method: "POST",
      url: `/v1/admin/billing-settlement-receipts/${ingestDeltaBody.id}/reconcile`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { toleranceEvents: 0, toleranceAmountCents: 0 },
    });
    expect(reconcileDeltaRes.statusCode).toBe(200);
    const reconcileDeltaBody = reconcileDeltaRes.json() as {
      receipt: { reconciliationStatus: string; deltaEvents: number; deltaAmountCents: number };
    };
    expect(reconcileDeltaBody.receipt.reconciliationStatus).toBe("delta");
    expect(reconcileDeltaBody.receipt.deltaEvents).toBeGreaterThan(0);
    expect(reconcileDeltaBody.receipt.deltaAmountCents).toBeGreaterThan(0);
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

  it("supports team RBAC, SSO, SCIM role templates, and billing report export queue", async () => {
    const email = `integration-rbac-owner-${randomUUID()}@example.com`;
    const teammateEmail = `integration-rbac-user-${randomUUID()}@example.com`;
    const scimEmail = `integration-scim-user-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const ownerRegister = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration RBAC Org" },
    });
    expect(ownerRegister.statusCode).toBe(201);
    const ownerToken = (ownerRegister.json() as { accessToken: string }).accessToken;

    const teammateRegister = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email: teammateEmail, password, orgName: "Teammate Org" },
    });
    expect(teammateRegister.statusCode).toBe(201);

    const scimRegister = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email: scimEmail, password, orgName: "SCIM User Org" },
    });
    expect(scimRegister.statusCode).toBe(201);

    const addMemberRes = await app.inject({
      method: "POST",
      url: "/v1/admin/members",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: { email: teammateEmail, role: "viewer" },
    });
    expect(addMemberRes.statusCode).toBe(200);

    const membersRes = await app.inject({
      method: "GET",
      url: "/v1/admin/members",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(membersRes.statusCode).toBe(200);
    const membersBody = membersRes.json() as { members: Array<{ user_id: string; email: string; role: string }> };
    const teammateMembership = membersBody.members.find((member) => member.email === teammateEmail);
    expect(teammateMembership).toBeTruthy();
    expect(teammateMembership?.role).toBe("viewer");

    const updateRoleRes = await app.inject({
      method: "PATCH",
      url: `/v1/admin/members/${teammateMembership!.user_id}/role`,
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: { role: "billing" },
    });
    expect(updateRoleRes.statusCode).toBe(200);

    const ssoUpsertRes = await app.inject({
      method: "PUT",
      url: "/v1/admin/sso",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: {
        provider: "saml",
        enabled: true,
        issuer: "https://idp.integration.example.com",
        entrypoint: "https://idp.integration.example.com/sso",
        audience: "urn:fdt:integration",
      },
    });
    expect(ssoUpsertRes.statusCode).toBe(200);

    const ssoGetRes = await app.inject({
      method: "GET",
      url: "/v1/admin/sso",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(ssoGetRes.statusCode).toBe(200);
    const ssoBody = ssoGetRes.json() as {
      sso: { provider: "saml" | "oidc"; enabled: boolean; issuer: string | null };
    };
    expect(ssoBody.sso.provider).toBe("saml");
    expect(ssoBody.sso.enabled).toBe(true);

    const templateUpsertRes = await app.inject({
      method: "PUT",
      url: "/v1/admin/role-templates/developer",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: { role: "member", description: "SCIM developer template" },
    });
    expect(templateUpsertRes.statusCode).toBe(200);

    const templateListRes = await app.inject({
      method: "GET",
      url: "/v1/admin/role-templates",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(templateListRes.statusCode).toBe(200);
    const templateListBody = templateListRes.json() as {
      templates: Array<{ template_key: string; role: string }>;
    };
    expect(templateListBody.templates.some((row) => row.template_key === "developer" && row.role === "member")).toBe(true);

    const scimProvisionRes = await app.inject({
      method: "POST",
      url: "/v1/admin/scim/provision/users",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: {
        operations: [{ email: scimEmail, templateKey: "developer", active: true }],
      },
    });
    expect(scimProvisionRes.statusCode).toBe(200);
    const scimProvisionBody = scimProvisionRes.json() as {
      results: Array<{ email: string; status: string; role: string | null }>;
    };
    expect(scimProvisionBody.results.some((row) => row.email === scimEmail && row.status === "applied" && row.role === "member")).toBe(
      true,
    );

    const scimEventsRes = await app.inject({
      method: "GET",
      url: "/v1/admin/scim/provision/events?limit=50",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(scimEventsRes.statusCode).toBe(200);
    const scimEventsBody = scimEventsRes.json() as {
      events: Array<{ email: string; status: string; action: string }>;
    };
    expect(scimEventsBody.events.some((row) => row.email === scimEmail && row.status === "applied" && row.action === "upsert")).toBe(true);

    const membersAfterScimRes = await app.inject({
      method: "GET",
      url: "/v1/admin/members",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(membersAfterScimRes.statusCode).toBe(200);
    const membersAfterScimBody = membersAfterScimRes.json() as { members: Array<{ email: string; role: string }> };
    expect(membersAfterScimBody.members.some((member) => member.email === scimEmail && member.role === "member")).toBe(true);

    const scimDeactivateRes = await app.inject({
      method: "POST",
      url: "/v1/admin/scim/provision/users",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: {
        operations: [{ email: scimEmail, active: false }],
      },
    });
    expect(scimDeactivateRes.statusCode).toBe(200);

    const reportCreateRes = await app.inject({
      method: "POST",
      url: "/v1/admin/billing-reports/exports",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: { dataset: "finance_events", destination: "inline", maxAttempts: 7 },
    });
    expect(reportCreateRes.statusCode).toBe(200);
    const reportCreateBody = reportCreateRes.json() as { ok: boolean; id: string };
    expect(reportCreateBody.ok).toBe(true);

    const reportListRes = await app.inject({
      method: "GET",
      url: "/v1/admin/billing-reports/exports?limit=20",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(reportListRes.statusCode).toBe(200);
    const reportListBody = reportListRes.json() as {
      exports: Array<{
        id: string;
        dataset: string;
        status: string;
        max_attempts: number;
        delivery_ack_status: "not_required" | "pending" | "acknowledged" | "expired";
      }>;
    };
    expect(
      reportListBody.exports.some(
        (job) => job.id === reportCreateBody.id && job.dataset === "finance_events" && job.max_attempts === 7,
      ),
    ).toBe(true);

    const ackToken = `ack_${randomUUID().replace(/-/g, "")}`;
    const ackTokenHash = createHash("sha256").update(ackToken).digest("hex");
    await app.db.query(
      `
        UPDATE billing_report_exports
        SET
          status = 'completed',
          completed_at = NOW(),
          delivery_ack_status = 'pending',
          delivery_ack_token_hash = $2,
          delivery_ack_deadline = NOW() + INTERVAL '1 hour',
          last_delivery_status = 'delivered_pending_ack'
        WHERE id = $1
      `,
      [reportCreateBody.id, ackTokenHash],
    );

    const ackRes = await app.inject({
      method: "POST",
      url: `/v1/billing/reports/exports/${reportCreateBody.id}/ack`,
      headers: { "x-fdt-report-ack-token": ackToken },
      payload: {
        sinkRef: "warehouse://integration/exports",
        metadata: { source: "integration_test" },
      },
    });
    expect(ackRes.statusCode).toBe(200);
    const ackBody = ackRes.json() as { ok: boolean; id: string };
    expect(ackBody.ok).toBe(true);
    expect(ackBody.id).toBe(reportCreateBody.id);

    const ackRow = await app.db.query<{ delivery_ack_status: string; delivery_ack_at: Date | null }>(
      `SELECT delivery_ack_status, delivery_ack_at FROM billing_report_exports WHERE id = $1 LIMIT 1`,
      [reportCreateBody.id],
    );
    expect(ackRow.rows[0]?.delivery_ack_status).toBe("acknowledged");
    expect(ackRow.rows[0]?.delivery_ack_at).toBeTruthy();

    await app.db.query(
      `
        UPDATE billing_report_exports
        SET
          status = 'completed',
          completed_at = NOW(),
          delivery_ack_status = 'pending',
          delivery_ack_token_hash = 'deadbeef',
          delivery_ack_deadline = NOW() - INTERVAL '5 minutes',
          last_delivery_status = 'delivered_pending_ack'
        WHERE id = $1
      `,
      [reportCreateBody.id],
    );

    const ackReconcileRes = await app.inject({
      method: "POST",
      url: "/v1/admin/billing-reports/exports/ack-reconcile",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: { ackStatus: "pending", onlyPastDeadline: true, limit: 20 },
    });
    expect(ackReconcileRes.statusCode).toBe(200);
    const ackReconcileBody = ackReconcileRes.json() as { attempted: number; replayed: number };
    expect(ackReconcileBody.attempted).toBeGreaterThan(0);
    expect(ackReconcileBody.replayed).toBeGreaterThan(0);

    const ackReconciledRow = await app.db.query<{ status: string; delivery_ack_status: string }>(
      `SELECT status, delivery_ack_status FROM billing_report_exports WHERE id = $1 LIMIT 1`,
      [reportCreateBody.id],
    );
    expect(ackReconciledRow.rows[0]?.status).toBe("pending");
    expect(ackReconciledRow.rows[0]?.delivery_ack_status).toBe("expired");

    await app.db.query(`UPDATE billing_report_exports SET status = 'failed', attempts = 2, error = 'integration failed' WHERE id = $1`, [
      reportCreateBody.id,
    ]);

    const reconcileRes = await app.inject({
      method: "POST",
      url: "/v1/admin/billing-reports/exports/reconcile",
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: { status: "failed", limit: 20, resetAttempts: true },
    });
    expect(reconcileRes.statusCode).toBe(200);
    const reconcileBody = reconcileRes.json() as { attempted: number; replayed: number };
    expect(reconcileBody.attempted).toBeGreaterThan(0);
    expect(reconcileBody.replayed).toBeGreaterThan(0);

    const reconciledRow = await app.db.query<{ status: string; attempts: number; next_attempt_at: Date | null }>(
      `SELECT status, attempts, next_attempt_at FROM billing_report_exports WHERE id = $1 LIMIT 1`,
      [reportCreateBody.id],
    );
    expect(reconciledRow.rows[0]?.status).toBe("pending");
    expect(reconciledRow.rows[0]?.attempts).toBe(0);
    expect(reconciledRow.rows[0]?.next_attempt_at).toBeTruthy();

    const membersAfterDeactivateRes = await app.inject({
      method: "GET",
      url: "/v1/admin/members",
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(membersAfterDeactivateRes.statusCode).toBe(200);
    const membersAfterDeactivateBody = membersAfterDeactivateRes.json() as { members: Array<{ email: string }> };
    expect(membersAfterDeactivateBody.members.some((member) => member.email === scimEmail)).toBe(false);
  }, 30_000);

  it("enforces token revoke list and signed runbook replay with dunning visibility", async () => {
    const email = `integration-revoke-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Revoke Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as { accessToken: string };
    const revokedAccessToken = registerBody.accessToken;
    const claims = jwt.verify(revokedAccessToken, process.env.JWT_SECRET!) as { orgId: string };
    const loginIp = randomTestIp();

    const revokeRes = await app.inject({
      method: "POST",
      url: "/v1/auth/token/revoke",
      headers: { authorization: `Bearer ${revokedAccessToken}` },
      payload: { reason: "integration revoke current token" },
    });
    expect(revokeRes.statusCode).toBe(200);

    const revokedAccessRes = await app.inject({
      method: "GET",
      url: "/v1/tunnels",
      headers: { authorization: `Bearer ${revokedAccessToken}` },
    });
    expect(revokedAccessRes.statusCode).toBe(401);

    const loginRes = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      remoteAddress: loginIp,
      payload: { email, password },
    });
    expect(loginRes.statusCode).toBe(200);
    const freshAccessToken = (loginRes.json() as { accessToken: string }).accessToken;

    await app.db.query(`UPDATE memberships SET created_at = NOW() - INTERVAL '120 days' WHERE org_id = $1`, [claims.orgId]);

    const rotationHealthRes = await app.inject({
      method: "GET",
      url: "/v1/admin/secrets/rotation-health?maxAgeDays=30&limit=200",
      headers: { authorization: `Bearer ${freshAccessToken}` },
    });
    expect(rotationHealthRes.statusCode).toBe(200);
    const rotationHealthBody = rotationHealthRes.json() as { staleUsers: number; totalUsers: number };
    expect(rotationHealthBody.totalUsers).toBeGreaterThan(0);
    expect(rotationHealthBody.staleUsers).toBeGreaterThan(0);

    const rotationScanRes = await app.inject({
      method: "POST",
      url: "/v1/admin/secrets/rotation/scan",
      headers: { authorization: `Bearer ${freshAccessToken}` },
      payload: { maxAgeDays: 30 },
    });
    expect(rotationScanRes.statusCode).toBe(200);
    const rotationScanBody = rotationScanRes.json() as { staleCount: number };
    expect(rotationScanBody.staleCount).toBeGreaterThan(0);

    const dunningId = randomUUID();
    await app.db.query(
      `
        INSERT INTO billing_dunning_cases (
          id,
          org_id,
          provider,
          subscription_ref,
          status,
          stage,
          retry_count,
          next_attempt_at,
          latest_event_type
        )
        VALUES ($1, $2, 'stripe', $3, 'open', 2, 1, NOW(), 'invoice.payment_failed')
      `,
      [dunningId, claims.orgId, `sub_dunning_${randomUUID().replace(/-/g, "")}`],
    );

    const userDunningRes = await app.inject({
      method: "GET",
      url: "/v1/billing/dunning?limit=20",
      headers: { authorization: `Bearer ${freshAccessToken}` },
    });
    expect(userDunningRes.statusCode).toBe(200);
    const userDunningBody = userDunningRes.json() as { cases: Array<{ id: string; status: string }> };
    expect(userDunningBody.cases.some((row) => row.id === dunningId && row.status === "open")).toBe(true);

    const adminDunningRes = await app.inject({
      method: "GET",
      url: "/v1/admin/billing-dunning?limit=50",
      headers: { authorization: `Bearer ${freshAccessToken}` },
    });
    expect(adminDunningRes.statusCode).toBe(200);
    const adminDunningBody = adminDunningRes.json() as {
      cases: Array<{ id: string; org_id: string }>;
    };
    expect(adminDunningBody.cases.some((row) => row.id === dunningId && row.org_id === claims.orgId)).toBe(true);

    const eventRowId = randomUUID();
    const eventPayload = {
      event: "subscription.activated",
      payload: {
        subscription: {
          entity: {
            id: `sub_replay_${randomUUID().replace(/-/g, "")}`,
            plan_id: `plan_unmapped_${randomUUID().slice(0, 8)}`,
            status: "active",
            notes: { orgId: claims.orgId },
          },
        },
      },
    };
    const eventBodyRaw = JSON.stringify(eventPayload);

    await app.db.query(
      `
        INSERT INTO billing_webhook_events
          (id, provider, event_id, provider_event_type, payload_hash, payload_json, status, attempts, replay_count)
        VALUES
          ($1, 'razorpay', $2, 'subscription.activated', $3, $4::jsonb, 'failed', 1, 0)
      `,
      [eventRowId, `evt_runbook_${randomUUID().replace(/-/g, "")}`, `hash_${randomUUID().replace(/-/g, "")}`, eventBodyRaw],
    );

    const runbookPayload = JSON.stringify({
      provider: "razorpay",
      eventClass: "subscription",
      limit: 20,
      force: false,
    });
    const timestamp = `${Math.floor(Date.now() / 1000)}`;
    const signature = createHmac("sha256", process.env.BILLING_RUNBOOK_SIGNING_SECRET!)
      .update(`${timestamp}.${runbookPayload}`)
      .digest("hex");

    const runbookRes = await app.inject({
      method: "POST",
      url: "/v1/billing/runbook/replay",
      headers: {
        "content-type": "application/json",
        "x-fdt-runbook-timestamp": timestamp,
        "x-fdt-runbook-signature": signature,
      },
      payload: runbookPayload,
    });
    expect(runbookRes.statusCode).toBe(200);
    const runbookBody = runbookRes.json() as { ok: boolean; attempted: number; processed: number };
    expect(runbookBody.ok).toBe(true);
    expect(runbookBody.attempted).toBeGreaterThan(0);
    expect(runbookBody.processed).toBeGreaterThan(0);

    const replayedEvent = await app.db.query<{ status: string }>(
      `SELECT status FROM billing_webhook_events WHERE id = $1 LIMIT 1`,
      [eventRowId],
    );
    expect(replayedEvent.rows[0]?.status).toBe("processed");
  }, 30_000);

  it("accepts certificate lifecycle event ingest and per-domain failure policy controls", async () => {
    const email = `integration-certevents-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Cert Events Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const accessToken = (registerRes.json() as { accessToken: string }).accessToken;

    const usersRes = await app.inject({
      method: "GET",
      url: "/v1/admin/users",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(usersRes.statusCode).toBe(200);
    const userId = (usersRes.json() as { users: Array<{ id: string; email: string }> }).users.find((u) => u.email === email)?.id;
    expect(userId).toBeTruthy();

    const promoteRes = await app.inject({
      method: "PATCH",
      url: `/v1/admin/users/${userId}/plan`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { planCode: "pro" },
    });
    expect(promoteRes.statusCode).toBe(200);

    const tunnelRes = await app.inject({
      method: "POST",
      url: "/v1/tunnels",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        name: "cert-events-http",
        protocol: "http",
        localAddr: "http://localhost:3000",
        region: "eu",
      },
    });
    expect(tunnelRes.statusCode).toBe(201);
    const tunnelBody = tunnelRes.json() as { id: string; region: string };
    expect(tunnelBody.region).toBe("eu");

    const domainName = `cert-${randomUUID().slice(0, 8)}.example.com`;
    const createDomainRes = await app.inject({
      method: "POST",
      url: "/v1/domains/custom",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { domain: domainName, tlsMode: "termination" },
    });
    expect(createDomainRes.statusCode).toBe(201);
    const domainId = (createDomainRes.json() as { id: string }).id;

    const verifyRes = await app.inject({
      method: "POST",
      url: `/v1/domains/custom/${domainId}/verify`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    });
    expect(verifyRes.statusCode).toBe(200);

    const routeRes = await app.inject({
      method: "POST",
      url: `/v1/domains/custom/${domainId}/route`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { tunnelId: tunnelBody.id, tlsMode: "termination" },
    });
    expect(routeRes.statusCode).toBe(200);

    const policyRes = await app.inject({
      method: "PATCH",
      url: `/v1/domains/custom/${domainId}/failure-policy`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { policy: "strict" },
    });
    expect(policyRes.statusCode).toBe(200);

    const certEventPayload = JSON.stringify({
      source: "cert_manager",
      clusterId: "cluster-eu",
      sourceEventId: `evt_cert_${randomUUID().replace(/-/g, "")}`,
      domainId,
      callbackClass: "renewal",
      callbackAction: "failed",
      callbackAttempt: 4,
      reason: "acme challenge timed out",
    });
    const certTimestamp = `${Math.floor(Date.now() / 1000)}`;
    const certSignature = createHmac("sha256", "integration_cert_source_secret")
      .update(`${certTimestamp}.${certEventPayload}`)
      .digest("hex");

    const certEventRes = await app.inject({
      method: "POST",
      url: "/v1/domains/cert-events",
      headers: {
        "content-type": "application/json",
        "x-cert-event-token": process.env.CERT_EVENT_INGEST_TOKEN!,
        "x-cert-source": "cert_manager",
        "x-cert-cluster": "cluster-eu",
        "x-cert-timestamp": certTimestamp,
        "x-cert-signature": certSignature,
      },
      payload: certEventPayload,
    });
    expect(certEventRes.statusCode).toBe(202);

    const eventsRes = await app.inject({
      method: "GET",
      url: `/v1/domains/custom/${domainId}/cert-events?limit=20`,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(eventsRes.statusCode).toBe(200);
    const eventsBody = eventsRes.json() as {
      events: Array<{
        event_type: string;
        status: string;
        callback_class: string | null;
        callback_action: string | null;
        callback_attempt: number | null;
      }>;
    };
    expect(
      eventsBody.events.some(
        (event) =>
          event.event_type === "renewal_failed" &&
          event.status === "pending" &&
          event.callback_class === "renewal" &&
          event.callback_action === "failed" &&
          event.callback_attempt === 4,
      ),
    ).toBe(true);

    const adminEventsRes = await app.inject({
      method: "GET",
      url: "/v1/admin/cert-events?status=pending&clusterId=cluster-eu&limit=50",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(adminEventsRes.statusCode).toBe(200);
    const adminEventsBody = adminEventsRes.json() as {
      events: Array<{ id: string; domain: string; callback_class: string | null; callback_attempt: number | null }>;
      stats: { pending: string; failed: string };
    };
    const adminEvent = adminEventsBody.events.find((event) => event.domain === domainName);
    const adminEventId = adminEvent?.id;
    expect(adminEventId).toBeTruthy();
    expect(adminEvent?.callback_class).toBe("renewal");
    expect(adminEvent?.callback_attempt).toBe(4);
    expect(Number.parseInt(adminEventsBody.stats.pending, 10)).toBeGreaterThan(0);

    const incidentsRes = await app.inject({
      method: "GET",
      url: `/v1/admin/cert-incidents?status=open&domain=${encodeURIComponent(domainName)}&limit=20`,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(incidentsRes.statusCode).toBe(200);
    const incidentsBody = incidentsRes.json() as {
      incidents: Array<{ id: string; incident_type: string; tier: number; status: string }>;
    };
    const incident = incidentsBody.incidents.find((row) => row.incident_type === "renewal_failed");
    expect(incident).toBeTruthy();
    expect(incident?.tier).toBe(3);
    expect(incident?.status).toBe("open");

    const ackIncidentRes = await app.inject({
      method: "POST",
      url: `/v1/admin/cert-incidents/${incident!.id}/ack`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { note: "on-call triage acknowledged" },
    });
    expect(ackIncidentRes.statusCode).toBe(200);

    const resolveIncidentRes = await app.inject({
      method: "POST",
      url: `/v1/admin/cert-incidents/${incident!.id}/resolve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { note: "manual runbook completed" },
    });
    expect(resolveIncidentRes.statusCode).toBe(200);
    const resolveIncidentBody = resolveIncidentRes.json() as { incident: { status: string } };
    expect(resolveIncidentBody.incident.status).toBe("resolved");

    await app.db.query(`UPDATE certificate_lifecycle_events SET status = 'failed', retry_count = 3 WHERE id = $1`, [adminEventId]);

    const replayRes = await app.inject({
      method: "POST",
      url: "/v1/admin/cert-events/replay",
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { status: "failed", source: "cert_manager", clusterId: "cluster-eu", limit: 20, resetRetry: true },
    });
    expect(replayRes.statusCode).toBe(200);
    const replayBody = replayRes.json() as { replayed: number; attempted: number };
    expect(replayBody.attempted).toBeGreaterThan(0);
    expect(replayBody.replayed).toBeGreaterThan(0);

    const replayedEvent = await app.db.query<{ status: string; retry_count: number }>(
      `SELECT status, retry_count FROM certificate_lifecycle_events WHERE id = $1 LIMIT 1`,
      [adminEventId],
    );
    expect(replayedEvent.rows[0]?.status).toBe("pending");
    expect(replayedEvent.rows[0]?.retry_count).toBe(0);

    const regionSummaryRes = await app.inject({
      method: "GET",
      url: "/v1/admin/domains/cert-region-summary",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(regionSummaryRes.statusCode).toBe(200);
    const regionSummaryBody = regionSummaryRes.json() as {
      regions: Array<{ region: string; total: string }>;
    };
    expect(regionSummaryBody.regions.some((region) => region.region === "eu" && Number.parseInt(region.total, 10) > 0)).toBe(
      true,
    );

    const domainsRes = await app.inject({
      method: "GET",
      url: "/v1/domains/custom",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(domainsRes.statusCode).toBe(200);
    const domainsBody = domainsRes.json() as {
      domains: Array<{ id: string; cert_failure_policy: "standard" | "strict" | "hold" }>;
    };
    expect(domainsBody.domains.find((domain) => domain.id === domainId)?.cert_failure_policy).toBe("strict");
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

  it("accepts relay heartbeat updates and assigns weighted region edges with failover", async () => {
    const heartbeatPrimaryRes = await app.inject({
      method: "POST",
      url: "/v1/relay/heartbeat",
      headers: {
        authorization: `Bearer ${process.env.RELAY_HEARTBEAT_TOKEN!}`,
      },
      payload: {
        edgeId: "eu-edge-integration-1",
        region: "eu",
        status: "online",
        capacity: 500,
        inFlight: 10,
        rejectedOverlimit: 0,
      },
    });
    expect(heartbeatPrimaryRes.statusCode).toBe(200);

    const heartbeatSecondaryRes = await app.inject({
      method: "POST",
      url: "/v1/relay/heartbeat",
      headers: {
        authorization: `Bearer ${process.env.RELAY_HEARTBEAT_TOKEN!}`,
      },
      payload: {
        edgeId: "eu-edge-integration-2",
        region: "eu",
        status: "online",
        capacity: 500,
        inFlight: 2,
        rejectedOverlimit: 0,
      },
    });
    expect(heartbeatSecondaryRes.statusCode).toBe(200);

    const email = `integration-relay-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Relay Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const registerBody = registerRes.json() as { accessToken: string; authtoken: string };
    const registerClaims = jwt.verify(registerBody.accessToken, process.env.JWT_SECRET!) as { orgId: string };

    const tunnelRes = await app.inject({
      method: "POST",
      url: "/v1/tunnels",
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
      payload: {
        name: "relay-heartbeat-eu",
        protocol: "http",
        localAddr: "http://localhost:3000",
        region: "eu",
      },
    });
    expect(tunnelRes.statusCode).toBe(201);
    const tunnelId = (tunnelRes.json() as { id: string }).id;

    const startRes = await app.inject({
      method: "POST",
      url: `/v1/tunnels/${tunnelId}/start`,
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
      payload: {},
    });
    expect(startRes.statusCode).toBe(200);
    const startBody = startRes.json() as { assignedEdge: string };
    expect(startBody.assignedEdge).toBe("eu-edge-integration-1");

    const apTunnelRes = await app.inject({
      method: "POST",
      url: "/v1/tunnels",
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
      payload: {
        name: "relay-heartbeat-ap",
        protocol: "http",
        localAddr: "http://localhost:3001",
        region: "ap",
      },
    });
    expect(apTunnelRes.statusCode).toBe(201);
    const apTunnelId = (apTunnelRes.json() as { id: string }).id;

    const apStartRes = await app.inject({
      method: "POST",
      url: `/v1/tunnels/${apTunnelId}/start`,
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
      payload: {},
    });
    expect(apStartRes.statusCode).toBe(200);
    const apStartBody = apStartRes.json() as { assignedEdge: string };
    expect(apStartBody.assignedEdge).toBe("eu-edge-integration-1");

    const exchangeRes = await app.inject({
      method: "POST",
      url: "/v1/agent/exchange",
      payload: {
        authtoken: registerBody.authtoken,
        tunnelId,
      },
    });
    expect(exchangeRes.statusCode).toBe(200);
    const exchangeBody = exchangeRes.json() as { tunnel: { assignedEdge: string } };
    expect(exchangeBody.tunnel.assignedEdge).toBe("eu-edge-integration-1");

    const adminEdges = await app.inject({
      method: "GET",
      url: "/v1/admin/relay-edges?region=eu&limit=20",
      headers: { authorization: `Bearer ${registerBody.accessToken}` },
    });
    expect(adminEdges.statusCode).toBe(200);
    const adminEdgesBody = adminEdges.json() as { edges: Array<{ edge_id: string }> };
    expect(adminEdgesBody.edges.some((edge) => edge.edge_id === "eu-edge-integration-1")).toBe(true);

    const replicaDomainId = randomUUID();
    const replicaDomain = `relay-replica-${randomUUID().slice(0, 8)}.example.com`;
    await app.db.query(
      `
        INSERT INTO custom_domains
          (id, org_id, domain, verification_token, verified, tls_status, tls_mode)
        VALUES
          ($1, $2, $3, $4, TRUE, 'issued', 'termination')
      `,
      [replicaDomainId, registerClaims.orgId, replicaDomain, randomUUID().slice(0, 12)],
    );
    await app.db.query(
      `
        INSERT INTO cert_region_replicas
          (id, domain_id, domain, source_region, target_region, tls_mode, tls_status, replication_state, lag_seconds, synced_at)
        VALUES
          ($1, $2, $3, 'eu', 'eu', 'termination', 'issued', 'source', 0, NOW())
      `,
      [randomUUID(), replicaDomainId, replicaDomain],
    );

    const relayCertReplicationRes = await app.inject({
      method: "GET",
      url: "/v1/relay/cert-replication?region=eu&limit=20",
      headers: {
        authorization: `Bearer ${process.env.RELAY_HEARTBEAT_TOKEN!}`,
      },
    });
    expect(relayCertReplicationRes.statusCode).toBe(200);
    const relayCertReplicationBody = relayCertReplicationRes.json() as {
      region: string;
      replicas: Array<{ target_region: string; replication_state: string }>;
    };
    expect(relayCertReplicationBody.region).toBe("eu");
    expect(
      relayCertReplicationBody.replicas.some((row) => row.target_region === "eu" && row.replication_state === "source"),
    ).toBe(true);
  }, 30_000);

  it("blocks login attempts from IPs with high abuse signals", async () => {
    const email = `integration-abuse-${randomUUID()}@example.com`;
    const password = "passw0rd123";

    const registerRes = await app.inject({
      method: "POST",
      url: "/v1/auth/register",
      payload: { email, password, orgName: "Integration Abuse Org" },
    });
    expect(registerRes.statusCode).toBe(201);
    const abuseIp = randomTestIp();

    for (let i = 0; i < 10; i += 1) {
      const failedLogin = await app.inject({
        method: "POST",
        url: "/v1/auth/login",
        remoteAddress: abuseIp,
        payload: { email, password: "wrong-password-123" },
      });
      expect(failedLogin.statusCode).toBe(401);
    }

    const blockedLogin = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      remoteAddress: abuseIp,
      payload: { email, password },
    });
    expect(blockedLogin.statusCode).toBe(429);
  }, 30_000);
});
