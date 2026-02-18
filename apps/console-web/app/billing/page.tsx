"use client";

import { FormEvent, useEffect, useState } from "react";
import { api, getToken } from "@/lib/api";

type Plan = {
  id: string;
  code: string;
  name: string;
  max_tunnels: number;
  custom_domains: boolean;
  ip_allowlist: boolean;
};

type BillingProvider = "stripe" | "razorpay" | "paypal";
type BillingEventType = "subscription_cancel" | "refund" | "payment_failed" | "payment_recovered";
type BillingEventStatus = "pending" | "processed" | "failed" | "mocked";

type SubscriptionInfo = {
  provider: BillingProvider;
  status: string;
  planCode: string | null;
  planName: string | null;
  externalSubscriptionId: string | null;
};

type FinanceEvent = {
  id: string;
  provider: BillingProvider;
  event_type: BillingEventType;
  status: BillingEventStatus;
  external_ref: string | null;
  amount_cents: number | null;
  currency: string | null;
  created_at: string;
  error: string | null;
};

type InvoiceRow = {
  id: string;
  provider: BillingProvider;
  provider_invoice_id: string | null;
  status: string;
  currency: string | null;
  subtotal_cents: string | null;
  tax_cents: string | null;
  total_cents: string | null;
  amount_paid_cents: string | null;
  invoice_url: string | null;
  due_at: string | null;
  paid_at: string | null;
  created_at: string;
};

type TaxRecordRow = {
  id: string;
  invoice_id: string;
  tax_type: string;
  jurisdiction: string | null;
  amount_cents: string;
  currency: string | null;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

export default function BillingPage() {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [provider, setProvider] = useState<BillingProvider>("stripe");
  const [subscription, setSubscription] = useState<SubscriptionInfo | null>(null);
  const [events, setEvents] = useState<FinanceEvent[]>([]);
  const [invoices, setInvoices] = useState<InvoiceRow[]>([]);
  const [taxRecords, setTaxRecords] = useState<TaxRecordRow[]>([]);
  const [paymentId, setPaymentId] = useState("");
  const [amountCents, setAmountCents] = useState("");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [plansData, subscriptionData, eventsData, invoicesData] = await Promise.all([
        api<{ plans: Plan[] }>("/v1/plans"),
        api<{ subscription: SubscriptionInfo }>("/v1/billing/subscription"),
        api<{ events: FinanceEvent[] }>("/v1/billing/finance-events?limit=20"),
        api<{ invoices: InvoiceRow[]; taxRecords: TaxRecordRow[] }>("/v1/billing/invoices?limit=20&includeTax=true"),
      ]);
      setPlans(plansData.plans);
      setSubscription(subscriptionData.subscription);
      setEvents(eventsData.events);
      setInvoices(invoicesData.invoices);
      setTaxRecords(invoicesData.taxRecords);
      setMessage("");
    } catch (error) {
      setMessage(`Failed loading billing data: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function checkout(planCode: "pro" | "team") {
    try {
      const session = await api<{ checkoutUrl: string; mode: string; provider: BillingProvider }>("/v1/billing/checkout-session", {
        method: "POST",
        body: JSON.stringify({ planCode, provider }),
      });
      setMessage(`Launching ${session.provider} checkout (${session.mode})`);
      window.open(session.checkoutUrl, "_blank", "noopener,noreferrer");
    } catch (error) {
      setMessage(`Checkout failed: ${String(error)}`);
    }
  }

  async function cancelSubscription(atPeriodEnd: boolean) {
    setBusy(true);
    try {
      const response = await api<{
        ok: boolean;
        provider: BillingProvider;
        mode: "mock" | "provider";
        status: string;
      }>("/v1/billing/subscription/cancel", {
        method: "POST",
        body: JSON.stringify({ atPeriodEnd, reason: reason || undefined }),
      });
      setMessage(`Cancel requested via ${response.provider} (${response.mode}), status=${response.status}`);
      await load();
    } catch (error) {
      setMessage(`Cancel failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function refund(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!paymentId.trim()) {
      setMessage("Payment ID is required");
      return;
    }

    setBusy(true);
    try {
      const parsedAmount = amountCents.trim() ? Number.parseInt(amountCents, 10) : undefined;
      const response = await api<{
        ok: boolean;
        provider: BillingProvider;
        mode: "mock" | "provider";
        refundId: string | null;
      }>("/v1/billing/refund", {
        method: "POST",
        body: JSON.stringify({
          paymentId: paymentId.trim(),
          amountCents: Number.isFinite(parsedAmount as number) ? parsedAmount : undefined,
          reason: reason || undefined,
        }),
      });
      setMessage(`Refund submitted via ${response.provider} (${response.mode}), refundId=${response.refundId ?? "n/a"}`);
      setPaymentId("");
      setAmountCents("");
      await load();
    } catch (error) {
      setMessage(`Refund failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function exportInvoicesCsv() {
    setBusy(true);
    try {
      const token = getToken();
      const response = await fetch(`${API_BASE}/v1/billing/invoices/export?limit=5000`, {
        headers: token ? { authorization: `Bearer ${token}` } : undefined,
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "billing-invoices.csv";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
      setMessage("Exported invoices CSV");
    } catch (error) {
      setMessage(`Export failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-3">
      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>Current subscription</h3>
        <p className="muted">
          provider={subscription?.provider ?? "-"}, status={subscription?.status ?? "-"}, plan={subscription?.planName ?? "-"} (
          {subscription?.planCode ?? "-"})
        </p>
        <p className="muted">external subscription id: {subscription?.externalSubscriptionId ?? "-"}</p>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>Payment provider</h3>
        <select value={provider} onChange={(event) => setProvider(event.target.value as BillingProvider)}>
          <option value="stripe">Stripe</option>
          <option value="razorpay">Razorpay</option>
          <option value="paypal">PayPal</option>
        </select>
        <p className="muted" style={{ marginTop: 10 }}>
          Missing provider keys automatically use mock checkout and finance-operation simulation for local/dev.
        </p>
      </section>

      {plans.map((plan) => (
        <section className="card" key={plan.id}>
          <h3>{plan.name}</h3>
          <p className="muted">{plan.max_tunnels} tunnels</p>
          <p className="muted">Custom domains: {String(plan.custom_domains)}</p>
          <p className="muted">IP allowlist: {String(plan.ip_allowlist)}</p>
          {(plan.code === "pro" || plan.code === "team") && (
            <button onClick={() => void checkout(plan.code as "pro" | "team")}>Upgrade to {plan.name}</button>
          )}
        </section>
      ))}

      <section className="card">
        <h3>Cancel subscription</h3>
        <p className="muted">Reason (optional)</p>
        <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Requested by customer" />
        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          <button className="button secondary" disabled={busy} onClick={() => void cancelSubscription(true)}>
            Cancel at period end
          </button>
          <button disabled={busy} onClick={() => void cancelSubscription(false)}>
            Cancel now
          </button>
        </div>
      </section>

      <section className="card">
        <h3>Create refund</h3>
        <form onSubmit={refund} className="grid">
          <div>
            <label>Payment ID</label>
            <input value={paymentId} onChange={(event) => setPaymentId(event.target.value)} placeholder="pi_... / ch_... / provider id" />
          </div>
          <div>
            <label>Amount (cents, optional)</label>
            <input value={amountCents} onChange={(event) => setAmountCents(event.target.value)} placeholder="1200" />
          </div>
          <button type="submit" disabled={busy}>
            Issue refund
          </button>
        </form>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
          <h3 style={{ marginBottom: 0 }}>Recent invoices</h3>
          <button className="button secondary" disabled={busy} onClick={() => void exportInvoicesCsv()}>
            Export invoices CSV
          </button>
        </div>
        <table className="table" style={{ marginTop: 12 }}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Provider</th>
              <th>Status</th>
              <th>Total</th>
              <th>Tax</th>
              <th>Paid</th>
              <th>Ref</th>
            </tr>
          </thead>
          <tbody>
            {invoices.map((invoice) => (
              <tr key={invoice.id}>
                <td>{new Date(invoice.created_at).toLocaleString()}</td>
                <td>{invoice.provider}</td>
                <td>{invoice.status}</td>
                <td>{invoice.total_cents ? `${invoice.total_cents} ${invoice.currency ?? "USD"}` : "-"}</td>
                <td>{invoice.tax_cents ? `${invoice.tax_cents} ${invoice.currency ?? "USD"}` : "-"}</td>
                <td>{invoice.amount_paid_cents ? `${invoice.amount_paid_cents} ${invoice.currency ?? "USD"}` : "-"}</td>
                <td style={{ maxWidth: 240, whiteSpace: "normal", wordBreak: "break-all" }}>
                  {invoice.provider_invoice_id ?? "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted" style={{ marginTop: 8 }}>
          Tax records: {taxRecords.length}
        </p>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>Recent finance events</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Provider</th>
              <th>Type</th>
              <th>Status</th>
              <th>Amount</th>
              <th>Reference</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td>{new Date(event.created_at).toLocaleString()}</td>
                <td>{event.provider}</td>
                <td>{event.event_type}</td>
                <td>{event.status}</td>
                <td>{event.amount_cents ? `${event.amount_cents} ${event.currency ?? "USD"}` : "-"}</td>
                <td>{event.external_ref ?? "-"}</td>
                <td style={{ maxWidth: 320, whiteSpace: "normal", wordBreak: "break-word" }}>{event.error ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <p className="muted" style={{ gridColumn: "1 / -1" }}>
        {message}
      </p>
    </div>
  );
}
