"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

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

export default function BillingPage() {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [provider, setProvider] = useState<BillingProvider>("stripe");
  const [subscription, setSubscription] = useState<SubscriptionInfo | null>(null);
  const [events, setEvents] = useState<FinanceEvent[]>([]);
  const [paymentId, setPaymentId] = useState("");
  const [amountCents, setAmountCents] = useState("");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [plansData, subscriptionData, eventsData] = await Promise.all([
        api<{ plans: Plan[] }>("/v1/plans"),
        api<{ subscription: SubscriptionInfo }>("/v1/billing/subscription"),
        api<{ events: FinanceEvent[] }>("/v1/billing/finance-events?limit=20"),
      ]);
      setPlans(plansData.plans);
      setSubscription(subscriptionData.subscription);
      setEvents(eventsData.events);
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
