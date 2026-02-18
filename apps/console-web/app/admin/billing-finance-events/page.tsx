"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";

type Provider = "stripe" | "razorpay" | "paypal";
type FinanceType = "subscription_cancel" | "refund" | "payment_failed" | "payment_recovered";
type Status = "pending" | "processed" | "failed" | "mocked";

type BillingFinanceEventRow = {
  id: string;
  org_id: string;
  provider: Provider;
  event_type: FinanceType;
  status: Status;
  external_id: string | null;
  external_ref: string | null;
  amount_cents: number | null;
  currency: string | null;
  reason: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
};

type FinanceStats = {
  total: string;
  processed: string;
  failed: string;
  mocked: string;
  refunds: string;
  cancellations: string;
  payment_failed: string;
};

export default function AdminBillingFinanceEventsPage() {
  const [rows, setRows] = useState<BillingFinanceEventRow[]>([]);
  const [stats, setStats] = useState<FinanceStats | null>(null);
  const [provider, setProvider] = useState<Provider | "all">("all");
  const [type, setType] = useState<FinanceType | "all">("all");
  const [status, setStatus] = useState<Status | "all">("all");
  const [message, setMessage] = useState("");

  const query = useMemo(() => {
    const params = new URLSearchParams();
    if (provider !== "all") params.set("provider", provider);
    if (type !== "all") params.set("type", type);
    if (status !== "all") params.set("status", status);
    params.set("limit", "200");
    return params.toString();
  }, [provider, status, type]);

  async function load() {
    try {
      const data = await api<{ events: BillingFinanceEventRow[]; stats: FinanceStats }>(
        `/v1/admin/billing-finance-events?${query}`,
      );
      setRows(data.events);
      setStats(data.stats);
      setMessage("");
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, [query]);

  return (
    <section className="card">
      <h3>Billing finance events</h3>
      <p className="muted">
        {stats
          ? `total=${stats.total}, processed=${stats.processed}, failed=${stats.failed}, mocked=${stats.mocked}, refunds=${stats.refunds}, cancellations=${stats.cancellations}, payment_failed=${stats.payment_failed}`
          : "No stats yet"}
      </p>
      <p className="muted">{message}</p>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <select value={provider} onChange={(event) => setProvider(event.target.value as Provider | "all")}>
          <option value="all">All providers</option>
          <option value="stripe">Stripe</option>
          <option value="razorpay">Razorpay</option>
          <option value="paypal">PayPal</option>
        </select>
        <select value={type} onChange={(event) => setType(event.target.value as FinanceType | "all")}>
          <option value="all">All types</option>
          <option value="subscription_cancel">subscription_cancel</option>
          <option value="refund">refund</option>
          <option value="payment_failed">payment_failed</option>
          <option value="payment_recovered">payment_recovered</option>
        </select>
        <select value={status} onChange={(event) => setStatus(event.target.value as Status | "all")}>
          <option value="all">All statuses</option>
          <option value="pending">pending</option>
          <option value="processed">processed</option>
          <option value="failed">failed</option>
          <option value="mocked">mocked</option>
        </select>
      </div>

      <button onClick={() => void load()} style={{ marginBottom: 12 }}>
        Refresh
      </button>

      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Org</th>
            <th>Provider</th>
            <th>Type</th>
            <th>Status</th>
            <th>Amount</th>
            <th>External Ref</th>
            <th>Error / Reason</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{new Date(row.created_at).toLocaleString()}</td>
              <td>{row.org_id}</td>
              <td>{row.provider}</td>
              <td>{row.event_type}</td>
              <td>{row.status}</td>
              <td>{row.amount_cents ? `${row.amount_cents} ${row.currency ?? "USD"}` : "-"}</td>
              <td>{row.external_ref ?? row.external_id ?? "-"}</td>
              <td style={{ maxWidth: 320, whiteSpace: "normal", wordBreak: "break-word" }}>{row.error ?? row.reason ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
