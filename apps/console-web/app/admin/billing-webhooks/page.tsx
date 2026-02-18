"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";

type Provider = "stripe" | "razorpay" | "paypal";
type Status = "pending" | "processed" | "failed";

type BillingWebhookEventRow = {
  id: string;
  provider: Provider;
  event_id: string;
  payload_hash: string;
  status: Status;
  attempts: number;
  received_at: string;
  processed_at: string | null;
  last_error: string | null;
};

type BillingWebhookStats = {
  total: string;
  pending: string;
  processed: string;
  failed: string;
  stale_pending: string;
};

export default function AdminBillingWebhooksPage() {
  const [rows, setRows] = useState<BillingWebhookEventRow[]>([]);
  const [stats, setStats] = useState<BillingWebhookStats>({
    total: "0",
    pending: "0",
    processed: "0",
    failed: "0",
    stale_pending: "0",
  });
  const [provider, setProvider] = useState<Provider | "all">("all");
  const [status, setStatus] = useState<Status | "all">("all");
  const [message, setMessage] = useState("");

  const query = useMemo(() => {
    const params = new URLSearchParams();
    params.set("limit", "300");
    if (provider !== "all") params.set("provider", provider);
    if (status !== "all") params.set("status", status);
    return params.toString();
  }, [provider, status]);

  async function load() {
    try {
      const data = await api<{ events: BillingWebhookEventRow[]; stats: BillingWebhookStats }>(
        `/v1/admin/billing-webhooks?${query}`,
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
      <h3>Billing Webhook Operations</h3>
      <p className="muted">{message}</p>

      <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        <span className="nav-pill">Total: {stats.total}</span>
        <span className="nav-pill">Pending: {stats.pending}</span>
        <span className="nav-pill">Processed: {stats.processed}</span>
        <span className="nav-pill">Failed: {stats.failed}</span>
        <span className="nav-pill">Stale Pending: {stats.stale_pending}</span>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <select value={provider} onChange={(event) => setProvider(event.target.value as Provider | "all")}>
          <option value="all">All providers</option>
          <option value="stripe">Stripe</option>
          <option value="razorpay">Razorpay</option>
          <option value="paypal">PayPal</option>
        </select>
        <select value={status} onChange={(event) => setStatus(event.target.value as Status | "all")}>
          <option value="all">All statuses</option>
          <option value="pending">Pending</option>
          <option value="processed">Processed</option>
          <option value="failed">Failed</option>
        </select>
        <button onClick={() => void load()}>Refresh</button>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Provider</th>
            <th>Status</th>
            <th>Attempts</th>
            <th>Event ID</th>
            <th>Processed</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{new Date(row.received_at).toLocaleString()}</td>
              <td>{row.provider}</td>
              <td>{row.status}</td>
              <td>{row.attempts}</td>
              <td style={{ maxWidth: 240, whiteSpace: "normal", wordBreak: "break-all" }}>{row.event_id}</td>
              <td>{row.processed_at ? new Date(row.processed_at).toLocaleString() : "-"}</td>
              <td style={{ maxWidth: 320, whiteSpace: "normal" }}>{row.last_error ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
