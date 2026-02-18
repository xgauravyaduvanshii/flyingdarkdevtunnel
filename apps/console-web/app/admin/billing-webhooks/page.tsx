"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";

type Provider = "stripe" | "razorpay" | "paypal";
type Status = "pending" | "processed" | "failed";

type BillingWebhookEventRow = {
  id: string;
  provider: Provider;
  event_id: string;
  provider_event_type: string | null;
  payload_hash: string;
  status: Status;
  attempts: number;
  replay_count: number;
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
  const [busy, setBusy] = useState(false);
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

  async function replayOne(id: string, force = false) {
    setBusy(true);
    try {
      const result = await api<{ ok: boolean; result: { status: string; message?: string } }>(
        `/v1/admin/billing-webhooks/${id}/replay`,
        { method: "POST", body: JSON.stringify({ force }) },
      );
      setMessage(`Replay result: ${result.result.status}${result.result.message ? ` (${result.result.message})` : ""}`);
      await load();
    } catch (error) {
      setMessage(`Replay failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function reconcileFailed() {
    setBusy(true);
    try {
      const payload: { provider?: Provider; limit: number; force: boolean } = { limit: 100, force: false };
      if (provider !== "all") payload.provider = provider;
      const summary = await api<{
        ok: boolean;
        attempted: number;
        processed: number;
        failed: number;
        skipped: number;
      }>("/v1/admin/billing-webhooks/reconcile", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setMessage(
        `Reconcile done: attempted=${summary.attempted}, processed=${summary.processed}, failed=${summary.failed}, skipped=${summary.skipped}`,
      );
      await load();
    } catch (error) {
      setMessage(`Reconcile failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

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
        <button onClick={() => void reconcileFailed()} disabled={busy}>
          Reconcile Failed
        </button>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Provider</th>
            <th>Type</th>
            <th>Status</th>
            <th>Attempts</th>
            <th>Replays</th>
            <th>Event ID</th>
            <th>Processed</th>
            <th>Error</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{new Date(row.received_at).toLocaleString()}</td>
              <td>{row.provider}</td>
              <td>{row.provider_event_type ?? "-"}</td>
              <td>{row.status}</td>
              <td>{row.attempts}</td>
              <td>{row.replay_count}</td>
              <td style={{ maxWidth: 240, whiteSpace: "normal", wordBreak: "break-all" }}>{row.event_id}</td>
              <td>{row.processed_at ? new Date(row.processed_at).toLocaleString() : "-"}</td>
              <td style={{ maxWidth: 320, whiteSpace: "normal" }}>{row.last_error ?? "-"}</td>
              <td>
                {row.status === "failed" ? (
                  <button className="button secondary" disabled={busy} onClick={() => void replayOne(row.id)}>
                    Replay
                  </button>
                ) : (
                  "-"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
