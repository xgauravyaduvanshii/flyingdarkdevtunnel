"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type DunningCase = {
  id: string;
  org_id: string;
  provider: "stripe" | "razorpay" | "paypal";
  subscription_ref: string;
  status: "open" | "recovered" | "closed";
  stage: number;
  retry_count: number;
  next_attempt_at: string | null;
  last_attempt_at: string | null;
  notification_count: number;
  last_error: string | null;
  latest_event_type: string | null;
  updated_at: string;
};

type DunningStats = {
  total: string;
  open: string;
  recovered: string;
  closed: string;
  due_now: string;
};

export default function AdminBillingDunningPage() {
  const [cases, setCases] = useState<DunningCase[]>([]);
  const [stats, setStats] = useState<DunningStats | null>(null);
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const data = await api<{ cases: DunningCase[]; stats: DunningStats }>("/v1/admin/billing-dunning?limit=200");
      setCases(data.cases);
      setStats(data.stats);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section className="card">
      <h3>Billing dunning operations</h3>
      <p className="muted">{message}</p>
      {stats && (
        <p className="muted">
          total={stats.total}, open={stats.open}, recovered={stats.recovered}, closed={stats.closed}, due_now={stats.due_now}
        </p>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Updated</th>
            <th>Org</th>
            <th>Provider</th>
            <th>Status</th>
            <th>Stage</th>
            <th>Retries</th>
            <th>Next attempt</th>
            <th>Event</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {cases.map((row) => (
            <tr key={row.id}>
              <td>{new Date(row.updated_at).toLocaleString()}</td>
              <td>{row.org_id}</td>
              <td>{row.provider}</td>
              <td>{row.status}</td>
              <td>{row.stage}</td>
              <td>{row.retry_count}</td>
              <td>{row.next_attempt_at ? new Date(row.next_attempt_at).toLocaleString() : "-"}</td>
              <td>{row.latest_event_type ?? "-"}</td>
              <td style={{ maxWidth: 280, whiteSpace: "normal", wordBreak: "break-word" }}>{row.last_error ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
