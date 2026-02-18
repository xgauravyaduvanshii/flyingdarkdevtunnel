"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type ExportJob = {
  id: string;
  org_id: string | null;
  dataset: "finance_events" | "invoices" | "dunning";
  status: "pending" | "running" | "completed" | "failed";
  destination: "inline" | "webhook" | "s3" | "warehouse";
  sink_url: string | null;
  next_attempt_at: string | null;
  attempts: number;
  max_attempts: number;
  last_delivery_status: string | null;
  row_count: number | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
};

export default function AdminBillingReportsPage() {
  const [jobs, setJobs] = useState<ExportJob[]>([]);
  const [dataset, setDataset] = useState<ExportJob["dataset"]>("finance_events");
  const [destination, setDestination] = useState<ExportJob["destination"]>("inline");
  const [sinkUrl, setSinkUrl] = useState("");
  const [orgId, setOrgId] = useState("");
  const [maxAttempts, setMaxAttempts] = useState("5");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await api<{ exports: ExportJob[] }>("/v1/admin/billing-reports/exports?limit=200");
      setJobs(data.exports);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function createJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const response = await api<{ id: string }>("/v1/admin/billing-reports/exports", {
        method: "POST",
        body: JSON.stringify({
          dataset,
          destination,
          sinkUrl: destination === "webhook" || destination === "warehouse" ? sinkUrl || undefined : undefined,
          orgId: orgId || undefined,
          maxAttempts: Number.parseInt(maxAttempts, 10) || 5,
        }),
      });
      setMessage(`Report export job queued: ${response.id}`);
      await load();
    } catch (error) {
      setMessage(`Create failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function reconcileFailed() {
    setBusy(true);
    try {
      const response = await api<{ attempted: number; replayed: number }>("/v1/admin/billing-reports/exports/reconcile", {
        method: "POST",
        body: JSON.stringify({ status: "failed", limit: 200, resetAttempts: false }),
      });
      setMessage(`Reconcile queued ${response.replayed}/${response.attempted} failed exports`);
      await load();
    } catch (error) {
      setMessage(`Reconcile failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-2">
      <section className="card">
        <h3>Create billing export</h3>
        <p className="muted">{message}</p>
        <form className="grid" onSubmit={createJob}>
          <div>
            <label>Dataset</label>
            <select value={dataset} onChange={(event) => setDataset(event.target.value as ExportJob["dataset"])}>
              <option value="finance_events">Finance events</option>
              <option value="invoices">Invoices</option>
              <option value="dunning">Dunning</option>
            </select>
          </div>
          <div>
            <label>Destination</label>
            <select value={destination} onChange={(event) => setDestination(event.target.value as ExportJob["destination"])}>
              <option value="inline">Inline (DB)</option>
              <option value="webhook">Webhook</option>
              <option value="warehouse">Warehouse Loader</option>
              <option value="s3">S3/Object Store</option>
            </select>
          </div>
          <div>
            <label>Org ID (optional)</label>
            <input value={orgId} onChange={(event) => setOrgId(event.target.value)} placeholder="00000000-..." />
          </div>
          <div>
            <label>Max attempts</label>
            <input value={maxAttempts} onChange={(event) => setMaxAttempts(event.target.value)} />
          </div>
          {(destination === "webhook" || destination === "warehouse") && (
            <div>
              <label>Sink URL</label>
              <input value={sinkUrl} onChange={(event) => setSinkUrl(event.target.value)} placeholder="https://ops.example.com/reports" />
            </div>
          )}
          <button disabled={busy} type="submit">
            Queue export job
          </button>
        </form>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <h3>Export jobs</h3>
          <button className="button secondary" onClick={() => void reconcileFailed()} disabled={busy}>
            Reconcile failed
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Dataset</th>
              <th>Status</th>
              <th>Destination</th>
              <th>Attempts</th>
              <th>Next retry</th>
              <th>Delivery state</th>
              <th>Rows</th>
              <th>Org</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => (
              <tr key={job.id}>
                <td>{new Date(job.created_at).toLocaleString()}</td>
                <td>{job.dataset}</td>
                <td>{job.status}</td>
                <td>{job.destination}</td>
                <td>
                  {job.attempts}/{job.max_attempts}
                </td>
                <td>{job.next_attempt_at ? new Date(job.next_attempt_at).toLocaleString() : "-"}</td>
                <td>{job.last_delivery_status ?? "-"}</td>
                <td>{job.row_count ?? "-"}</td>
                <td>{job.org_id ?? "all"}</td>
                <td style={{ maxWidth: 320, whiteSpace: "normal", wordBreak: "break-word" }}>{job.error ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
