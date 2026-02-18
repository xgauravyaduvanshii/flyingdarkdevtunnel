"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type CertEvent = {
  id: string;
  source: string;
  cluster_id: string | null;
  domain: string;
  event_type: string;
  status: "pending" | "applied" | "failed";
  retry_count: number;
  next_retry_at: string | null;
  last_error: string | null;
  route_region: string | null;
  created_at: string;
};

type CertRegionSummary = {
  region: string;
  total: string;
  issued: string;
  expiring: string;
  tls_error: string;
  pending_issue: string;
  pending_route: string;
  passthrough_unverified: string;
  last_event_at: string | null;
};

export default function AdminCertEventsPage() {
  const [events, setEvents] = useState<CertEvent[]>([]);
  const [regions, setRegions] = useState<CertRegionSummary[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState("");
  const [clusterId, setClusterId] = useState("");

  async function load() {
    try {
      const [eventData, regionData] = await Promise.all([
        api<{ events: CertEvent[] }>("/v1/admin/cert-events?limit=200"),
        api<{ regions: CertRegionSummary[] }>("/v1/admin/domains/cert-region-summary"),
      ]);
      setEvents(eventData.events);
      setRegions(regionData.regions);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function replayOne(id: string) {
    setBusy(true);
    try {
      await api(`/v1/admin/cert-events/${id}/replay`, {
        method: "POST",
        body: JSON.stringify({ force: true, resetRetry: true }),
      });
      setMessage(`Replayed certificate event: ${id}`);
      await load();
    } catch (error) {
      setMessage(`Replay failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function replayBulk(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const response = await api<{ replayed: number; attempted: number }>("/v1/admin/cert-events/replay", {
        method: "POST",
        body: JSON.stringify({
          status: "failed",
          source: source || undefined,
          clusterId: clusterId || undefined,
          limit: 200,
          resetRetry: true,
        }),
      });
      setMessage(`Bulk replay complete: ${response.replayed}/${response.attempted} queued`);
      await load();
    } catch (error) {
      setMessage(`Bulk replay failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-2">
      <section className="card">
        <h3>Dead-letter replay</h3>
        <p className="muted">{message}</p>
        <form className="grid" onSubmit={replayBulk}>
          <div>
            <label>Source (optional)</label>
            <input value={source} onChange={(event) => setSource(event.target.value)} placeholder="cert_manager" />
          </div>
          <div>
            <label>Cluster ID (optional)</label>
            <input value={clusterId} onChange={(event) => setClusterId(event.target.value)} placeholder="cluster-eu" />
          </div>
          <button disabled={busy} type="submit">
            Replay failed events
          </button>
        </form>
      </section>

      <section className="card">
        <h3>Certificate region summary</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Region</th>
              <th>Total</th>
              <th>Issued</th>
              <th>Errors</th>
              <th>Pending</th>
              <th>Last event</th>
            </tr>
          </thead>
          <tbody>
            {regions.map((row) => (
              <tr key={row.region}>
                <td>{row.region}</td>
                <td>{row.total}</td>
                <td>{row.issued}</td>
                <td>{row.tls_error}</td>
                <td>{Number.parseInt(row.pending_issue, 10) + Number.parseInt(row.pending_route, 10)}</td>
                <td>{row.last_event_at ? new Date(row.last_event_at).toLocaleString() : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>Certificate lifecycle events</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Source</th>
              <th>Cluster</th>
              <th>Domain</th>
              <th>Type</th>
              <th>Status</th>
              <th>Region</th>
              <th>Retries</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {events.map((row) => (
              <tr key={row.id}>
                <td>{new Date(row.created_at).toLocaleString()}</td>
                <td>{row.source}</td>
                <td>{row.cluster_id ?? "-"}</td>
                <td>{row.domain}</td>
                <td>{row.event_type}</td>
                <td>{row.status}</td>
                <td>{row.route_region ?? "-"}</td>
                <td>{row.retry_count}</td>
                <td>
                  <button className="button secondary" disabled={busy} onClick={() => void replayOne(row.id)}>
                    Replay
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
