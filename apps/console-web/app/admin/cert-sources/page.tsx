"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type CertSourceRow = {
  source: string;
  cluster_id: string;
  last_event_id: string | null;
  last_event_type: string | null;
  last_status: "accepted" | "signature_failed" | null;
  events_total: string;
  signature_failures: string;
  last_seen_at: string;
};

export default function AdminCertSourcesPage() {
  const [sources, setSources] = useState<CertSourceRow[]>([]);
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const data = await api<{ sources: CertSourceRow[] }>("/v1/admin/cert-sources?limit=200");
      setSources(data.sources);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section className="card">
      <h3>Certificate sources</h3>
      <p className="muted">{message}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Source</th>
            <th>Cluster</th>
            <th>Status</th>
            <th>Events</th>
            <th>Signature failures</th>
            <th>Last event</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {sources.map((row) => (
            <tr key={`${row.source}:${row.cluster_id}`}>
              <td>{row.source}</td>
              <td>{row.cluster_id}</td>
              <td>{row.last_status ?? "-"}</td>
              <td>{row.events_total}</td>
              <td>{row.signature_failures}</td>
              <td>{row.last_event_type ?? row.last_event_id ?? "-"}</td>
              <td>{new Date(row.last_seen_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
