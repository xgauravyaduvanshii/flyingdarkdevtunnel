"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type ReplicaRow = {
  id: string;
  domain: string;
  source_region: string;
  target_region: string;
  tls_mode: "termination" | "passthrough";
  tls_status: string;
  replication_state: "source" | "replicated" | "stale";
  lag_seconds: number;
  synced_at: string;
};

type ReplicaStats = {
  total: string;
  source: string;
  replicated: string;
  stale: string;
};

export default function AdminCertReplicationPage() {
  const [rows, setRows] = useState<ReplicaRow[]>([]);
  const [stats, setStats] = useState<ReplicaStats>({ total: "0", source: "0", replicated: "0", stale: "0" });
  const [targetRegion, setTargetRegion] = useState("");
  const [state, setState] = useState<"" | "source" | "replicated" | "stale">("");
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const query = new URLSearchParams({ limit: "500" });
      if (targetRegion.trim()) query.set("targetRegion", targetRegion.trim().toLowerCase());
      if (state) query.set("state", state);
      const data = await api<{ replicas: ReplicaRow[]; stats: ReplicaStats }>(`/v1/admin/domains/cert-replication?${query.toString()}`);
      setRows(data.replicas);
      setStats(data.stats);
      setMessage("");
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section className="card">
      <h3>Certificate replication</h3>
      <p className="muted">
        Total {stats.total} | source {stats.source} | replicated {stats.replicated} | stale {stats.stale}
      </p>
      <p className="muted">{message}</p>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr auto", marginBottom: 12 }}>
        <div>
          <label>Target region</label>
          <input value={targetRegion} onChange={(event) => setTargetRegion(event.target.value)} placeholder="us / eu / ap" />
        </div>
        <div>
          <label>State</label>
          <select value={state} onChange={(event) => setState(event.target.value as "" | "source" | "replicated" | "stale")}>
            <option value="">all</option>
            <option value="source">source</option>
            <option value="replicated">replicated</option>
            <option value="stale">stale</option>
          </select>
        </div>
        <button style={{ alignSelf: "end" }} onClick={() => void load()}>
          Refresh
        </button>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Source</th>
            <th>Target</th>
            <th>State</th>
            <th>TLS status</th>
            <th>Lag (s)</th>
            <th>Synced</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{row.domain}</td>
              <td>{row.source_region}</td>
              <td>{row.target_region}</td>
              <td>{row.replication_state}</td>
              <td>{row.tls_status}</td>
              <td>{row.lag_seconds}</td>
              <td>{new Date(row.synced_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
