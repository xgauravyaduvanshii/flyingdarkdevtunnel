"use client";

import { FormEvent, useState } from "react";
import { api } from "@/lib/api";

type RequestLog = {
  id: string;
  method: string;
  path: string;
  status_code: number | null;
  started_at: string;
};

export default function InspectPage() {
  const [tunnelId, setTunnelId] = useState("");
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [message, setMessage] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const data = await api<{ requests: RequestLog[] }>(`/v1/requests?tunnelId=${encodeURIComponent(tunnelId)}`);
      setLogs(data.requests);
      setMessage(`Loaded ${data.requests.length} requests`);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  async function replay(id: string) {
    await api(`/v1/requests/${id}/replay`, { method: "POST", body: JSON.stringify({}) });
    setMessage(`Replay queued for ${id}`);
  }

  return (
    <div className="grid">
      <section className="card">
        <h3>Request inspector</h3>
        <form onSubmit={onSubmit} className="grid cols-2">
          <div>
            <label>Tunnel ID</label>
            <input value={tunnelId} onChange={(e) => setTunnelId(e.target.value)} placeholder="UUID" required />
          </div>
          <div style={{ alignSelf: "end" }}>
            <button type="submit">Load requests</button>
          </div>
        </form>
        <p className="muted">{message}</p>
      </section>
      <section className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th>Started</th>
              <th>Replay</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((row) => (
              <tr key={row.id}>
                <td>{row.method}</td>
                <td>{row.path}</td>
                <td>{row.status_code ?? "-"}</td>
                <td>{new Date(row.started_at).toLocaleString()}</td>
                <td>
                  <button onClick={() => void replay(row.id)}>Replay</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
