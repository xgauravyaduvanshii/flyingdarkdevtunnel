"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type TunnelRow = {
  id: string;
  org_id: string;
  name: string;
  protocol: string;
  public_url: string | null;
  status: string;
  created_at: string;
};

export default function AdminTunnelsPage() {
  const [rows, setRows] = useState<TunnelRow[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const data = await api<{ tunnels: TunnelRow[] }>("/v1/admin/tunnels");
        setRows(data.tunnels);
      } catch (error) {
        setMessage(`Load failed: ${String(error)}`);
      }
    })();
  }, []);

  return (
    <section className="card">
      <h3>Admin tunnels</h3>
      <p className="muted">{message}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Org</th>
            <th>Protocol</th>
            <th>Public URL</th>
            <th>Status</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{row.name}</td>
              <td>{row.org_id}</td>
              <td>{row.protocol}</td>
              <td>{row.public_url ?? "-"}</td>
              <td>{row.status}</td>
              <td>{new Date(row.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
