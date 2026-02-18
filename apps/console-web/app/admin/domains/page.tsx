"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type AdminDomainRow = {
  id: string;
  domain: string;
  org_id: string;
  verified: boolean;
  tls_status: string;
  tls_mode: "termination" | "passthrough";
  target_tunnel_id: string | null;
  tunnel_name: string | null;
  certificate_ref: string | null;
  tls_last_checked_at: string | null;
  tls_not_after: string | null;
  tls_last_error: string | null;
  cert_failure_policy: "standard" | "strict" | "hold";
  cert_failure_count: number;
  cert_retry_backoff_seconds: number;
  cert_next_retry_at: string | null;
  created_at: string;
};

export default function AdminDomainsPage() {
  const [rows, setRows] = useState<AdminDomainRow[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const data = await api<{ domains: AdminDomainRow[] }>("/v1/admin/domains");
        setRows(data.domains);
      } catch (error) {
        setMessage(`Load failed: ${String(error)}`);
      }
    })();
  }, []);

  return (
    <section className="card">
      <h3>Admin domains</h3>
      <p className="muted">{message}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Org</th>
            <th>TLS mode</th>
            <th>Status</th>
            <th>Tunnel</th>
            <th>Expiry</th>
            <th>Last check</th>
            <th>Policy</th>
            <th>Failures</th>
            <th>Next retry</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{row.domain}</td>
              <td>{row.org_id}</td>
              <td>{row.tls_mode}</td>
              <td>{row.verified ? row.tls_status : "unverified"}</td>
              <td>{row.tunnel_name ?? row.target_tunnel_id ?? "-"}</td>
              <td>{row.tls_not_after ? new Date(row.tls_not_after).toLocaleString() : "-"}</td>
              <td>{row.tls_last_checked_at ? new Date(row.tls_last_checked_at).toLocaleString() : "-"}</td>
              <td>{row.cert_failure_policy}</td>
              <td>{row.cert_failure_count}</td>
              <td>{row.cert_next_retry_at ? new Date(row.cert_next_retry_at).toLocaleString() : "-"}</td>
              <td style={{ maxWidth: 260, whiteSpace: "normal" }}>{row.tls_last_error ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
