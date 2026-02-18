"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type AuditRow = {
  id: string;
  actor_user_id: string | null;
  org_id: string | null;
  action: string;
  entity_type: string;
  entity_id: string;
  created_at: string;
};

export default function AdminAuditPage() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const data = await api<{ audit: AuditRow[] }>("/v1/admin/audit?limit=200");
        setRows(data.audit);
      } catch (error) {
        setMessage(`Load failed: ${String(error)}`);
      }
    })();
  }, []);

  return (
    <section className="card">
      <h3>Audit log</h3>
      <p className="muted">{message}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Entity</th>
            <th>Actor</th>
            <th>Org</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{new Date(row.created_at).toLocaleString()}</td>
              <td>{row.action}</td>
              <td>{row.entity_type}:{row.entity_id}</td>
              <td>{row.actor_user_id ?? "system"}</td>
              <td>{row.org_id ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
