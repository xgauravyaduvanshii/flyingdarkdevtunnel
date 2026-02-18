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
  prev_hash: string | null;
  entry_hash: string | null;
  created_at: string;
};

type IntegrityResponse = {
  ok: boolean;
  scanned: number;
  valid: number;
  mismatches: Array<{ id: string; reason: string }>;
  latestHash: string | null;
};

export default function AdminAuditPage() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityResponse | null>(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const [data, integrityData] = await Promise.all([
          api<{ audit: AuditRow[] }>("/v1/admin/audit?limit=200"),
          api<IntegrityResponse>("/v1/admin/audit/integrity?limit=2000"),
        ]);
        setRows(data.audit);
        setIntegrity(integrityData);
      } catch (error) {
        setMessage(`Load failed: ${String(error)}`);
      }
    })();
  }, []);

  return (
    <section className="card">
      <h3>Audit log</h3>
      <p className="muted">{message}</p>
      {integrity && (
        <p className="muted">
          chain_ok={String(integrity.ok)}, scanned={integrity.scanned}, valid={integrity.valid}, mismatches=
          {integrity.mismatches.length}
        </p>
      )}
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
