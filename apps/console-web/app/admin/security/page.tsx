"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type SecurityAnomaly = {
  id: string;
  category: "auth_failed" | "rate_limited" | "token_revoked" | "abuse_signal";
  severity: "low" | "medium" | "high";
  ip: string | null;
  user_id: string | null;
  org_id: string | null;
  route: string | null;
  details: Record<string, unknown> | null;
  created_at: string;
};

type RevokedToken = {
  id: string;
  jti: string;
  token_type: "access" | "refresh" | "agent";
  user_id: string | null;
  org_id: string | null;
  expires_at: string | null;
  reason: string | null;
  created_at: string;
};

type RotationHealth = {
  thresholdDays: number;
  totalUsers: number;
  staleUsers: number;
  users: Array<{
    user_id: string;
    email: string;
    role: string;
    age_days: number;
    stale: boolean;
  }>;
};

export default function AdminSecurityPage() {
  const [anomalies, setAnomalies] = useState<SecurityAnomaly[]>([]);
  const [tokens, setTokens] = useState<RevokedToken[]>([]);
  const [rotationHealth, setRotationHealth] = useState<RotationHealth | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [anomalyData, tokenData, rotationData] = await Promise.all([
        api<{ anomalies: SecurityAnomaly[] }>("/v1/admin/security-anomalies?limit=200"),
        api<{ tokens: RevokedToken[] }>("/v1/admin/revoked-tokens?limit=200"),
        api<RotationHealth>("/v1/admin/secrets/rotation-health?maxAgeDays=90"),
      ]);
      setAnomalies(anomalyData.anomalies);
      setTokens(tokenData.tokens);
      setRotationHealth(rotationData);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function pruneExpired() {
    setBusy(true);
    try {
      const response = await api<{ deleted: number; before: string }>("/v1/admin/revoked-tokens/prune", {
        method: "POST",
        body: JSON.stringify({}),
      });
      setMessage(`Pruned ${response.deleted} expired revoked tokens`);
      await load();
    } catch (error) {
      setMessage(`Prune failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function runRotationScan() {
    setBusy(true);
    try {
      const response = await api<{ staleCount: number; thresholdDays: number }>("/v1/admin/secrets/rotation/scan", {
        method: "POST",
        body: JSON.stringify({ maxAgeDays: 90 }),
      });
      setMessage(`Rotation scan complete: stale=${response.staleCount} (threshold ${response.thresholdDays} days)`);
      await load();
    } catch (error) {
      setMessage(`Rotation scan failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-2">
      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>Security anomalies</h3>
        <p className="muted">{message}</p>
        <table className="table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Category</th>
              <th>Severity</th>
              <th>IP</th>
              <th>Org</th>
              <th>Route</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {anomalies.map((row) => (
              <tr key={row.id}>
                <td>{new Date(row.created_at).toLocaleString()}</td>
                <td>{row.category}</td>
                <td>{row.severity}</td>
                <td>{row.ip ?? "-"}</td>
                <td>{row.org_id ?? "-"}</td>
                <td>{row.route ?? "-"}</td>
                <td style={{ maxWidth: 360, whiteSpace: "normal", wordBreak: "break-word" }}>
                  {row.details ? JSON.stringify(row.details) : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <h3>Secret rotation health</h3>
          <button className="button secondary" disabled={busy} onClick={() => void runRotationScan()}>
            Run rotation scan
          </button>
        </div>
        <p className="muted">
          {rotationHealth
            ? `Threshold ${rotationHealth.thresholdDays}d | stale ${rotationHealth.staleUsers}/${rotationHealth.totalUsers}`
            : "No rotation data"}
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Age (days)</th>
              <th>Stale</th>
            </tr>
          </thead>
          <tbody>
            {(rotationHealth?.users ?? []).map((row) => (
              <tr key={row.user_id}>
                <td>{row.email}</td>
                <td>{row.role}</td>
                <td>{row.age_days}</td>
                <td>{row.stale ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
          <h3>Revoked tokens</h3>
          <button className="button secondary" disabled={busy} onClick={() => void pruneExpired()}>
            Prune expired
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Type</th>
              <th>JTI</th>
              <th>Org</th>
              <th>User</th>
              <th>Expires</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((row) => (
              <tr key={row.id}>
                <td>{new Date(row.created_at).toLocaleString()}</td>
                <td>{row.token_type}</td>
                <td style={{ maxWidth: 280, overflowWrap: "anywhere" }}>{row.jti}</td>
                <td>{row.org_id ?? "-"}</td>
                <td>{row.user_id ?? "-"}</td>
                <td>{row.expires_at ? new Date(row.expires_at).toLocaleString() : "-"}</td>
                <td>{row.reason ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
