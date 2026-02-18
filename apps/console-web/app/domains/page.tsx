"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type DomainRow = {
  id: string;
  domain: string;
  verified: boolean;
  verification_token: string;
  tls_mode: "termination" | "passthrough";
  target_tunnel_id: string | null;
  tls_status: string;
  certificate_ref: string | null;
  tls_last_checked_at: string | null;
  tls_not_after: string | null;
  tls_last_error: string | null;
  cert_failure_policy: "standard" | "strict" | "hold";
  cert_failure_count: number;
  cert_next_retry_at: string | null;
};

type TunnelRow = {
  id: string;
  name: string;
  protocol: "http" | "https" | "tcp";
};

export default function DomainsPage() {
  const [domain, setDomain] = useState("");
  const [tlsMode, setTlsMode] = useState<"termination" | "passthrough">("termination");
  const [rows, setRows] = useState<DomainRow[]>([]);
  const [tunnels, setTunnels] = useState<TunnelRow[]>([]);
  const [routeTunnelId, setRouteTunnelId] = useState<Record<string, string>>({});
  const [policyByDomainId, setPolicyByDomainId] = useState<Record<string, DomainRow["cert_failure_policy"]>>({});
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const [domainsRes, tunnelsRes] = await Promise.all([
        api<{ domains: DomainRow[] }>("/v1/domains/custom"),
        api<{ tunnels: TunnelRow[] }>("/v1/tunnels"),
      ]);
      setRows(domainsRes.domains);
      setTunnels(tunnelsRes.tunnels);
      setPolicyByDomainId(
        Object.fromEntries(domainsRes.domains.map((row) => [row.id, row.cert_failure_policy ?? "standard"])) as Record<
          string,
          DomainRow["cert_failure_policy"]
        >,
      );
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function onAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await api("/v1/domains/custom", {
        method: "POST",
        body: JSON.stringify({ domain, tlsMode }),
      });
      setMessage("Domain created. Verify then route to a tunnel.");
      setDomain("");
      await load();
    } catch (error) {
      setMessage(`Create failed: ${String(error)}`);
    }
  }

  async function verify(id: string) {
    await api(`/v1/domains/custom/${id}/verify`, { method: "POST", body: JSON.stringify({}) });
    await load();
  }

  async function routeDomain(id: string) {
    const tunnelId = routeTunnelId[id];
    if (!tunnelId) {
      setMessage("Select a tunnel before routing");
      return;
    }

    const mode = rows.find((row) => row.id === id)?.tls_mode ?? "termination";
    await api(`/v1/domains/custom/${id}/route`, {
      method: "POST",
      body: JSON.stringify({ tunnelId, tlsMode: mode }),
    });
    await load();
  }

  async function unrouteDomain(id: string) {
    await api(`/v1/domains/custom/${id}/unroute`, { method: "POST", body: JSON.stringify({}) });
    await load();
  }

  async function remove(id: string) {
    await api(`/v1/domains/custom/${id}`, { method: "DELETE" });
    await load();
  }

  async function updateFailurePolicy(id: string) {
    const policy = policyByDomainId[id] ?? "standard";
    await api(`/v1/domains/custom/${id}/failure-policy`, {
      method: "PATCH",
      body: JSON.stringify({ policy }),
    });
    setMessage(`Failure policy updated: ${policy}`);
    await load();
  }

  return (
    <div className="grid cols-2">
      <section className="card">
        <h3>Add custom domain</h3>
        <form onSubmit={onAdd} className="grid">
          <div>
            <label>Domain</label>
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="api.example.com" required />
          </div>
          <div>
            <label>TLS mode</label>
            <select value={tlsMode} onChange={(e) => setTlsMode(e.target.value as "termination" | "passthrough")}> 
              <option value="termination">Termination</option>
              <option value="passthrough">Passthrough</option>
            </select>
          </div>
          <button type="submit">Add domain</button>
        </form>
        <p className="muted" style={{ marginTop: 10 }}>{message}</p>
      </section>

      <section className="card">
        <h3>Custom domains</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>TLS mode</th>
              <th>Status</th>
              <th>Policy</th>
              <th>Expiry</th>
              <th>Retries</th>
              <th>Token</th>
              <th>Tunnel</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.domain}</td>
                <td>{row.tls_mode}</td>
                <td>{row.verified ? `verified (${row.tls_status})` : "pending"}</td>
                <td>
                  <select
                    value={policyByDomainId[row.id] ?? row.cert_failure_policy}
                    onChange={(e) =>
                      setPolicyByDomainId((prev) => ({
                        ...prev,
                        [row.id]: e.target.value as DomainRow["cert_failure_policy"],
                      }))
                    }
                  >
                    <option value="standard">standard</option>
                    <option value="strict">strict</option>
                    <option value="hold">hold</option>
                  </select>
                </td>
                <td>{row.tls_not_after ? new Date(row.tls_not_after).toLocaleDateString() : "-"}</td>
                <td>
                  {row.cert_failure_count}
                  {row.cert_next_retry_at ? (
                    <p className="muted" style={{ marginTop: 4 }}>
                      next: {new Date(row.cert_next_retry_at).toLocaleString()}
                    </p>
                  ) : null}
                </td>
                <td style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis" }}>{row.verification_token}</td>
                <td>
                  <select
                    value={routeTunnelId[row.id] ?? row.target_tunnel_id ?? ""}
                    onChange={(e) => setRouteTunnelId((prev) => ({ ...prev, [row.id]: e.target.value }))}
                  >
                    <option value="">Select tunnel</option>
                    {tunnels.map((tunnel) => (
                      <option key={tunnel.id} value={tunnel.id}>
                        {tunnel.name} ({tunnel.protocol})
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <button className="button secondary" onClick={() => void verify(row.id)}>Verify</button>
                  <button style={{ marginLeft: 8 }} onClick={() => void routeDomain(row.id)}>Route</button>
                  <button style={{ marginLeft: 8 }} onClick={() => void unrouteDomain(row.id)}>Unroute</button>
                  <button style={{ marginLeft: 8 }} onClick={() => void updateFailurePolicy(row.id)}>Save policy</button>
                  <button style={{ marginLeft: 8 }} onClick={() => void remove(row.id)}>Delete</button>
                  {row.tls_last_error && (
                    <p className="muted" style={{ marginTop: 8, maxWidth: 260, whiteSpace: "normal" }}>
                      TLS error: {row.tls_last_error}
                    </p>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
