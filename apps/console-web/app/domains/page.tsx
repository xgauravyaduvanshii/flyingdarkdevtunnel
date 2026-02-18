"use client";

import { FormEvent, useState } from "react";
import { api } from "@/lib/api";

type DomainRow = { id: string; domain: string; verificationToken: string; verified: boolean };

export default function DomainsPage() {
  const [domain, setDomain] = useState("");
  const [rows, setRows] = useState<DomainRow[]>([]);
  const [message, setMessage] = useState("");

  async function onAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const created = await api<DomainRow>("/v1/domains/custom", {
        method: "POST",
        body: JSON.stringify({ domain }),
      });
      setRows((prev) => [created, ...prev]);
      setMessage("Domain created. Complete DNS verification then click verify.");
      setDomain("");
    } catch (error) {
      setMessage(`Create failed: ${String(error)}`);
    }
  }

  async function verify(id: string) {
    await api(`/v1/domains/custom/${id}/verify`, { method: "POST", body: JSON.stringify({}) });
    setRows((prev) => prev.map((row) => (row.id === id ? { ...row, verified: true } : row)));
  }

  async function remove(id: string) {
    await api(`/v1/domains/custom/${id}`, { method: "DELETE" });
    setRows((prev) => prev.filter((row) => row.id !== id));
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
              <th>Verify token</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.domain}</td>
                <td>{row.verificationToken}</td>
                <td>{row.verified ? "verified" : "pending"}</td>
                <td>
                  <button className="button secondary" onClick={() => void verify(row.id)}>
                    Verify
                  </button>
                  <button style={{ marginLeft: 8 }} onClick={() => void remove(row.id)}>
                    Delete
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
