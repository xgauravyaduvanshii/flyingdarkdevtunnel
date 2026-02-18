"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type ScimEvent = {
  id: string;
  email: string;
  template_key: string | null;
  requested_role: string | null;
  resolved_role: string | null;
  action: "upsert" | "deactivate" | "delete";
  status: "applied" | "skipped" | "failed";
  details: Record<string, unknown> | null;
  created_at: string;
};

export default function AdminScimPage() {
  const [events, setEvents] = useState<ScimEvent[]>([]);
  const [email, setEmail] = useState("");
  const [templateKey, setTemplateKey] = useState("default");
  const [role, setRole] = useState("");
  const [active, setActive] = useState(true);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await api<{ events: ScimEvent[] }>("/v1/admin/scim/provision/events?limit=200");
      setEvents(data.events);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function submitProvision(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const response = await api<{ results: Array<{ email: string; status: string; message: string }> }>(
        "/v1/admin/scim/provision/users",
        {
          method: "POST",
          body: JSON.stringify({
            operations: [
              {
                email,
                active,
                templateKey: templateKey || undefined,
                role: role || undefined,
              },
            ],
          }),
        },
      );
      const result = response.results[0];
      setMessage(`${result.email}: ${result.status} (${result.message})`);
      await load();
    } catch (error) {
      setMessage(`Provision failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-2">
      <section className="card">
        <h3>SCIM user provision</h3>
        <p className="muted">{message}</p>
        <form className="grid" onSubmit={submitProvision}>
          <div>
            <label>Email</label>
            <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="user@example.com" required />
          </div>
          <div>
            <label>Template key</label>
            <input value={templateKey} onChange={(event) => setTemplateKey(event.target.value)} placeholder="developer" />
          </div>
          <div>
            <label>Direct role override (optional)</label>
            <select value={role} onChange={(event) => setRole(event.target.value)}>
              <option value="">(use template/default)</option>
              <option value="member">member</option>
              <option value="viewer">viewer</option>
              <option value="billing">billing</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
            </select>
          </div>
          <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input checked={active} onChange={(event) => setActive(event.target.checked)} type="checkbox" />
            Active membership
          </label>
          <button disabled={busy} type="submit">
            Run provision operation
          </button>
        </form>
      </section>

      <section className="card">
        <h3>SCIM event log</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Email</th>
              <th>Action</th>
              <th>Status</th>
              <th>Template</th>
              <th>Resolved role</th>
            </tr>
          </thead>
          <tbody>
            {events.map((row) => (
              <tr key={row.id}>
                <td>{new Date(row.created_at).toLocaleString()}</td>
                <td>{row.email}</td>
                <td>{row.action}</td>
                <td>{row.status}</td>
                <td>{row.template_key ?? "-"}</td>
                <td>{row.resolved_role ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
