"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type RoleTemplate = {
  id: string;
  template_key: string;
  role: "owner" | "admin" | "member" | "billing" | "viewer";
  description: string | null;
  updated_at: string;
};

export default function AdminRoleTemplatesPage() {
  const [templates, setTemplates] = useState<RoleTemplate[]>([]);
  const [templateKey, setTemplateKey] = useState("developer");
  const [role, setRole] = useState<RoleTemplate["role"]>("member");
  const [description, setDescription] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await api<{ templates: RoleTemplate[] }>("/v1/admin/role-templates");
      setTemplates(data.templates);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function upsertTemplate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      await api(`/v1/admin/role-templates/${encodeURIComponent(templateKey)}`, {
        method: "PUT",
        body: JSON.stringify({
          role,
          description: description || undefined,
        }),
      });
      setMessage(`Template ${templateKey} saved`);
      await load();
    } catch (error) {
      setMessage(`Save failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function removeTemplate(key: string) {
    setBusy(true);
    try {
      await api(`/v1/admin/role-templates/${encodeURIComponent(key)}`, { method: "DELETE" });
      setMessage(`Template ${key} deleted`);
      await load();
    } catch (error) {
      setMessage(`Delete failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-2">
      <section className="card">
        <h3>Role template editor</h3>
        <p className="muted">{message}</p>
        <form className="grid" onSubmit={upsertTemplate}>
          <div>
            <label>Template key</label>
            <input value={templateKey} onChange={(event) => setTemplateKey(event.target.value)} placeholder="developer" />
          </div>
          <div>
            <label>Role</label>
            <select value={role} onChange={(event) => setRole(event.target.value as RoleTemplate["role"])}>
              <option value="member">member</option>
              <option value="viewer">viewer</option>
              <option value="billing">billing</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
            </select>
          </div>
          <div>
            <label>Description</label>
            <input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Engineering developer access profile" />
          </div>
          <button disabled={busy} type="submit">
            Save template
          </button>
        </form>
      </section>

      <section className="card">
        <h3>Current templates</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Role</th>
              <th>Description</th>
              <th>Updated</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {templates.map((template) => (
              <tr key={template.id}>
                <td>{template.template_key}</td>
                <td>{template.role}</td>
                <td>{template.description ?? "-"}</td>
                <td>{new Date(template.updated_at).toLocaleString()}</td>
                <td>
                  <button className="button secondary" disabled={busy} onClick={() => void removeTemplate(template.template_key)}>
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
