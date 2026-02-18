"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type UserRow = {
  id: string;
  email: string;
  role: string;
  org_id: string;
  created_at: string;
};

export default function AdminUsersPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const data = await api<{ users: UserRow[] }>("/v1/admin/users");
      setUsers(data.users);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function setPlan(userId: string, planCode: "free" | "pro" | "team") {
    try {
      await api(`/v1/admin/users/${userId}/plan`, {
        method: "PATCH",
        body: JSON.stringify({ planCode }),
      });
      setMessage(`Plan set to ${planCode} for ${userId}`);
    } catch (error) {
      setMessage(`Plan update failed: ${String(error)}`);
    }
  }

  return (
    <section className="card">
      <h3>Admin users</h3>
      <p className="muted">{message}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Org</th>
            <th>Created</th>
            <th>Plan</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.email}</td>
              <td>{u.role}</td>
              <td>{u.org_id}</td>
              <td>{new Date(u.created_at).toLocaleDateString()}</td>
              <td>
                <button className="button secondary" onClick={() => void setPlan(u.id, "free")}>Free</button>
                <button style={{ marginLeft: 8 }} onClick={() => void setPlan(u.id, "pro")}>Pro</button>
                <button style={{ marginLeft: 8 }} onClick={() => void setPlan(u.id, "team")}>Team</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
