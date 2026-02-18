"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type MemberRow = {
  id: string;
  user_id: string;
  org_id: string;
  role: "owner" | "admin" | "member" | "billing" | "viewer";
  email: string;
  created_at: string;
};

const roles: MemberRow["role"][] = ["owner", "admin", "member", "billing", "viewer"];

export default function AdminMembersPage() {
  const [members, setMembers] = useState<MemberRow[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<MemberRow["role"]>("member");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await api<{ members: MemberRow[] }>("/v1/admin/members");
      setMembers(data.members);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function addMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      await api("/v1/admin/members", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), role }),
      });
      setMessage(`Membership upserted for ${email}`);
      setEmail("");
      await load();
    } catch (error) {
      setMessage(`Member update failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function changeRole(userId: string, nextRole: MemberRow["role"]) {
    setBusy(true);
    try {
      await api(`/v1/admin/members/${userId}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role: nextRole }),
      });
      setMessage(`Role updated to ${nextRole}`);
      await load();
    } catch (error) {
      setMessage(`Role update failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  async function removeMember(userId: string) {
    if (!window.confirm("Remove this member from organization?")) {
      return;
    }

    setBusy(true);
    try {
      await api(`/v1/admin/members/${userId}`, { method: "DELETE" });
      setMessage("Member removed");
      await load();
    } catch (error) {
      setMessage(`Remove failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid cols-2">
      <section className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>Team members</h3>
        <p className="muted">{message}</p>
        <table className="table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {members.map((member) => (
              <tr key={member.user_id}>
                <td>{member.email}</td>
                <td>{member.role}</td>
                <td>{new Date(member.created_at).toLocaleString()}</td>
                <td>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {roles.map((targetRole) => (
                      <button
                        key={targetRole}
                        className={targetRole === member.role ? "button secondary" : "button"}
                        disabled={busy || targetRole === member.role}
                        onClick={() => void changeRole(member.user_id, targetRole)}
                      >
                        {targetRole}
                      </button>
                    ))}
                    <button className="button secondary" disabled={busy} onClick={() => void removeMember(member.user_id)}>
                      Remove
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>Add member</h3>
        <form className="grid" onSubmit={addMember}>
          <div>
            <label>Email</label>
            <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="xgauravyaduvanshii@gmail.com" />
          </div>
          <div>
            <label>Role</label>
            <select value={role} onChange={(event) => setRole(event.target.value as MemberRow["role"])}>
              {roles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <button disabled={busy || !email.trim()} type="submit">
            Save membership
          </button>
        </form>
      </section>
    </div>
  );
}
