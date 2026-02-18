"use client";

import { FormEvent, useState } from "react";
import { api, setToken } from "@/lib/api";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [message, setMessage] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("Creating account...");

    try {
      const data = await api<{ accessToken: string; authtoken: string }>("/v1/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password, orgName }),
      });
      setToken(data.accessToken);
      setMessage(`Registered. Save this authtoken safely: ${data.authtoken}`);
    } catch (error) {
      setMessage(`Register failed: ${String(error)}`);
    }
  }

  return (
    <section className="card" style={{ maxWidth: 620 }}>
      <h3>Register</h3>
      <form onSubmit={onSubmit} className="grid">
        <div>
          <label>Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
        </div>
        <div>
          <label>Password</label>
          <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" minLength={8} required />
        </div>
        <div>
          <label>Organization name</label>
          <input value={orgName} onChange={(e) => setOrgName(e.target.value)} />
        </div>
        <button type="submit">Create account</button>
      </form>
      <p className="muted" style={{ marginTop: 12 }}>{message}</p>
    </section>
  );
}
