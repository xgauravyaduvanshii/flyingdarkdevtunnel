"use client";

import { FormEvent, useState } from "react";
import { api, setToken } from "@/lib/api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("Logging in...");

    try {
      const data = await api<{ accessToken: string }>("/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      setToken(data.accessToken);
      setMessage("Login successful. Token stored in browser localStorage.");
    } catch (error) {
      setMessage(`Login failed: ${String(error)}`);
    }
  }

  return (
    <section className="card" style={{ maxWidth: 560 }}>
      <h3>Login</h3>
      <form onSubmit={onSubmit} className="grid">
        <div>
          <label>Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
        </div>
        <div>
          <label>Password</label>
          <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" required />
        </div>
        <button type="submit">Login</button>
      </form>
      <p className="muted" style={{ marginTop: 12 }}>{message}</p>
    </section>
  );
}
