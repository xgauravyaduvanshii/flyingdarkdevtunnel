"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type Tunnel = {
  id: string;
  name: string;
  protocol: "http" | "https" | "tcp";
  local_addr: string;
  subdomain: string | null;
  public_url: string | null;
  status: "active" | "stopped" | "error";
  inspect: boolean;
};

export default function TunnelsPage() {
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [name, setName] = useState("my-local-app");
  const [protocol, setProtocol] = useState<"http" | "https" | "tcp">("http");
  const [localAddr, setLocalAddr] = useState("http://localhost:3000");
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const data = await api<{ tunnels: Tunnel[] }>("/v1/tunnels");
      setTunnels(data.tunnels);
    } catch (error) {
      setMessage(`Failed to load tunnels: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function createTunnel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await api("/v1/tunnels", {
        method: "POST",
        body: JSON.stringify({ name, protocol, localAddr, inspect: true }),
      });
      setMessage("Tunnel created");
      await load();
    } catch (error) {
      setMessage(`Create failed: ${String(error)}`);
    }
  }

  async function startTunnel(id: string) {
    await api(`/v1/tunnels/${id}/start`, { method: "POST", body: JSON.stringify({}) });
    await load();
  }

  async function stopTunnel(id: string) {
    await api(`/v1/tunnels/${id}/stop`, { method: "POST", body: JSON.stringify({}) });
    await load();
  }

  return (
    <div className="grid cols-2">
      <section className="card">
        <h3>Create tunnel</h3>
        <form onSubmit={createTunnel} className="grid">
          <div>
            <label>Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div>
            <label>Protocol</label>
            <select value={protocol} onChange={(e) => setProtocol(e.target.value as any)}>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="tcp">TCP</option>
            </select>
          </div>
          <div>
            <label>Local address</label>
            <input value={localAddr} onChange={(e) => setLocalAddr(e.target.value)} required />
          </div>
          <button type="submit">Create</button>
        </form>
        <p className="muted" style={{ marginTop: 10 }}>{message}</p>
      </section>

      <section className="card">
        <h3>Active and saved tunnels</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Protocol</th>
              <th>Public URL</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {tunnels.map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td>{t.protocol}</td>
                <td>{t.public_url ?? "-"}</td>
                <td>{t.status}</td>
                <td>
                  {t.status === "active" ? (
                    <button className="button secondary" onClick={() => void stopTunnel(t.id)}>Stop</button>
                  ) : (
                    <button onClick={() => void startTunnel(t.id)}>Start</button>
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
