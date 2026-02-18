"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type RelayEdge = {
  edge_id: string;
  region: string;
  status: "online" | "degraded" | "offline";
  capacity: number;
  in_flight: number;
  rejected_overlimit: string;
  last_heartbeat_at: string;
};

export default function AdminRelayEdgesPage() {
  const [edges, setEdges] = useState<RelayEdge[]>([]);
  const [message, setMessage] = useState("");

  async function load() {
    try {
      const data = await api<{ edges: RelayEdge[] }>("/v1/admin/relay-edges?limit=200");
      setEdges(data.edges);
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section className="card">
      <h3>Relay edges</h3>
      <p className="muted">{message}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Edge</th>
            <th>Region</th>
            <th>Status</th>
            <th>Capacity</th>
            <th>In flight</th>
            <th>Rejected</th>
            <th>Last heartbeat</th>
          </tr>
        </thead>
        <tbody>
          {edges.map((edge) => (
            <tr key={edge.edge_id}>
              <td>{edge.edge_id}</td>
              <td>{edge.region}</td>
              <td>{edge.status}</td>
              <td>{edge.capacity}</td>
              <td>{edge.in_flight}</td>
              <td>{edge.rejected_overlimit}</td>
              <td>{new Date(edge.last_heartbeat_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
