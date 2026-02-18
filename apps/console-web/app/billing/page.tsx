"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Plan = {
  id: string;
  code: string;
  name: string;
  max_tunnels: number;
  custom_domains: boolean;
  ip_allowlist: boolean;
};

export default function BillingPage() {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const data = await api<{ plans: Plan[] }>("/v1/plans");
        setPlans(data.plans);
      } catch (error) {
        setMessage(`Failed loading plans: ${String(error)}`);
      }
    })();
  }, []);

  async function checkout(planCode: "pro" | "team") {
    try {
      const session = await api<{ checkoutUrl: string }>("/v1/billing/checkout-session", {
        method: "POST",
        body: JSON.stringify({ planCode }),
      });
      setMessage(`Checkout session: ${session.checkoutUrl}`);
    } catch (error) {
      setMessage(`Checkout failed: ${String(error)}`);
    }
  }

  return (
    <div className="grid cols-3">
      {plans.map((plan) => (
        <section className="card" key={plan.id}>
          <h3>{plan.name}</h3>
          <p className="muted">{plan.max_tunnels} tunnels</p>
          <p className="muted">Custom domains: {String(plan.custom_domains)}</p>
          <p className="muted">IP allowlist: {String(plan.ip_allowlist)}</p>
          {(plan.code === "pro" || plan.code === "team") && (
            <button onClick={() => void checkout(plan.code as "pro" | "team")}>Upgrade to {plan.name}</button>
          )}
        </section>
      ))}
      <p className="muted">{message}</p>
    </div>
  );
}
