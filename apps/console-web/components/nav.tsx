"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  ["/", "Overview"],
  ["/tunnels", "Tunnels"],
  ["/inspect", "Inspect"],
  ["/domains", "Domains"],
  ["/billing", "Billing"],
  ["/admin/users", "Admin"],
  ["/admin/domains", "Domains Admin"],
  ["/admin/billing-webhooks", "Billing Ops"],
  ["/admin/billing-finance-events", "Finance Ops"],
] as const;

export function TopNav() {
  const pathname = usePathname();

  return (
    <header className="nav">
      <div>
        <h2 style={{ margin: 0 }}>TunnelForge</h2>
        <small className="muted">Secure temporary and reserved tunnels</small>
      </div>
      <nav className="nav-links">
        {links.map(([href, label]) => {
          const active = pathname === href || (href !== "/" && pathname.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              className="nav-pill"
              style={{
                borderColor: active ? "rgba(251, 146, 60, 0.7)" : undefined,
                background: active ? "rgba(251, 146, 60, 0.2)" : undefined,
              }}
            >
              {label}
            </Link>
          );
        })}
        <Link href="/login" className="nav-pill">
          Login
        </Link>
      </nav>
    </header>
  );
}
