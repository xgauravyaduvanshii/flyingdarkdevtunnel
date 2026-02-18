export default function HomePage() {
  return (
    <div className="grid cols-3">
      <section className="card">
        <h3>HTTP/HTTPS Tunnels</h3>
        <p className="muted">Expose local apps with random or reserved subdomains and inspect traffic live.</p>
      </section>
      <section className="card">
        <h3>TCP Tunnels</h3>
        <p className="muted">Forward SSH or database ports securely through controlled public endpoints.</p>
      </section>
      <section className="card">
        <h3>Security Controls</h3>
        <p className="muted">Use auth, IP allowlists, inspect opt-out, and token rotation to reduce exposure.</p>
      </section>
      <section className="card" style={{ gridColumn: "span 2" }}>
        <h3>Quick start</h3>
        <pre style={{ overflowX: "auto" }}>
{`# Login via CLI
fdt login --api https://api.yourdomain.com

# Start a tunnel
fdt http --local http://localhost:3000 --name myapp

# Start from config
fdt start --config ourdomain.yml`}
        </pre>
      </section>
      <section className="card">
        <h3>Admin</h3>
        <p className="muted">Use the Admin section to manage users, plans, active tunnels, and audit logs.</p>
      </section>
    </div>
  );
}
