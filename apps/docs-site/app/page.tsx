export default function DocsHome() {
  return (
    <article>
      <h1>TunnelForge Documentation</h1>
      <p>CLI quickstart:</p>
      <pre>{`fdt login --api http://localhost:4000
fdt http --tunnel-id <tunnel-id> --local http://localhost:3000`}</pre>

      <h2>Config file</h2>
      <pre>{`tunnels:
  - name: web
    protocol: http
    tunnelId: 11111111-1111-1111-1111-111111111111
    localAddr: http://localhost:3000
  - name: ssh
    protocol: tcp
    tunnelId: 22222222-2222-2222-2222-222222222222
    localAddr: 127.0.0.1:22`}</pre>

      <h2>Security</h2>
      <ul>
        <li>Never share authtokens in plain text logs.</li>
        <li>Rotate authtokens immediately after leakage.</li>
        <li>Use basic auth and IP restrictions for sensitive tunnels.</li>
      </ul>

      <h2>Billing providers</h2>
      <pre>{`POST /v1/billing/checkout-session
{
  "planCode": "pro",
  "provider": "stripe" | "razorpay" | "paypal"
}`}</pre>
      <p>Webhook endpoints: <code>/v1/billing/webhook/stripe</code>, <code>/v1/billing/webhook/razorpay</code>, <code>/v1/billing/webhook/paypal</code></p>
    </article>
  );
}
