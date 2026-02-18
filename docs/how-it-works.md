# How It Works

This document explains core platform flows end-to-end:
- tunnel setup and traffic forwarding,
- policy enforcement points,
- certificate lifecycle automation,
- billing and finance reconciliation workflows.

---

## 1) Tunnel Lifecycle (Control + Data Plane)

```mermaid
sequenceDiagram
  participant Dev as Developer
  participant CLI as Go CLI (agent)
  participant API as Control Plane API
  participant Relay as Relay Edge
  participant App as Local App

  Dev->>CLI: login + start command
  CLI->>API: authenticate + tunnel start request
  API-->>CLI: short-lived agent JWT + edge assignment
  CLI->>Relay: connect control websocket with token
  Relay-->>CLI: tunnel session accepted
  Note over Relay,CLI: Session stays persistent with reconnect logic
  Relay->>CLI: inbound public request frame
  CLI->>App: forward request to local target
  App-->>CLI: local response
  CLI-->>Relay: response frame
```

Key points:
- API owns identity, entitlements, and policy issuance.
- Relay owns real-time enforcement for network traffic.
- CLI/agent owns local forwarding to developer targets.

---

## 2) Edge Security and Routing Decisions

```mermaid
flowchart TD
  Inbound[Inbound request at relay] --> HostCheck{Host mapped to active tunnel?}
  HostCheck -- No --> NotFound[404 / unassigned host]
  HostCheck -- Yes --> ModeCheck{TLS mode policy valid?}
  ModeCheck -- No --> ModeReject[421 / mode mismatch]
  ModeCheck -- Yes --> AuthCheck{Basic auth required?}
  AuthCheck -- Yes --> AuthValid{Credentials valid?}
  AuthValid -- No --> AuthFail[401]
  AuthValid -- Yes --> IPCheck
  AuthCheck -- No --> IPCheck{IP allowlist configured?}
  IPCheck -- Yes --> IPValid{Client IP allowed?}
  IPValid -- No --> IPFail[403]
  IPValid -- Yes --> Concurrency
  IPCheck -- No --> Concurrency{Concurrency limit exceeded?}
  Concurrency -- Yes --> Busy[429 backpressure]
  Concurrency -- No --> Forward[Forward to active agent stream]
```

---

## 3) Certificate Lifecycle Flow

```mermaid
flowchart LR
  CertManager[cert-manager / ACME events] --> Ingest[POST /v1/domains/cert-events]
  Ingest --> Verify[Provenance + signature checks]
  Verify --> Queue[certificate_lifecycle_events]
  Queue --> Worker[worker-certificates]
  Worker --> DomainState[custom_domains tls/cert fields]
  Worker --> Incident[certificate_incidents tiered state]
  Incident --> AdminOps[Admin ack/resolve APIs]
  Worker --> Replicas[cert_region_replicas snapshot sync]
```

Implemented behavior:
- callback-only cert ingest mapping (`callbackClass/callbackAction -> eventType`)
- retry/backoff and DLQ replay controls
- tiered incident tracking (`open`, `acknowledged`, `resolved`)
- region replication state snapshots for multi-region foundations

---

## 4) Billing and Finance Reconciliation Flow

```mermaid
flowchart TD
  Checkout[Checkout session create] --> Provider[Stripe / Razorpay / PayPal]
  Provider --> Webhook[Provider webhook]
  Webhook --> Verify[Signature + freshness + idempotency]
  Verify --> Apply[Apply subscription/entitlement updates]
  Apply --> FinanceLedger[billing_finance_events]
  Apply --> Dunning[billing_dunning_cases]
  Dunning --> Notifications[Webhook/email/slack notifications]
  FinanceLedger --> Reports[billing_report_exports]
  ExternalSink[External sink] --> Settlement[Signed settlement receipt ingest]
  Settlement --> Reconcile[Admin settlement reconcile]
  Reconcile --> Delta[Matched / Delta / Failed state]
```

Implemented behavior:
- provider webhook replay/reconcile automation
- report export + delivery ACK lifecycle
- signed settlement receipt ingest and reconciliation with delta metrics

---

## 5) Why This Split Architecture

1. Go for data plane throughput and stable network behavior.
2. TypeScript control plane for speed of product iteration.
3. Worker isolation to keep background concerns independent and retryable.
4. PostgreSQL as source of truth, Redis for ephemeral/coordination state.
5. Monorepo to keep contracts, docs, tests, and infra aligned.

---

## 6) Where to Extend Next

- Strict active-active cert material distribution workflows.
- Expanded multi-region traffic policy drills.
- Broader adaptive abuse controls beyond auth endpoints.
- Stronger enterprise identity and policy controls (deeper SSO/SCIM).

---

## Related References

- `README.md`
- `docs/architecture.md`
- `docs/certificate-lifecycle.md`
- `docs/billing-providers.md`
- `docs/testing-and-ci.md`
- `plan.md`
