import dotenv from "dotenv";
import crypto from "node:crypto";
import http from "node:http";
import tls from "node:tls";
import { Pool } from "pg";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  CERT_WORKER_INTERVAL_SECONDS: z.coerce.number().int().positive().default(300),
  TLS_PROBE_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(8),
  CERT_EXPIRY_WARN_DAYS: z.coerce.number().int().positive().default(30),
  CERT_DEPLOYMENT_ENV: z.enum(["dev", "staging", "prod"]).default("dev"),
  CERT_RENEWAL_SLA_WARNING_HOURS: z.coerce.number().int().positive().default(72),
  CERT_ALERT_WEBHOOK_URL: z.string().url().optional(),
  CERT_ALERT_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(1800),
  CERT_RUNBOOK_WEBHOOK_URL: z.string().url().optional(),
  CERT_RUNBOOK_SIGNING_SECRET: z.string().optional(),
  CERT_RUNBOOK_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(900),
  CERT_METRICS_PORT: z.coerce.number().int().positive().default(9465),
  CERT_EVENT_BATCH_SIZE: z.coerce.number().int().positive().default(100),
  CERT_EVENT_MAX_RETRIES: z.coerce.number().int().positive().default(6),
  CERT_EVENT_BASE_BACKOFF_SECONDS: z.coerce.number().int().positive().default(45),
  CERT_DLQ_AUTO_REPLAY_ENABLED: z
    .string()
    .optional()
    .default("false")
    .transform((value) => value.trim().toLowerCase() === "true"),
  CERT_DLQ_REPLAY_MAX_EVENTS: z.coerce.number().int().positive().default(50),
  CERT_DLQ_REPLAY_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(900),
  CERT_DLQ_REPLAY_MAX_REPLAYS: z.coerce.number().int().positive().default(3),
  CERT_DLQ_REPLAY_MAX_AGE_HOURS: z.coerce.number().int().positive().default(168),
  CERT_PROBE_FALLBACK_ENABLED: z
    .string()
    .optional()
    .default("true")
    .transform((value) => value.trim().toLowerCase() !== "false"),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });
const lastAlertAtByKey = new Map<string, number>();
const lastRunbookAtByKey = new Map<string, number>();
let certAlertsSentTotal = 0;
let certRunbooksTriggeredTotal = 0;
let certRunbookFailuresTotal = 0;
let certRenewalSlaAlertsSentTotal = 0;
let certDlqAutoReplayTotal = 0;

type DomainTlsStatus = "issued" | "expiring" | "tls_error" | "passthrough_unverified" | "pending_route" | "pending_issue";
type CertFailurePolicy = "standard" | "strict" | "hold";

type CustomDomain = {
  id: string;
  domain: string;
  tls_mode: "termination" | "passthrough";
  verified: boolean;
  target_tunnel_id: string | null;
  cert_failure_policy: CertFailurePolicy;
  cert_failure_count: number;
  cert_next_retry_at: Date | null;
  cert_last_event_at: Date | null;
};

type ProbeResult = {
  status: "issued" | "expiring" | "tls_error" | "passthrough_unverified";
  certificateRef: string | null;
  notAfter: Date | null;
  error: string | null;
};

type AlertState = {
  domainId: string;
  domain: string;
  tlsMode: "termination" | "passthrough";
  status: DomainTlsStatus;
  notAfter: Date | null;
  error: string | null;
};

type RenewalSlaAlertClass = "renewal_sla_warning" | "renewal_sla_breach";

type RenewalSlaAlertState = {
  domainId: string;
  domain: string;
  tlsMode: "termination" | "passthrough";
  status: DomainTlsStatus;
  renewalDueAt: Date;
  hoursUntilDue: number;
};

type CertEventType =
  | "issuance_succeeded"
  | "issuance_failed"
  | "renewal_succeeded"
  | "renewal_failed"
  | "certificate_expiring";

type CertMetricsSnapshot = {
  generatedAt: number;
  domainStatusCounts: Record<DomainTlsStatus, number>;
  pendingEventCount: number;
  failedEventCount: number;
  renewalSlaWarningCount: number;
  renewalSlaBreachCount: number;
};

let certMetricsSnapshot: CertMetricsSnapshot = {
  generatedAt: Date.now(),
  domainStatusCounts: {
    issued: 0,
    expiring: 0,
    tls_error: 0,
    passthrough_unverified: 0,
    pending_route: 0,
    pending_issue: 0,
  },
  pendingEventCount: 0,
  failedEventCount: 0,
  renewalSlaWarningCount: 0,
  renewalSlaBreachCount: 0,
};

type CertificateEventRow = {
  id: string;
  source: string;
  source_event_id: string | null;
  domain_id: string | null;
  domain: string;
  event_type: CertEventType;
  status: "pending" | "applied" | "failed";
  certificate_ref: string | null;
  not_after: Date | null;
  renewal_due_at: Date | null;
  reason: string | null;
  payload_json: unknown;
  retry_count: number;
  next_retry_at: Date | null;
  cert_failure_policy: CertFailurePolicy | null;
  cert_failure_count: number | null;
  tls_mode: "termination" | "passthrough" | null;
};

function failureBackoffSeconds(policy: CertFailurePolicy, failureCount: number): number {
  const cappedFailureCount = Math.max(1, Math.min(failureCount, 10));
  const exponent = Math.max(0, cappedFailureCount - 1);

  if (policy === "strict") {
    return Math.min(12 * 60 * 60, 5 * 60 * 2 ** exponent);
  }
  if (policy === "hold") {
    const base = failureCount >= 3 ? 30 * 60 : 10 * 60;
    return Math.min(24 * 60 * 60, base * 2 ** exponent);
  }
  return Math.min(6 * 60 * 60, 60 * 2 ** exponent);
}

function eventRetryBackoffSeconds(retryCount: number): number {
  const exponent = Math.max(0, Math.min(retryCount - 1, 8));
  return Math.min(60 * 60, env.CERT_EVENT_BASE_BACKOFF_SECONDS * 2 ** exponent);
}

function hmacSignature(secret: string, timestamp: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
}

function renderMetrics(): string {
  const lines = [
    "# HELP fdt_cert_domains_total Number of custom domains by TLS lifecycle status.",
    "# TYPE fdt_cert_domains_total gauge",
  ];

  for (const [status, count] of Object.entries(certMetricsSnapshot.domainStatusCounts)) {
    lines.push(`fdt_cert_domains_total{status="${status}"} ${count}`);
  }

  lines.push("# HELP fdt_cert_events_pending_total Pending certificate lifecycle events.");
  lines.push("# TYPE fdt_cert_events_pending_total gauge");
  lines.push(`fdt_cert_events_pending_total ${certMetricsSnapshot.pendingEventCount}`);
  lines.push("# HELP fdt_cert_events_failed_total Failed certificate lifecycle events.");
  lines.push("# TYPE fdt_cert_events_failed_total gauge");
  lines.push(`fdt_cert_events_failed_total ${certMetricsSnapshot.failedEventCount}`);
  lines.push("# HELP fdt_cert_alerts_sent_total Certificate alerts emitted by worker.");
  lines.push("# TYPE fdt_cert_alerts_sent_total counter");
  lines.push(`fdt_cert_alerts_sent_total ${certAlertsSentTotal}`);
  lines.push("# HELP fdt_cert_runbook_triggers_total Successful runbook triggers from certificate alerts.");
  lines.push("# TYPE fdt_cert_runbook_triggers_total counter");
  lines.push(`fdt_cert_runbook_triggers_total ${certRunbooksTriggeredTotal}`);
  lines.push("# HELP fdt_cert_runbook_trigger_failures_total Failed runbook trigger deliveries.");
  lines.push("# TYPE fdt_cert_runbook_trigger_failures_total counter");
  lines.push(`fdt_cert_runbook_trigger_failures_total ${certRunbookFailuresTotal}`);
  lines.push("# HELP fdt_cert_metrics_generated_at_seconds Last metrics snapshot generation time.");
  lines.push("# TYPE fdt_cert_metrics_generated_at_seconds gauge");
  lines.push(`fdt_cert_metrics_generated_at_seconds ${Math.floor(certMetricsSnapshot.generatedAt / 1000)}`);
  lines.push("# HELP fdt_cert_domains_renewal_sla_warning_total Domains approaching renewal SLA warning window.");
  lines.push("# TYPE fdt_cert_domains_renewal_sla_warning_total gauge");
  lines.push(`fdt_cert_domains_renewal_sla_warning_total ${certMetricsSnapshot.renewalSlaWarningCount}`);
  lines.push("# HELP fdt_cert_domains_renewal_sla_breach_total Domains that exceeded renewal SLA.");
  lines.push("# TYPE fdt_cert_domains_renewal_sla_breach_total gauge");
  lines.push(`fdt_cert_domains_renewal_sla_breach_total ${certMetricsSnapshot.renewalSlaBreachCount}`);
  lines.push("# HELP fdt_cert_renewal_sla_alerts_sent_total Renewal SLA alerts emitted by worker.");
  lines.push("# TYPE fdt_cert_renewal_sla_alerts_sent_total counter");
  lines.push(`fdt_cert_renewal_sla_alerts_sent_total ${certRenewalSlaAlertsSentTotal}`);
  lines.push("# HELP fdt_cert_dlq_auto_replays_total Certificate DLQ events automatically re-queued by worker.");
  lines.push("# TYPE fdt_cert_dlq_auto_replays_total counter");
  lines.push(`fdt_cert_dlq_auto_replays_total ${certDlqAutoReplayTotal}`);

  return `${lines.join("\n")}\n`;
}

function startMetricsServer(): void {
  const server = http.createServer((req, res) => {
    if (req.url === "/metrics") {
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(renderMetrics());
      return;
    }
    if (req.url === "/healthz") {
      res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
  });

  server.listen(env.CERT_METRICS_PORT, "0.0.0.0", () => {
    console.log(`[worker-certificates] metrics server listening on :${env.CERT_METRICS_PORT}`);
  });
}

function shouldAlert(state: AlertState): boolean {
  return state.status === "tls_error" || state.status === "expiring";
}

function alertKeyFor(state: AlertState): string {
  return `${state.domainId}:${state.status}`;
}

function formatAlertMessage(state: AlertState): string {
  if (state.status === "expiring" && state.notAfter) {
    const daysLeft = Math.max(0, Math.ceil((state.notAfter.getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
    return `[worker-certificates] tls certificate expiring domain=${state.domain} tls_mode=${state.tlsMode} not_after=${state.notAfter.toISOString()} days_left=${daysLeft}`;
  }
  return `[worker-certificates] tls probe error domain=${state.domain} tls_mode=${state.tlsMode} error=${state.error ?? "unknown"}`;
}

async function triggerRunbookForAlert(state: AlertState): Promise<void> {
  await triggerRunbookPayload(
    {
      source: "worker-certificates",
      type: "certificate.alert",
      severity: state.status === "tls_error" ? "critical" : "warning",
      incidentRoute: "ticket",
      domainId: state.domainId,
      domain: state.domain,
      tlsMode: state.tlsMode,
      status: state.status,
      notAfter: state.notAfter ? state.notAfter.toISOString() : null,
      error: state.error,
      timestamp: new Date().toISOString(),
    },
    `${alertKeyFor(state)}:runbook`,
  );
}

async function triggerRunbookPayload(payloadObject: Record<string, unknown>, key: string): Promise<void> {
  if (!env.CERT_RUNBOOK_WEBHOOK_URL) {
    return;
  }

  const now = Date.now();
  const last = lastRunbookAtByKey.get(key) ?? 0;
  if (now - last < env.CERT_RUNBOOK_COOLDOWN_SECONDS * 1000) {
    return;
  }

  const payload = JSON.stringify(payloadObject);
  const headers: Record<string, string> = { "content-type": "application/json" };

  if (env.CERT_RUNBOOK_SIGNING_SECRET) {
    const ts = `${Math.floor(now / 1000)}`;
    headers["x-fdt-timestamp"] = ts;
    headers["x-fdt-signature"] = hmacSignature(env.CERT_RUNBOOK_SIGNING_SECRET, ts, payload);
  }

  const response = await fetch(env.CERT_RUNBOOK_WEBHOOK_URL, {
    method: "POST",
    headers,
    body: payload,
  });
  if (!response.ok) {
    throw new Error(`runbook webhook responded with status ${response.status}`);
  }

  certRunbooksTriggeredTotal += 1;
  lastRunbookAtByKey.set(key, now);
}

async function maybeEmitAlert(state: AlertState): Promise<void> {
  if (!shouldAlert(state)) return;

  const key = alertKeyFor(state);
  const now = Date.now();
  const last = lastAlertAtByKey.get(key) ?? 0;
  if (now - last < env.CERT_ALERT_COOLDOWN_SECONDS * 1000) {
    return;
  }

  const message = formatAlertMessage(state);
  console.warn(message);
  certAlertsSentTotal += 1;

  if (env.CERT_ALERT_WEBHOOK_URL) {
    try {
      await fetch(env.CERT_ALERT_WEBHOOK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          source: "worker-certificates",
          severity: "warning",
          domainId: state.domainId,
          domain: state.domain,
          tlsMode: state.tlsMode,
          status: state.status,
          notAfter: state.notAfter ? state.notAfter.toISOString() : null,
          error: state.error,
          expiryWarnDays: env.CERT_EXPIRY_WARN_DAYS,
          timestamp: new Date().toISOString(),
        }),
      });
    } catch (error) {
      console.error("[worker-certificates] alert webhook delivery failed", error);
    }
  }

  try {
    await triggerRunbookForAlert(state);
  } catch (error) {
    certRunbookFailuresTotal += 1;
    console.error("[worker-certificates] runbook alert delivery failed", error);
  }

  lastAlertAtByKey.set(key, now);
}

function renewalSlaClass(hoursUntilDue: number): RenewalSlaAlertClass | null {
  if (hoursUntilDue <= 0) {
    return "renewal_sla_breach";
  }
  if (hoursUntilDue <= env.CERT_RENEWAL_SLA_WARNING_HOURS) {
    return "renewal_sla_warning";
  }
  return null;
}

function renewalSlaSeverity(classification: RenewalSlaAlertClass): "warning" | "critical" {
  if (classification === "renewal_sla_breach" && env.CERT_DEPLOYMENT_ENV === "prod") {
    return "critical";
  }
  return "warning";
}

function renewalSlaRoute(classification: RenewalSlaAlertClass): "ticket" | "page" {
  if (classification === "renewal_sla_breach" && env.CERT_DEPLOYMENT_ENV === "prod") {
    return "page";
  }
  return "ticket";
}

function renewalSlaAlertKey(state: RenewalSlaAlertState, classification: RenewalSlaAlertClass): string {
  return `${state.domainId}:${classification}`;
}

async function maybeEmitRenewalSlaAlert(state: RenewalSlaAlertState): Promise<void> {
  const classification = renewalSlaClass(state.hoursUntilDue);
  if (!classification) return;

  const key = renewalSlaAlertKey(state, classification);
  const now = Date.now();
  const last = lastAlertAtByKey.get(key) ?? 0;
  if (now - last < env.CERT_ALERT_COOLDOWN_SECONDS * 1000) {
    return;
  }

  const severity = renewalSlaSeverity(classification);
  const incidentRoute = renewalSlaRoute(classification);
  console.warn(
    `[worker-certificates] renewal sla ${classification} domain=${state.domain} status=${state.status} due_at=${state.renewalDueAt.toISOString()} hours_until_due=${state.hoursUntilDue.toFixed(1)} env=${env.CERT_DEPLOYMENT_ENV}`,
  );
  certRenewalSlaAlertsSentTotal += 1;

  if (env.CERT_ALERT_WEBHOOK_URL) {
    try {
      await fetch(env.CERT_ALERT_WEBHOOK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          source: "worker-certificates",
          type: "certificate.renewal_sla",
          classification,
          severity,
          incidentRoute,
          domainId: state.domainId,
          domain: state.domain,
          tlsMode: state.tlsMode,
          status: state.status,
          renewalDueAt: state.renewalDueAt.toISOString(),
          hoursUntilDue: Number.parseFloat(state.hoursUntilDue.toFixed(2)),
          warningWindowHours: env.CERT_RENEWAL_SLA_WARNING_HOURS,
          environment: env.CERT_DEPLOYMENT_ENV,
          timestamp: new Date().toISOString(),
        }),
      });
    } catch (error) {
      console.error("[worker-certificates] renewal SLA alert webhook delivery failed", error);
    }
  }

  try {
    await triggerRunbookPayload(
      {
        source: "worker-certificates",
        type: "certificate.renewal_sla",
        classification,
        severity,
        incidentRoute,
        domainId: state.domainId,
        domain: state.domain,
        tlsMode: state.tlsMode,
        status: state.status,
        renewalDueAt: state.renewalDueAt.toISOString(),
        hoursUntilDue: Number.parseFloat(state.hoursUntilDue.toFixed(2)),
        environment: env.CERT_DEPLOYMENT_ENV,
        timestamp: new Date().toISOString(),
      },
      `${key}:runbook`,
    );
  } catch (error) {
    certRunbookFailuresTotal += 1;
    console.error("[worker-certificates] renewal SLA runbook delivery failed", error);
  }

  lastAlertAtByKey.set(key, now);
}

async function probeTlsCertificate(domain: string, timeoutSeconds: number): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const timeoutMs = timeoutSeconds * 1000;

    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });

    let done = false;
    const finish = (result: ProbeResult) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };

    socket.on("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      if (!cert || typeof cert !== "object" || !cert.valid_to) {
        finish({ status: "tls_error", certificateRef: null, notAfter: null, error: "peer certificate missing" });
        return;
      }

      const notAfter = new Date(cert.valid_to);
      if (Number.isNaN(notAfter.getTime())) {
        finish({
          status: "tls_error",
          certificateRef: cert.fingerprint256 ? `sha256:${String(cert.fingerprint256).replace(/:/g, "")}` : null,
          notAfter: null,
          error: "certificate not_after invalid",
        });
        return;
      }

      const msRemaining = notAfter.getTime() - Date.now();
      const status = msRemaining <= 1000 * 60 * 60 * 24 * env.CERT_EXPIRY_WARN_DAYS ? "expiring" : "issued";
      finish({
        status,
        certificateRef: cert.fingerprint256 ? `sha256:${String(cert.fingerprint256).replace(/:/g, "")}` : null,
        notAfter,
        error: null,
      });
    });

    socket.on("error", (error) => {
      finish({ status: "tls_error", certificateRef: null, notAfter: null, error: String(error) });
    });

    socket.on("timeout", () => {
      finish({
        status: "tls_error",
        certificateRef: null,
        notAfter: null,
        error: `tls probe timeout after ${timeoutSeconds}s`,
      });
    });
  });
}

async function markEventApplied(id: string): Promise<void> {
  await db.query(
    `
      UPDATE certificate_lifecycle_events
      SET status = 'applied', processed_at = NOW(), updated_at = NOW(), last_error = NULL
      WHERE id = $1
    `,
    [id],
  );
}

async function markEventRetryOrFail(event: CertificateEventRow, error: unknown): Promise<void> {
  const nextRetryCount = event.retry_count + 1;
  const errText = String(error);

  if (nextRetryCount >= env.CERT_EVENT_MAX_RETRIES) {
    await db.query(
      `
        UPDATE certificate_lifecycle_events
        SET
          status = 'failed',
          retry_count = $2,
          last_error = $3,
          processed_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `,
      [event.id, nextRetryCount, errText],
    );
    return;
  }

  const backoffSeconds = eventRetryBackoffSeconds(nextRetryCount);
  const nextRetryAt = new Date(Date.now() + backoffSeconds * 1000);
  await db.query(
    `
      UPDATE certificate_lifecycle_events
      SET
        retry_count = $2,
        next_retry_at = $3,
        last_error = $4,
        updated_at = NOW()
      WHERE id = $1
    `,
    [event.id, nextRetryCount, nextRetryAt, errText],
  );
}

async function applyCertificateEvent(event: CertificateEventRow): Promise<void> {
  const domainId = event.domain_id;
  if (!domainId) {
    throw new Error(`domain not resolved for event ${event.id} (${event.domain})`);
  }

  const policy = event.cert_failure_policy ?? "standard";
  const currentFailureCount = event.cert_failure_count ?? 0;
  const commonArgs = [domainId, event.event_type, event.certificate_ref ?? null, event.not_after ?? null, event.renewal_due_at ?? null];

  if (event.event_type === "issuance_succeeded" || event.event_type === "renewal_succeeded") {
    await db.query(
      `
        UPDATE custom_domains
        SET
          tls_status = 'issued',
          certificate_ref = COALESCE($3, certificate_ref),
          tls_not_after = COALESCE($4, tls_not_after),
          cert_renewal_due_at = COALESCE($5, cert_renewal_due_at),
          tls_last_error = NULL,
          tls_last_checked_at = NOW(),
          cert_failure_count = 0,
          cert_retry_backoff_seconds = 0,
          cert_next_retry_at = NULL,
          cert_last_event_type = $2,
          cert_last_event_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `,
      commonArgs,
    );
    return;
  }

  if (event.event_type === "certificate_expiring") {
    await db.query(
      `
        UPDATE custom_domains
        SET
          tls_status = 'expiring',
          certificate_ref = COALESCE($3, certificate_ref),
          tls_not_after = COALESCE($4, tls_not_after),
          cert_renewal_due_at = COALESCE($5, cert_renewal_due_at),
          tls_last_checked_at = NOW(),
          cert_last_event_type = $2,
          cert_last_event_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `,
      commonArgs,
    );
    return;
  }

  const nextFailureCount = currentFailureCount + 1;
  const backoffSeconds = failureBackoffSeconds(policy, nextFailureCount);
  const nextRetryAt = new Date(Date.now() + backoffSeconds * 1000);
  await db.query(
    `
      UPDATE custom_domains
      SET
        tls_status = 'tls_error',
        certificate_ref = COALESCE($3, certificate_ref),
        tls_not_after = COALESCE($4, tls_not_after),
        cert_renewal_due_at = COALESCE($5, cert_renewal_due_at),
        tls_last_error = COALESCE($6, tls_last_error),
        tls_last_checked_at = NOW(),
        cert_failure_count = $7,
        cert_retry_backoff_seconds = $8,
        cert_next_retry_at = $9,
        cert_last_event_type = $2,
        cert_last_event_at = NOW(),
        updated_at = NOW()
      WHERE id = $1
    `,
    [domainId, event.event_type, event.certificate_ref ?? null, event.not_after ?? null, event.renewal_due_at ?? null, event.reason ?? "certificate issuance failure", nextFailureCount, backoffSeconds, nextRetryAt],
  );
}

async function processCertificateEvents(): Promise<void> {
  const events = await db.query<CertificateEventRow>(
    `
      SELECT
        e.id,
        e.source,
        e.source_event_id,
        COALESCE(e.domain_id, d.id) AS domain_id,
        e.domain,
        e.event_type,
        e.status,
        e.certificate_ref,
        e.not_after,
        e.renewal_due_at,
        e.reason,
        e.payload_json,
        e.retry_count,
        e.next_retry_at,
        d.cert_failure_policy,
        d.cert_failure_count,
        d.tls_mode
      FROM certificate_lifecycle_events e
      LEFT JOIN custom_domains d ON d.id = e.domain_id OR (e.domain_id IS NULL AND d.domain = e.domain)
      WHERE e.status = 'pending'
        AND (e.next_retry_at IS NULL OR e.next_retry_at <= NOW())
      ORDER BY e.created_at ASC
      LIMIT $1
    `,
    [env.CERT_EVENT_BATCH_SIZE],
  );

  for (const event of events.rows) {
    try {
      await applyCertificateEvent(event);
      await markEventApplied(event.id);

      if (!event.domain_id) {
        continue;
      }

      const state = await db.query<{
        id: string;
        domain: string;
        tls_mode: "termination" | "passthrough";
        tls_status: DomainTlsStatus;
        tls_not_after: Date | null;
        tls_last_error: string | null;
      }>(
        `
          SELECT id, domain, tls_mode, tls_status, tls_not_after, tls_last_error
          FROM custom_domains
          WHERE id = $1
          LIMIT 1
        `,
        [event.domain_id],
      );

      const row = state.rows[0];
      if (row) {
        await maybeEmitAlert({
          domainId: row.id,
          domain: row.domain,
          tlsMode: row.tls_mode,
          status: row.tls_status,
          notAfter: row.tls_not_after,
          error: row.tls_last_error,
        });
      }
    } catch (error) {
      console.error("[worker-certificates] certificate event apply failed", event.id, error);
      await markEventRetryOrFail(event, error);
    }
  }
}

async function syncCertificateStateByProbe(): Promise<void> {
  const domains = await db.query<CustomDomain>(
    `
      SELECT
        id,
        domain,
        tls_mode,
        verified,
        target_tunnel_id,
        cert_failure_policy,
        cert_failure_count,
        cert_next_retry_at,
        cert_last_event_at
      FROM custom_domains
      WHERE verified = TRUE
      ORDER BY created_at DESC
      LIMIT 500
    `,
  );

  const now = Date.now();
  for (const domain of domains.rows) {
    if (!domain.target_tunnel_id) {
      await db.query(
        `
          UPDATE custom_domains
          SET
            tls_status = 'pending_route',
            certificate_ref = NULL,
            tls_last_checked_at = NOW(),
            tls_last_error = NULL,
            tls_not_after = NULL,
            cert_last_event_type = 'pending_route',
            cert_last_event_at = NOW(),
            updated_at = NOW()
          WHERE id = $1
        `,
        [domain.id],
      );
      continue;
    }

    if (domain.cert_next_retry_at && domain.cert_next_retry_at.getTime() > now) {
      continue;
    }

    if (domain.cert_last_event_at && now - domain.cert_last_event_at.getTime() < 10 * 60 * 1000) {
      continue;
    }

    const result = await probeTlsCertificate(domain.domain, env.TLS_PROBE_TIMEOUT_SECONDS);
    let status: DomainTlsStatus = result.status;
    const certificateRef = result.certificateRef;
    const notAfter = result.notAfter;
    let error = result.error;
    let failureCount = domain.cert_failure_count;
    let retryBackoff = 0;
    let nextRetryAt: Date | null = null;

    if (domain.tls_mode === "passthrough") {
      status = "passthrough_unverified";
      error = result.status === "tls_error" ? result.error : null;
      failureCount = 0;
    } else if (status === "tls_error") {
      failureCount += 1;
      retryBackoff = failureBackoffSeconds(domain.cert_failure_policy, failureCount);
      nextRetryAt = new Date(Date.now() + retryBackoff * 1000);
    } else {
      failureCount = 0;
    }

    await db.query(
      `
        UPDATE custom_domains
        SET
          tls_status = $2,
          certificate_ref = $3,
          tls_not_after = $4,
          tls_last_error = $5,
          tls_last_checked_at = NOW(),
          cert_failure_count = $6,
          cert_retry_backoff_seconds = $7,
          cert_next_retry_at = $8,
          cert_last_event_type = 'probe_sync',
          cert_last_event_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `,
      [domain.id, status, certificateRef, notAfter, error, failureCount, retryBackoff, nextRetryAt],
    );

    await maybeEmitAlert({
      domainId: domain.id,
      domain: domain.domain,
      tlsMode: domain.tls_mode,
      status,
      notAfter,
      error,
    });
  }
}

async function checkRenewalSlaEscalations(): Promise<void> {
  const candidates = await db.query<{
    id: string;
    domain: string;
    tls_mode: "termination" | "passthrough";
    tls_status: DomainTlsStatus;
    cert_renewal_due_at: Date | null;
  }>(
    `
      SELECT id, domain, tls_mode, tls_status, cert_renewal_due_at
      FROM custom_domains
      WHERE verified = TRUE
        AND tls_mode = 'termination'
        AND cert_renewal_due_at IS NOT NULL
        AND cert_renewal_due_at <= NOW() + ($1 || ' hours')::interval
      ORDER BY cert_renewal_due_at ASC
      LIMIT 500
    `,
    [env.CERT_RENEWAL_SLA_WARNING_HOURS],
  );

  const nowMs = Date.now();
  for (const row of candidates.rows) {
    if (!row.cert_renewal_due_at) {
      continue;
    }
    const hoursUntilDue = (row.cert_renewal_due_at.getTime() - nowMs) / (1000 * 60 * 60);
    await maybeEmitRenewalSlaAlert({
      domainId: row.id,
      domain: row.domain,
      tlsMode: row.tls_mode,
      status: row.tls_status,
      renewalDueAt: row.cert_renewal_due_at,
      hoursUntilDue,
    });
  }
}

async function autoReplayDlqEvents(): Promise<void> {
  if (!env.CERT_DLQ_AUTO_REPLAY_ENABLED) {
    return;
  }

  const candidates = await db.query<{
    id: string;
    dlq_replay_count: number;
  }>(
    `
      SELECT id, dlq_replay_count
      FROM certificate_lifecycle_events
      WHERE status = 'failed'
        AND retry_count >= $1
        AND dlq_replay_count < $2
        AND updated_at <= NOW() - make_interval(secs => $3::int)
        AND created_at >= NOW() - make_interval(hours => $4::int)
      ORDER BY updated_at ASC
      LIMIT $5
    `,
    [
      env.CERT_EVENT_MAX_RETRIES,
      env.CERT_DLQ_REPLAY_MAX_REPLAYS,
      env.CERT_DLQ_REPLAY_COOLDOWN_SECONDS,
      env.CERT_DLQ_REPLAY_MAX_AGE_HOURS,
      env.CERT_DLQ_REPLAY_MAX_EVENTS,
    ],
  );

  if (candidates.rows.length === 0) {
    return;
  }

  const ids = candidates.rows.map((row) => row.id);
  const replayed = await db.query<{ id: string }>(
    `
      UPDATE certificate_lifecycle_events
      SET
        status = 'pending',
        retry_count = 0,
        next_retry_at = NOW(),
        processed_at = NULL,
        last_error = 'auto-replayed from dlq',
        dlq_replay_count = dlq_replay_count + 1,
        last_dlq_replayed_at = NOW(),
        updated_at = NOW()
      WHERE id = ANY($1::uuid[])
      RETURNING id
    `,
    [ids],
  );

  certDlqAutoReplayTotal += replayed.rowCount ?? 0;
  console.warn(
    `[worker-certificates] auto replayed ${replayed.rowCount ?? 0} failed certificate events from dlq (maxReplays=${env.CERT_DLQ_REPLAY_MAX_REPLAYS})`,
  );
}

async function refreshMetricsSnapshot(): Promise<void> {
  const domainStatusRows = await db.query<{ tls_status: DomainTlsStatus; count: string }>(
    `
      SELECT tls_status, COUNT(*)::text AS count
      FROM custom_domains
      GROUP BY tls_status
    `,
  );

  const domainStatusCounts: Record<DomainTlsStatus, number> = {
    issued: 0,
    expiring: 0,
    tls_error: 0,
    passthrough_unverified: 0,
    pending_route: 0,
    pending_issue: 0,
  };
  for (const row of domainStatusRows.rows) {
    domainStatusCounts[row.tls_status] = Number.parseInt(row.count, 10) || 0;
  }

  const eventRows = await db.query<{ pending_count: string; failed_count: string }>(
    `
      SELECT
        COUNT(*) FILTER (WHERE status = 'pending')::text AS pending_count,
        COUNT(*) FILTER (WHERE status = 'failed')::text AS failed_count
      FROM certificate_lifecycle_events
    `,
  );

  const counts = eventRows.rows[0] ?? { pending_count: "0", failed_count: "0" };
  const renewalRows = await db.query<{ warning_count: string; breach_count: string }>(
    `
      SELECT
        COUNT(*) FILTER (
          WHERE verified = TRUE
            AND tls_mode = 'termination'
            AND cert_renewal_due_at IS NOT NULL
            AND cert_renewal_due_at > NOW()
            AND cert_renewal_due_at <= NOW() + ($1 || ' hours')::interval
        )::text AS warning_count,
        COUNT(*) FILTER (
          WHERE verified = TRUE
            AND tls_mode = 'termination'
            AND cert_renewal_due_at IS NOT NULL
            AND cert_renewal_due_at <= NOW()
        )::text AS breach_count
      FROM custom_domains
    `,
    [env.CERT_RENEWAL_SLA_WARNING_HOURS],
  );
  const renewal = renewalRows.rows[0] ?? { warning_count: "0", breach_count: "0" };

  certMetricsSnapshot = {
    generatedAt: Date.now(),
    domainStatusCounts,
    pendingEventCount: Number.parseInt(counts.pending_count, 10) || 0,
    failedEventCount: Number.parseInt(counts.failed_count, 10) || 0,
    renewalSlaWarningCount: Number.parseInt(renewal.warning_count, 10) || 0,
    renewalSlaBreachCount: Number.parseInt(renewal.breach_count, 10) || 0,
  };
}

async function loop(): Promise<void> {
  while (true) {
    try {
      await autoReplayDlqEvents();
      await processCertificateEvents();
      if (env.CERT_PROBE_FALLBACK_ENABLED) {
        await syncCertificateStateByProbe();
      }
      await checkRenewalSlaEscalations();
      await refreshMetricsSnapshot();
    } catch (error) {
      console.error("[worker-certificates] sync failed", error);
    }

    await new Promise((resolve) => setTimeout(resolve, env.CERT_WORKER_INTERVAL_SECONDS * 1000));
  }
}

startMetricsServer();

loop().catch((error) => {
  console.error("[worker-certificates] fatal", error);
  process.exit(1);
});
