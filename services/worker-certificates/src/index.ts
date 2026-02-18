import dotenv from "dotenv";
import tls from "node:tls";
import { Pool } from "pg";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  CERT_WORKER_INTERVAL_SECONDS: z.coerce.number().int().positive().default(300),
  TLS_PROBE_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(8),
  CERT_EXPIRY_WARN_DAYS: z.coerce.number().int().positive().default(30),
  CERT_ALERT_WEBHOOK_URL: z.string().url().optional(),
  CERT_ALERT_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(1800),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });
const lastAlertAtByKey = new Map<string, number>();

type CustomDomain = {
  id: string;
  domain: string;
  tls_mode: "termination" | "passthrough";
  verified: boolean;
  target_tunnel_id: string | null;
};

type ProbeResult = {
  status: "issued" | "expiring" | "tls_error" | "passthrough_unverified";
  certificateRef: string | null;
  notAfter: Date | null;
  error: string | null;
};

type DomainTlsStatus = "issued" | "expiring" | "tls_error" | "passthrough_unverified" | "pending_route";

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
        finish({
          status: "tls_error",
          certificateRef: null,
          notAfter: null,
          error: "peer certificate missing",
        });
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
      finish({
        status: "tls_error",
        certificateRef: null,
        notAfter: null,
        error: String(error),
      });
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

type AlertState = {
  domainId: string;
  domain: string;
  tlsMode: "termination" | "passthrough";
  status: DomainTlsStatus;
  notAfter: Date | null;
  error: string | null;
};

function alertKeyFor(state: AlertState): string {
  return `${state.domainId}:${state.status}`;
}

function shouldAlert(state: AlertState): boolean {
  return state.status === "tls_error" || state.status === "expiring";
}

function formatAlertMessage(state: AlertState): string {
  if (state.status === "expiring" && state.notAfter) {
    const daysLeft = Math.max(0, Math.ceil((state.notAfter.getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
    return `[worker-certificates] tls certificate expiring domain=${state.domain} tls_mode=${state.tlsMode} not_after=${state.notAfter.toISOString()} days_left=${daysLeft}`;
  }
  return `[worker-certificates] tls probe error domain=${state.domain} tls_mode=${state.tlsMode} error=${state.error ?? "unknown"}`;
}

async function maybeEmitAlert(state: AlertState): Promise<void> {
  if (!shouldAlert(state)) {
    return;
  }

  const key = alertKeyFor(state);
  const now = Date.now();
  const last = lastAlertAtByKey.get(key) ?? 0;
  if (now - last < env.CERT_ALERT_COOLDOWN_SECONDS * 1000) {
    return;
  }

  const message = formatAlertMessage(state);
  console.warn(message);

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

  lastAlertAtByKey.set(key, now);
}

async function syncCertificateState(): Promise<void> {
  const domainsRes = await db.query<CustomDomain>(
    `
      SELECT id, domain, tls_mode, verified, target_tunnel_id
      FROM custom_domains
      WHERE verified = TRUE
      ORDER BY created_at DESC
      LIMIT 500
    `,
  );

  for (const domain of domainsRes.rows) {
    if (!domain.target_tunnel_id) {
      await db.query(
        `
          UPDATE custom_domains
          SET
            tls_status = 'pending_route',
            certificate_ref = NULL,
            tls_last_checked_at = NOW(),
            tls_last_error = NULL,
            tls_not_after = NULL
          WHERE id = $1
        `,
        [domain.id],
      );
      continue;
    }

    const result = await probeTlsCertificate(domain.domain, env.TLS_PROBE_TIMEOUT_SECONDS);

    let status: DomainTlsStatus = result.status;
    const certificateRef = result.certificateRef;
    const notAfter = result.notAfter;
    let error = result.error;

    if (domain.tls_mode === "passthrough") {
      // Passthrough certificates are owned by upstream; keep status explicit.
      status = "passthrough_unverified";
      if (result.status !== "tls_error") {
        error = null;
      }
    }

    await db.query(
      `
        UPDATE custom_domains
        SET
          tls_status = $2,
          certificate_ref = $3,
          tls_not_after = $4,
          tls_last_error = $5,
          tls_last_checked_at = NOW()
        WHERE id = $1
      `,
      [domain.id, status, certificateRef, notAfter, error],
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

async function loop(): Promise<void> {
  while (true) {
    try {
      await syncCertificateState();
    } catch (error) {
      console.error("[worker-certificates] sync failed", error);
    }

    await new Promise((resolve) => setTimeout(resolve, env.CERT_WORKER_INTERVAL_SECONDS * 1000));
  }
}

loop().catch((error) => {
  console.error("[worker-certificates] fatal", error);
  process.exit(1);
});
