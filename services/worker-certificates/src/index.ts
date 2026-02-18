import dotenv from "dotenv";
import tls from "node:tls";
import { Pool } from "pg";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  CERT_WORKER_INTERVAL_SECONDS: z.coerce.number().int().positive().default(300),
  TLS_PROBE_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(8),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });

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
      const status = msRemaining <= 1000 * 60 * 60 * 24 * 30 ? "expiring" : "issued";
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
