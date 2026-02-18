import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import fastifyRawBody from "fastify-raw-body";
import { v4 as uuidv4 } from "uuid";
import { envPlugin } from "./plugins/env.js";
import { dbPlugin } from "./plugins/db.js";
import { authPlugin } from "./plugins/auth.js";
import { auditPlugin } from "./plugins/audit.js";
import { registerRoutes } from "./routes/index.js";

export async function buildApp() {
  const app = Fastify({
    logger: true,
    bodyLimit: 1024 * 1024 * 10
  });

  await app.register(envPlugin);
  await app.register(cors, { origin: true, credentials: true });
  await app.register(rateLimit, {
    max: 120,
    timeWindow: "1 minute",
    errorResponseBuilder: (request, context) => {
      // Best-effort anomaly logging for abusive traffic bursts.
      void app.db
        ?.query(
          `
            INSERT INTO security_anomaly_events (id, category, severity, ip, route, details)
            VALUES ($1, 'rate_limited', 'medium', $2, $3, $4)
          `,
          [uuidv4(), request.ip ?? null, request.url ?? null, { max: context.max, after: context.after }],
        )
        .catch((error) => {
          request.log.warn({ err: error }, "failed to record rate-limit anomaly");
        });

      return {
        message: "Rate limit exceeded",
        retryAfter: context.after,
      };
    },
  });
  await app.register(fastifyRawBody, {
    field: "rawBody",
    global: false,
    encoding: "utf8",
    runFirst: true,
  });

  await app.register(dbPlugin);
  await app.register(authPlugin);
  await app.register(auditPlugin);
  await registerRoutes(app);

  app.setErrorHandler((error, request, reply) => {
    const statusCode = (error as any).statusCode ?? 500;
    request.log.error({ err: error }, "request failed");
    const message = error instanceof Error ? error.message : "Internal server error";
    reply.status(statusCode).send({ message });
  });

  return app;
}
