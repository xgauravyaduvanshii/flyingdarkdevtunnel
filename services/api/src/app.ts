import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import fastifyRawBody from "fastify-raw-body";
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
    timeWindow: "1 minute"
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
