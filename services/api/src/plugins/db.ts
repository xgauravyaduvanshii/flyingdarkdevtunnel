import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import { Pool } from "pg";
import { runMigrations } from "../lib/migrations.js";

const plugin: FastifyPluginAsync = async (app) => {
  const pool = new Pool({
    connectionString: app.env.DATABASE_URL
  });

  await runMigrations(pool);

  app.decorate("db", pool);

  app.addHook("onClose", async () => {
    await pool.end();
  });
};

export const dbPlugin = fp(plugin);
