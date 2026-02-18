import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import dotenv from "dotenv";
import { apiEnvSchema } from "@fdt/config";

dotenv.config();

const plugin: FastifyPluginAsync = async (app) => {
  const parsed = apiEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(`Invalid env: ${parsed.error.message}`);
  }

  app.decorate("env", parsed.data);
};

export const envPlugin = fp(plugin);
