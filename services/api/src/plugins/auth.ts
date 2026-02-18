import fp from "fastify-plugin";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import { HttpError } from "../lib/errors.js";

type AccessPayload = {
  userId: string;
  orgId: string;
  role: string;
  tokenType: "access";
};

type RefreshPayload = {
  userId: string;
  orgId: string;
  role: string;
  tokenType: "refresh";
};

type AgentPayload = {
  userId: string;
  orgId: string;
  tunnelId: string;
  protocol: "http" | "https" | "tcp";
  subdomain: string | null;
  tokenType: "agent";
};

function parseBearerToken(request: FastifyRequest): string {
  const value = request.headers.authorization;
  if (!value || !value.startsWith("Bearer ")) {
    throw new HttpError(401, "Missing bearer token");
  }
  return value.slice("Bearer ".length);
}

const plugin: FastifyPluginAsync = async (app) => {
  app.decorate("auth", {
    signAccessToken: async (payload: { userId: string; orgId: string; role: string }) => {
      return jwt.sign({ ...payload, tokenType: "access" }, app.env.JWT_SECRET, { expiresIn: "15m" });
    },
    signRefreshToken: async (payload: { userId: string; orgId: string; role: string }) => {
      return jwt.sign({ ...payload, tokenType: "refresh" }, app.env.JWT_REFRESH_SECRET, { expiresIn: "30d" });
    },
    signAgentToken: async (payload: {
      userId: string;
      orgId: string;
      tunnelId: string;
      protocol: "http" | "https" | "tcp";
      subdomain: string | null;
    }) => {
      return jwt.sign({ ...payload, tokenType: "agent" }, app.env.AGENT_JWT_SECRET, { expiresIn: "15m" });
    },
    requireAuth: async (request: FastifyRequest) => {
      let decoded: AccessPayload;
      try {
        const token = parseBearerToken(request);
        decoded = jwt.verify(token, app.env.JWT_SECRET) as AccessPayload;
      } catch {
        throw new HttpError(401, "Unauthorized");
      }

      if (decoded.tokenType !== "access") {
        throw new HttpError(401, "Invalid token type");
      }

      request.authUser = decoded;
    },
    requireAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
      await app.auth.requireAuth(request, reply);
      if (!request.authUser || !["admin", "owner"].includes(request.authUser.role)) {
        throw new HttpError(403, "Forbidden");
      }
    },
  });

  app.decorate("verifyRefreshToken", (token: string): RefreshPayload => {
    return jwt.verify(token, app.env.JWT_REFRESH_SECRET) as RefreshPayload;
  });

  app.decorate("verifyAgentToken", (token: string): AgentPayload => {
    return jwt.verify(token, app.env.AGENT_JWT_SECRET) as AgentPayload;
  });
};

export const authPlugin = fp(plugin);
