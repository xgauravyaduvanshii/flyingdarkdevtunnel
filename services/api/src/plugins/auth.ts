import fp from "fastify-plugin";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { HttpError } from "../lib/errors.js";

type AccessPayload = {
  userId: string;
  orgId: string;
  role: string;
  tokenType: "access";
  jti?: string;
  exp?: number;
  iat?: number;
};

type RefreshPayload = {
  userId: string;
  orgId: string;
  role: string;
  tokenType: "refresh";
  jti?: string;
  exp?: number;
  iat?: number;
};

type AgentPayload = {
  userId: string;
  orgId: string;
  tunnelId: string;
  protocol: "http" | "https" | "tcp";
  subdomain: string | null;
  hosts: string[];
  tlsModes: Record<string, "termination" | "passthrough">;
  basicAuthUser: string | null;
  basicAuthPassword: string | null;
  ipAllowlist: string[];
  region: string;
  maxConcurrentConns: number;
  tokenType: "agent";
  jti?: string;
  exp?: number;
  iat?: number;
};

function parseBearerToken(request: FastifyRequest): string {
  const value = request.headers.authorization;
  if (!value || !value.startsWith("Bearer ")) {
    throw new HttpError(401, "Missing bearer token");
  }
  return value.slice("Bearer ".length);
}

const plugin: FastifyPluginAsync = async (app) => {
  const isRevoked = async (jti: string | undefined): Promise<boolean> => {
    if (!jti) return false;
    const revoked = await app.db.query(`SELECT 1 FROM auth_revoked_tokens WHERE jti = $1 LIMIT 1`, [jti]);
    return Boolean(revoked.rowCount);
  };

  app.decorate("auth", {
    signAccessToken: async (payload: { userId: string; orgId: string; role: string }) => {
      return jwt.sign({ ...payload, tokenType: "access" }, app.env.JWT_SECRET, { expiresIn: "15m", jwtid: uuidv4() });
    },
    signRefreshToken: async (payload: { userId: string; orgId: string; role: string }) => {
      return jwt.sign({ ...payload, tokenType: "refresh" }, app.env.JWT_REFRESH_SECRET, { expiresIn: "30d", jwtid: uuidv4() });
    },
    signAgentToken: async (payload: {
      userId: string;
      orgId: string;
      tunnelId: string;
      protocol: "http" | "https" | "tcp";
      subdomain: string | null;
      hosts: string[];
      tlsModes: Record<string, "termination" | "passthrough">;
      basicAuthUser: string | null;
      basicAuthPassword: string | null;
      ipAllowlist: string[];
      region: string;
      maxConcurrentConns: number;
    }) => {
      return jwt.sign({ ...payload, tokenType: "agent" }, app.env.AGENT_JWT_SECRET, { expiresIn: "15m", jwtid: uuidv4() });
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
      if (await isRevoked(decoded.jti)) {
        throw new HttpError(401, "Token revoked");
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

  app.decorate("verifyRefreshToken", async (token: string): Promise<RefreshPayload> => {
    const decoded = jwt.verify(token, app.env.JWT_REFRESH_SECRET) as RefreshPayload;
    if (decoded.tokenType !== "refresh") {
      throw new HttpError(401, "Invalid token type");
    }
    if (await isRevoked(decoded.jti)) {
      throw new HttpError(401, "Refresh token revoked");
    }
    return decoded;
  });

  app.decorate("verifyAgentToken", async (token: string): Promise<AgentPayload> => {
    const decoded = jwt.verify(token, app.env.AGENT_JWT_SECRET) as AgentPayload;
    if (decoded.tokenType !== "agent") {
      throw new HttpError(401, "Invalid token type");
    }
    if (await isRevoked(decoded.jti)) {
      throw new HttpError(401, "Agent token revoked");
    }
    return decoded;
  });
};

export const authPlugin = fp(plugin);
