import type { ApiEnv } from "@fdt/config";
import type { Pool } from "pg";

declare module "fastify" {
  interface FastifyInstance {
    env: ApiEnv;
    db: Pool;
    auth: {
      signAccessToken: (payload: { userId: string; orgId: string; role: string }) => Promise<string>;
      signRefreshToken: (payload: { userId: string; orgId: string; role: string }) => Promise<string>;
      signAgentToken: (payload: {
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
      }) => Promise<string>;
      requireAuth: (request: any, reply: any) => Promise<void>;
      requireAdmin: (request: any, reply: any) => Promise<void>;
    };
    verifyRefreshToken: (token: string) => Promise<{
      userId: string;
      orgId: string;
      role: string;
      tokenType: "refresh";
      jti?: string;
      exp?: number;
      iat?: number;
    }>;
    verifyAgentToken: (token: string) => Promise<{
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
    }>;
    audit: {
      log: (args: {
        actorUserId: string | null;
        orgId: string | null;
        action: string;
        entityType: string;
        entityId: string;
        metadata?: Record<string, unknown>;
      }) => Promise<void>;
    };
  }

  interface FastifyRequest {
    rawBody?: string | Buffer;
    authUser?: {
      userId: string;
      orgId: string;
      role: string;
      tokenType: "access" | "refresh" | "agent";
      jti?: string;
      tunnelId?: string;
      protocol?: "http" | "https" | "tcp";
      subdomain?: string | null;
    };
  }
}
