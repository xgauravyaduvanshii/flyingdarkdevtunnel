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
      }) => Promise<string>;
      requireAuth: (request: any, reply: any) => Promise<void>;
      requireAdmin: (request: any, reply: any) => Promise<void>;
    };
    verifyRefreshToken: (token: string) => {
      userId: string;
      orgId: string;
      role: string;
      tokenType: "refresh";
    };
    verifyAgentToken: (token: string) => {
      userId: string;
      orgId: string;
      tunnelId: string;
      protocol: "http" | "https" | "tcp";
      subdomain: string | null;
      tokenType: "agent";
    };
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
    authUser?: {
      userId: string;
      orgId: string;
      role: string;
      tokenType: "access" | "refresh" | "agent";
      tunnelId?: string;
      protocol?: "http" | "https" | "tcp";
      subdomain?: string | null;
    };
  }
}
