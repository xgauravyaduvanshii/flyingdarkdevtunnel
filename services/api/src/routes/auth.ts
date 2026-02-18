import argon2 from "argon2";
import { FastifyInstance, FastifyPluginAsync } from "fastify";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";
import { randomToken } from "../lib/utils.js";

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  orgName: z.string().min(2).max(80).optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  orgId: z.string().uuid().optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(10)
});

const revokeTokenSchema = z.object({
  token: z.string().min(20).optional(),
  tokenType: z.enum(["access", "refresh", "agent"]).optional(),
  reason: z.string().min(2).max(500).optional(),
});

type RevocableTokenPayload = {
  userId?: string;
  orgId?: string;
  tokenType?: "access" | "refresh" | "agent";
  jti?: string;
  exp?: number;
};

function bearerTokenFromHeaders(headers: Record<string, unknown>): string | null {
  const raw = headers.authorization;
  if (typeof raw !== "string") return null;
  if (!raw.startsWith("Bearer ")) return null;
  return raw.slice("Bearer ".length);
}

function verifyRevocableToken(
  app: FastifyInstance,
  token: string,
  tokenType: "access" | "refresh" | "agent",
): RevocableTokenPayload {
  const secret =
    tokenType === "access" ? app.env.JWT_SECRET : tokenType === "refresh" ? app.env.JWT_REFRESH_SECRET : app.env.AGENT_JWT_SECRET;
  return jwt.verify(token, secret) as RevocableTokenPayload;
}

async function recordSecurityAnomaly(
  app: FastifyInstance,
  input: {
    category: "auth_failed" | "token_revoked";
    severity: "low" | "medium" | "high";
    ip: string | null;
    userId?: string | null;
    orgId?: string | null;
    route: string;
    details?: Record<string, unknown>;
  },
): Promise<void> {
  await app.db.query(
    `
      INSERT INTO security_anomaly_events (id, category, severity, ip, user_id, org_id, route, details)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `,
    [
      uuidv4(),
      input.category,
      input.severity,
      input.ip,
      input.userId ?? null,
      input.orgId ?? null,
      input.route,
      input.details ?? null,
    ],
  );
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post("/register", async (request, reply) => {
    const body = registerSchema.parse(request.body);

    const existing = await app.db.query(`SELECT id FROM users WHERE email = $1 LIMIT 1`, [body.email]);
    if (existing.rowCount) {
      return reply.code(409).send({ message: "Email already registered" });
    }

    const userId = uuidv4();
    const orgId = uuidv4();
    const membershipId = uuidv4();
    const passwordHash = await argon2.hash(body.password);
    const rawAuthtoken = randomToken(24);
    const authtokenHash = await argon2.hash(rawAuthtoken);

    await app.db.query("BEGIN");
    try {
      await app.db.query(`INSERT INTO organizations (id, name) VALUES ($1, $2)`, [
        orgId,
        body.orgName ?? `Org-${body.email.split("@")[0]}`,
      ]);
      await app.db.query(
        `INSERT INTO users (id, email, password_hash, authtoken_hash) VALUES ($1, $2, $3, $4)`,
        [userId, body.email, passwordHash, authtokenHash],
      );
      await app.db.query(
        `INSERT INTO memberships (id, user_id, org_id, role) VALUES ($1, $2, $3, 'owner')`,
        [membershipId, userId, orgId],
      );
      await app.db.query(
        `
        INSERT INTO entitlements (id, org_id, plan_id, max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours)
        VALUES ($1, $2, '11111111-1111-1111-1111-111111111111', 3, 50, FALSE, FALSE, FALSE, 24)
      `,
        [uuidv4(), orgId],
      );
      await app.db.query(
        `
        INSERT INTO subscriptions (id, org_id, status, plan_id)
        VALUES ($1, $2, 'free', '11111111-1111-1111-1111-111111111111')
      `,
        [uuidv4(), orgId],
      );
      await app.db.query("COMMIT");
    } catch (error) {
      await app.db.query("ROLLBACK");
      throw error;
    }

    await app.audit.log({
      actorUserId: userId,
      orgId,
      action: "auth.register",
      entityType: "user",
      entityId: userId,
      metadata: { email: body.email }
    });

    const accessToken = await app.auth.signAccessToken({ userId, orgId, role: "owner" });
    const refreshToken = await app.auth.signRefreshToken({ userId, orgId, role: "owner" });

    return reply.code(201).send({ accessToken, refreshToken, authtoken: rawAuthtoken });
  });

  app.post("/login", async (request, reply) => {
    const body = loginSchema.parse(request.body);

    const userRes = await app.db.query<{
      id: string;
      password_hash: string;
      org_id: string;
      role: string;
    }>(
      `
      SELECT u.id, u.password_hash, m.org_id, m.role
      FROM users u
      JOIN memberships m ON m.user_id = u.id
      WHERE u.email = $1
        AND ($2::uuid IS NULL OR m.org_id = $2)
      ORDER BY
        CASE m.role
          WHEN 'owner' THEN 0
          WHEN 'admin' THEN 1
          WHEN 'member' THEN 2
          WHEN 'billing' THEN 3
          ELSE 4
        END,
        m.created_at ASC
      LIMIT 1
    `,
      [body.email, body.orgId ?? null],
    );

    const row = userRes.rows[0];
    if (!row) {
      await recordSecurityAnomaly(app, {
        category: "auth_failed",
        severity: "medium",
        ip: request.ip ?? null,
        route: "/v1/auth/login",
        details: { reason: "user_not_found", email: body.email },
      });
      return reply.code(401).send({ message: "Invalid credentials" });
    }

    const ok = await argon2.verify(row.password_hash, body.password);
    if (!ok) {
      await recordSecurityAnomaly(app, {
        category: "auth_failed",
        severity: "medium",
        ip: request.ip ?? null,
        userId: row.id,
        orgId: row.org_id,
        route: "/v1/auth/login",
        details: { reason: "password_mismatch", email: body.email },
      });
      return reply.code(401).send({ message: "Invalid credentials" });
    }

    const accessToken = await app.auth.signAccessToken({ userId: row.id, orgId: row.org_id, role: row.role });
    const refreshToken = await app.auth.signRefreshToken({ userId: row.id, orgId: row.org_id, role: row.role });

    await app.audit.log({
      actorUserId: row.id,
      orgId: row.org_id,
      action: "auth.login",
      entityType: "user",
      entityId: row.id
    });

    return { accessToken, refreshToken };
  });

  app.post("/token/refresh", async (request, reply) => {
    const body = refreshSchema.parse(request.body);

    let decoded: { userId: string; orgId: string; role: string };
    try {
      decoded = await app.verifyRefreshToken(body.refreshToken);
    } catch {
      return reply.code(401).send({ message: "Invalid refresh token" });
    }

    const accessToken = await app.auth.signAccessToken({
      userId: decoded.userId,
      orgId: decoded.orgId,
      role: decoded.role,
    });

    return { accessToken };
  });

  app.post(
    "/token/revoke",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request, reply) => {
      const body = revokeTokenSchema.parse(request.body ?? {});
      const fallbackToken = bearerTokenFromHeaders(request.headers as Record<string, unknown>);
      const targetToken = body.token ?? fallbackToken;

      if (!targetToken) {
        return reply.code(400).send({ message: "Token is required" });
      }

      const decodedHint = jwt.decode(targetToken) as RevocableTokenPayload | null;
      const tokenType = body.tokenType ?? decodedHint?.tokenType ?? "access";

      let decoded: RevocableTokenPayload;
      try {
        decoded = verifyRevocableToken(app, targetToken, tokenType);
      } catch {
        return reply.code(400).send({ message: "Token verification failed" });
      }

      if (!decoded.jti) {
        return reply.code(400).send({ message: "Token missing jti; cannot revoke" });
      }

      await app.db.query(
        `
        INSERT INTO auth_revoked_tokens (id, jti, token_type, user_id, org_id, expires_at, reason)
        VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7)
        ON CONFLICT (jti) DO NOTHING
      `,
        [
          uuidv4(),
          decoded.jti,
          tokenType,
          decoded.userId ?? request.authUser!.userId,
          decoded.orgId ?? request.authUser!.orgId,
          decoded.exp ?? null,
          body.reason ?? "manual revoke",
        ],
      );
      await recordSecurityAnomaly(app, {
        category: "token_revoked",
        severity: "low",
        ip: request.ip ?? null,
        userId: decoded.userId ?? request.authUser!.userId,
        orgId: decoded.orgId ?? request.authUser!.orgId,
        route: "/v1/auth/token/revoke",
        details: { tokenType, reason: body.reason ?? null },
      });

      await app.audit.log({
        actorUserId: request.authUser!.userId,
        orgId: request.authUser!.orgId,
        action: "auth.token.revoke",
        entityType: "auth_token",
        entityId: decoded.jti,
        metadata: {
          tokenType,
          reason: body.reason ?? null,
        },
      });

      return { ok: true, jti: decoded.jti, tokenType };
    },
  );

  app.post(
    "/authtoken/rotate",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request) => {
      const userId = request.authUser!.userId;
      const rawAuthtoken = randomToken(24);
      const authtokenHash = await argon2.hash(rawAuthtoken);

      await app.db.query(`UPDATE users SET authtoken_hash = $1 WHERE id = $2`, [authtokenHash, userId]);
      await app.db.query(
        `
        INSERT INTO secret_rotations (id, actor_user_id, target_user_id, org_id, secret_type, reason, metadata)
        VALUES ($1, $2, $3, $4, 'authtoken', $5, $6)
      `,
        [uuidv4(), request.authUser!.userId, userId, request.authUser!.orgId, "self-service rotation", { source: "auth.authtoken.rotate" }],
      );
      await app.audit.log({
        actorUserId: userId,
        orgId: request.authUser!.orgId,
        action: "auth.authtoken.rotate",
        entityType: "user",
        entityId: userId
      });

      return { authtoken: rawAuthtoken };
    },
  );
};
