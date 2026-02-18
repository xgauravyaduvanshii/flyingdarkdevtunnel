import argon2 from "argon2";
import { FastifyPluginAsync } from "fastify";
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
  password: z.string().min(8)
});

const refreshSchema = z.object({
  refreshToken: z.string().min(10)
});

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
      LIMIT 1
    `,
      [body.email],
    );

    const row = userRes.rows[0];
    if (!row) {
      return reply.code(401).send({ message: "Invalid credentials" });
    }

    const ok = await argon2.verify(row.password_hash, body.password);
    if (!ok) {
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
      decoded = app.verifyRefreshToken(body.refreshToken);
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
    "/authtoken/rotate",
    {
      preHandler: app.auth.requireAuth,
    },
    async (request) => {
      const userId = request.authUser!.userId;
      const rawAuthtoken = randomToken(24);
      const authtokenHash = await argon2.hash(rawAuthtoken);

      await app.db.query(`UPDATE users SET authtoken_hash = $1 WHERE id = $2`, [authtokenHash, userId]);
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
