import dotenv from "dotenv";
import { Pool } from "pg";
import { z } from "zod";
import { runMigrations } from "../lib/migrations.js";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  SECRET_ROTATION_MAX_AGE_DAYS: z.coerce.number().int().positive().default(90),
  SECRET_ROTATION_ENFORCE: z
    .string()
    .optional()
    .default("true")
    .transform((value) => value.trim().toLowerCase() !== "false"),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });

async function main(): Promise<void> {
  await runMigrations(db);

  const rows = await db.query<{
    org_id: string;
    stale_users: string;
    total_users: string;
    oldest_age_days: string;
  }>(
    `
      WITH rotation_state AS (
        SELECT
          m.org_id,
          m.user_id,
          COALESCE(MAX(sr.created_at), m.created_at) AS reference_at
        FROM memberships m
        LEFT JOIN secret_rotations sr
          ON sr.target_user_id = m.user_id
         AND sr.org_id = m.org_id
         AND sr.secret_type = 'authtoken'
        GROUP BY m.org_id, m.user_id, m.created_at
      )
      SELECT
        org_id,
        COUNT(*) FILTER (WHERE reference_at < NOW() - make_interval(days => $1::int))::text AS stale_users,
        COUNT(*)::text AS total_users,
        COALESCE(MAX(EXTRACT(EPOCH FROM NOW() - reference_at) / 86400), 0)::text AS oldest_age_days
      FROM rotation_state
      GROUP BY org_id
      ORDER BY org_id ASC
    `,
    [env.SECRET_ROTATION_MAX_AGE_DAYS],
  );

  const summary = rows.rows.map((row) => ({
    orgId: row.org_id,
    staleUsers: Number.parseInt(row.stale_users, 10) || 0,
    totalUsers: Number.parseInt(row.total_users, 10) || 0,
    oldestAgeDays: Number.parseFloat(row.oldest_age_days) || 0,
  }));
  const staleOrgCount = summary.filter((row) => row.staleUsers > 0).length;

  const report = {
    checkedAt: new Date().toISOString(),
    thresholdDays: env.SECRET_ROTATION_MAX_AGE_DAYS,
    enforce: env.SECRET_ROTATION_ENFORCE,
    staleOrgCount,
    organizations: summary,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

  if (env.SECRET_ROTATION_ENFORCE && staleOrgCount > 0) {
    process.exitCode = 1;
  }
}

main()
  .catch((error) => {
    console.error("[verify-secret-rotations] fatal", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await db.end();
  });
