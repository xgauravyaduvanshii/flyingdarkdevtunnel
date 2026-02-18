import dotenv from "dotenv";
import { Pool } from "pg";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  INSPECTOR_LOOP_INTERVAL_SECONDS: z.coerce.number().int().positive().default(15),
});

const env = envSchema.parse(process.env);
const db = new Pool({ connectionString: env.DATABASE_URL });

async function processReplayJobs(): Promise<void> {
  const jobs = await db.query<{ id: string; request_log_id: string }>(
    `SELECT id, request_log_id FROM replay_jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 20`,
  );

  for (const job of jobs.rows) {
    try {
      await db.query(`UPDATE replay_jobs SET status = 'running', updated_at = NOW() WHERE id = $1`, [job.id]);

      // Placeholder replay worker logic. In production this dispatches replay to active agent session.
      await db.query(
        `UPDATE replay_jobs SET status = 'completed', result = $2::jsonb, updated_at = NOW() WHERE id = $1`,
        [job.id, JSON.stringify({ ok: true, replayedAt: new Date().toISOString() })],
      );
    } catch (error) {
      await db.query(
        `UPDATE replay_jobs SET status = 'failed', result = $2::jsonb, updated_at = NOW() WHERE id = $1`,
        [job.id, JSON.stringify({ ok: false, error: String(error) })],
      );
    }
  }
}

async function pruneRetention(): Promise<void> {
  await db.query(
    `
    DELETE FROM request_logs rl
    USING tunnels t
    JOIN entitlements e ON e.org_id = t.org_id
    WHERE rl.tunnel_id = t.id
      AND rl.started_at < NOW() - make_interval(hours => e.retention_hours)
  `,
  );
}

async function loop(): Promise<void> {
  while (true) {
    await processReplayJobs();
    await pruneRetention();
    await new Promise((resolve) => setTimeout(resolve, env.INSPECTOR_LOOP_INTERVAL_SECONDS * 1000));
  }
}

loop().catch((error) => {
  console.error("[worker-inspector] fatal", error);
  process.exit(1);
});
