#!/usr/bin/env node
import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";

function asInt(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : fallback;
}

function asFloat(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) ? value : fallback;
}

const target = process.env.TARGET_URL;
if (!target) {
  console.error("TARGET_URL is required");
  process.exit(2);
}

const totalRequests = asInt("REQUESTS", 500);
const concurrency = asInt("CONCURRENCY", 40);
const timeoutMs = asInt("TIMEOUT_MS", 5000);
const maxFailureRate = asFloat("MAX_FAILURE_RATE", 0.05);
const minSuccessRate = asFloat("MIN_SUCCESS_RATE", 0);
const maxP95Ms = process.env.MAX_P95_MS ? asFloat("MAX_P95_MS", Number.POSITIVE_INFINITY) : Number.POSITIVE_INFINITY;
const requireStatus = process.env.REQUIRE_STATUS ?? "";
const method = (process.env.HTTP_METHOD ?? "GET").toUpperCase();

const parsed = new URL(target);
const transport = parsed.protocol === "https:" ? https : http;
const hostHeader = process.env.HOST_HEADER?.trim();
const authUser = process.env.BASIC_AUTH_USER;
const authPass = process.env.BASIC_AUTH_PASS;

const statusCounts = new Map();
const latencies = [];
let success = 0;
let failed = 0;
let timeoutCount = 0;
let networkErrorCount = 0;
let started = 0;

function quantile(values, q) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil(sorted.length * q) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
}

function incStatus(key) {
  statusCounts.set(key, (statusCounts.get(key) ?? 0) + 1);
}

function requestOnce() {
  return new Promise((resolve) => {
    const startedAt = performance.now();
    const headers = {};
    if (hostHeader) headers.host = hostHeader;
    if (authUser && authPass) {
      headers.authorization = `Basic ${Buffer.from(`${authUser}:${authPass}`).toString("base64")}`;
    }

    const req = transport.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers,
        rejectUnauthorized: false,
      },
      (res) => {
        res.on("data", () => {});
        res.on("end", () => {
          const elapsed = performance.now() - startedAt;
          latencies.push(elapsed);
          const statusCode = res.statusCode ?? 0;
          incStatus(String(statusCode));
          if (statusCode >= 200 && statusCode < 300) {
            success += 1;
          } else {
            failed += 1;
          }
          resolve();
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("timeout"));
    });

    req.on("error", (error) => {
      const elapsed = performance.now() - startedAt;
      latencies.push(elapsed);
      failed += 1;
      if (String(error.message).includes("timeout")) {
        timeoutCount += 1;
        incStatus("timeout");
      } else {
        networkErrorCount += 1;
        incStatus("network_error");
      }
      resolve();
    });

    req.setTimeout(timeoutMs);
    req.end();
  });
}

async function worker() {
  while (true) {
    const index = started;
    started += 1;
    if (index >= totalRequests) {
      return;
    }
    await requestOnce();
  }
}

const begin = performance.now();
await Promise.all(Array.from({ length: Math.max(1, concurrency) }, () => worker()));
const elapsedMs = performance.now() - begin;

const total = success + failed;
const failureRate = total === 0 ? 1 : failed / total;
const successRate = total === 0 ? 0 : success / total;
const p50 = quantile(latencies, 0.5);
const p95 = quantile(latencies, 0.95);
const p99 = quantile(latencies, 0.99);

const result = {
  target,
  method,
  total,
  success,
  failed,
  successRate,
  failureRate,
  timeoutCount,
  networkErrorCount,
  durationMs: elapsedMs,
  requestsPerSecond: elapsedMs <= 0 ? 0 : total / (elapsedMs / 1000),
  latencyMs: {
    p50,
    p95,
    p99,
  },
  statuses: Object.fromEntries(statusCounts.entries()),
};

console.log(JSON.stringify(result, null, 2));

let hasViolation = false;
if (failureRate > maxFailureRate) {
  hasViolation = true;
  console.error(`failure rate violation: ${failureRate.toFixed(4)} > ${maxFailureRate.toFixed(4)}`);
}
if (successRate < minSuccessRate) {
  hasViolation = true;
  console.error(`success rate violation: ${successRate.toFixed(4)} < ${minSuccessRate.toFixed(4)}`);
}
if (p95 > maxP95Ms) {
  hasViolation = true;
  console.error(`p95 violation: ${p95.toFixed(2)}ms > ${maxP95Ms.toFixed(2)}ms`);
}

if (requireStatus.trim()) {
  for (const token of requireStatus.split(",")) {
    const [code, minCountRaw] = token.split(":");
    const minCount = Number.parseInt(minCountRaw ?? "1", 10);
    const actual = statusCounts.get(code.trim()) ?? 0;
    if (!Number.isFinite(minCount) || minCount < 1) {
      continue;
    }
    if (actual < minCount) {
      hasViolation = true;
      console.error(`required status violation: ${code.trim()} count ${actual} < ${minCount}`);
    }
  }
}

if (hasViolation) {
  process.exit(1);
}
