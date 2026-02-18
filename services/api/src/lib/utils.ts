import { randomBytes } from "node:crypto";

export function randomToken(size = 32): string {
  return randomBytes(size).toString("hex");
}

export function generateSubdomain(prefix = "fdt"): string {
  const suffix = randomBytes(4).toString("hex");
  return `${prefix}-${suffix}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}
