import crypto from "node:crypto";

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

function normalizeValue(input: unknown): JsonValue {
  if (input === undefined) {
    return null;
  }

  if (
    input == null ||
    typeof input === "string" ||
    typeof input === "number" ||
    typeof input === "boolean"
  ) {
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => normalizeValue(item));
  }

  if (typeof input === "object") {
    const obj = input as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const normalized: Record<string, JsonValue> = {};
    for (const key of keys) {
      normalized[key] = normalizeValue(obj[key]);
    }
    return normalized;
  }

  return String(input);
}

export type AuditHashInput = {
  actorUserId: string | null;
  orgId: string | null;
  action: string;
  entityType: string;
  entityId: string;
  metadata?: Record<string, unknown>;
  createdAtIso: string;
  prevHash: string | null;
};

export function computeAuditEntryHash(input: AuditHashInput): string {
  const canonicalPayload = normalizeValue({
    actorUserId: input.actorUserId,
    orgId: input.orgId,
    action: input.action,
    entityType: input.entityType,
    entityId: input.entityId,
    metadata: input.metadata ?? null,
    createdAt: input.createdAtIso,
    prevHash: input.prevHash,
  });

  return crypto.createHash("sha256").update(JSON.stringify(canonicalPayload)).digest("hex");
}
