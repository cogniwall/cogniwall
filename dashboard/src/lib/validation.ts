export interface AuditEventInput {
  event_id: string;
  timestamp: string;
  status: "approved" | "blocked" | "error";
  rule?: string | null;
  reason?: string | null;
  details?: Record<string, unknown> | null;
  elapsed_ms: number;
  payload?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
}

export interface ValidationResult {
  valid: AuditEventInput[];
  errors: { index: number; error: string }[];
}

const VALID_STATUSES = new Set(["approved", "blocked", "error"]);

export function validateEvents(events: unknown[]): ValidationResult {
  const valid: AuditEventInput[] = [];
  const errors: { index: number; error: string }[] = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i] as Record<string, unknown>;
    if (!event || typeof event !== "object") {
      errors.push({ index: i, error: "Event must be an object" });
      continue;
    }
    if (!event.event_id || typeof event.event_id !== "string") {
      errors.push({ index: i, error: "Missing or invalid event_id" });
      continue;
    }
    if (!event.timestamp || typeof event.timestamp !== "string") {
      errors.push({ index: i, error: "Missing or invalid timestamp" });
      continue;
    }
    if (!VALID_STATUSES.has(event.status as string)) {
      errors.push({ index: i, error: `Invalid status: ${event.status}` });
      continue;
    }
    if (typeof event.elapsed_ms !== "number") {
      errors.push({ index: i, error: "Missing or invalid elapsed_ms" });
      continue;
    }
    valid.push(event as unknown as AuditEventInput);
  }
  return { valid, errors };
}
