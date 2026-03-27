import { prisma } from "@/lib/prisma";
import { Prisma } from "@prisma/client";

export interface EventListParams {
  status?: string;
  rule?: string;
  from?: string;
  to?: string;
  search?: string;
  page?: number;
  limit?: number;
  eventId?: string;
}

function parseDate(value: string | undefined): Date | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  if (isNaN(d.getTime())) return undefined;
  return d;
}

export async function queryEvents(params: EventListParams) {
  const { status, rule, from, to, search, page = 1, limit, eventId } = params;

  // Cap limit: minimum 1, maximum 500, default 50
  const effectiveLimit = Math.min(Math.max(1, limit ?? 50), 500);

  if (eventId) {
    const event = await prisma.auditEvent.findUnique({
      where: { eventId },
    });
    return event ? { events: [event], total: 1, page: 1, pages: 1 } : { events: [], total: 0, page: 1, pages: 0 };
  }

  const where: Prisma.AuditEventWhereInput = {};

  if (status) where.status = status;
  if (rule) where.rule = rule;
  const fromDate = parseDate(from);
  const toDate = parseDate(to);
  if (fromDate || toDate) {
    where.timestamp = {};
    if (fromDate) where.timestamp.gte = fromDate;
    if (toDate) where.timestamp.lte = toDate;
  }
  if (search) {
    where.OR = [
      { reason: { contains: search, mode: "insensitive" } },
      { rule: { contains: search, mode: "insensitive" } },
    ];
  }

  const skip = (page - 1) * effectiveLimit;
  const [events, total] = await Promise.all([
    prisma.auditEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      skip,
      take: effectiveLimit,
    }),
    prisma.auditEvent.count({ where }),
  ]);

  return {
    events,
    total,
    page,
    pages: Math.ceil(total / effectiveLimit),
  };
}

// Only these three values are ever used — validated explicitly before interpolation.
const VALID_INTERVALS = new Set(["hour", "day", "week"]);

export async function queryAnalytics(params: {
  from?: string;
  to?: string;
  interval?: "hour" | "day" | "week";
}) {
  const now = new Date();
  const fromDate = parseDate(params.from) ?? new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const toDate = parseDate(params.to) ?? now;

  // Validate interval against whitelist before use in raw SQL
  const rawInterval = params.interval ?? "hour";
  const validInterval = VALID_INTERVALS.has(rawInterval) ? rawInterval : "hour";

  const [summary, overTime, topRules, topAgents] = await Promise.all([
    prisma.auditEvent.groupBy({
      by: ["status"],
      where: { timestamp: { gte: fromDate, lte: toDate } },
      _count: true,
    }),
    // validInterval is guaranteed to be one of "hour" | "day" | "week" by the whitelist check above.
    prisma.$queryRawUnsafe<{ bucket: Date; status: string; count: bigint }[]>(
      `SELECT date_trunc('${validInterval}', timestamp) as bucket, status, COUNT(*) as count
       FROM audit_events
       WHERE timestamp >= $1 AND timestamp <= $2
       GROUP BY bucket, status
       ORDER BY bucket ASC`,
      fromDate,
      toDate
    ),
    prisma.auditEvent.groupBy({
      by: ["rule"],
      where: {
        timestamp: { gte: fromDate, lte: toDate },
        status: "blocked",
        rule: { not: null },
      },
      _count: true,
      orderBy: { _count: { rule: "desc" } },
      take: 10,
    }),
    prisma.$queryRawUnsafe<{ agent_id: string; count: bigint }[]>(
      `SELECT metadata->>'agent_id' as agent_id, COUNT(*) as count
       FROM audit_events
       WHERE timestamp >= $1 AND timestamp <= $2
         AND status = 'blocked'
         AND metadata->>'agent_id' IS NOT NULL
       GROUP BY metadata->>'agent_id'
       ORDER BY count DESC
       LIMIT 10`,
      fromDate,
      toDate
    ),
  ]);

  const counts: Record<string, number> = { approved: 0, blocked: 0, error: 0 };
  for (const row of summary) {
    counts[row.status] = row._count;
  }
  const total = counts.approved + counts.blocked + counts.error;

  const bucketMap = new Map<string, { approved: number; blocked: number; errors: number }>();
  for (const row of overTime) {
    const key = row.bucket.toISOString();
    if (!bucketMap.has(key)) {
      bucketMap.set(key, { approved: 0, blocked: 0, errors: 0 });
    }
    const bucket = bucketMap.get(key)!;
    if (row.status === "approved") bucket.approved = Number(row.count);
    else if (row.status === "blocked") bucket.blocked = Number(row.count);
    else if (row.status === "error") bucket.errors = Number(row.count);
  }
  const over_time = Array.from(bucketMap.entries()).map(([bucket, data]) => ({
    bucket,
    ...data,
  }));

  return {
    summary: {
      total,
      approved: counts.approved,
      blocked: counts.blocked,
      errors: counts.error,
      block_rate: total > 0 ? counts.blocked / total : 0,
    },
    over_time,
    top_rules: topRules.map((r) => ({ rule: r.rule, count: r._count })),
    top_blocked_agents: topAgents.map((a) => ({
      agent_id: a.agent_id,
      blocked_count: Number(a.count),
    })),
  };
}
