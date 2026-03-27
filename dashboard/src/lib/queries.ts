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

export async function queryEvents(params: EventListParams) {
  const { status, rule, from, to, search, page = 1, limit = 50, eventId } = params;

  if (eventId) {
    const event = await prisma.auditEvent.findUnique({
      where: { eventId },
    });
    return event ? { events: [event], total: 1, page: 1, pages: 1 } : { events: [], total: 0, page: 1, pages: 0 };
  }

  const where: Prisma.AuditEventWhereInput = {};

  if (status) where.status = status;
  if (rule) where.rule = rule;
  if (from || to) {
    where.timestamp = {};
    if (from) where.timestamp.gte = new Date(from);
    if (to) where.timestamp.lte = new Date(to);
  }
  if (search) {
    where.OR = [
      { reason: { contains: search, mode: "insensitive" } },
      { rule: { contains: search, mode: "insensitive" } },
    ];
  }

  const skip = (page - 1) * limit;
  const [events, total] = await Promise.all([
    prisma.auditEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      skip,
      take: limit,
    }),
    prisma.auditEvent.count({ where }),
  ]);

  return {
    events,
    total,
    page,
    pages: Math.ceil(total / limit),
  };
}

export async function queryAnalytics(params: {
  from?: string;
  to?: string;
  interval?: "hour" | "day" | "week";
}) {
  const now = new Date();
  const fromDate = params.from ? new Date(params.from) : new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const toDate = params.to ? new Date(params.to) : now;
  const interval = params.interval || "hour";

  const truncFn = interval === "hour"
    ? "date_trunc('hour', timestamp)"
    : interval === "day"
    ? "date_trunc('day', timestamp)"
    : "date_trunc('week', timestamp)";

  const [summary, overTime, topRules, topAgents] = await Promise.all([
    prisma.auditEvent.groupBy({
      by: ["status"],
      where: { timestamp: { gte: fromDate, lte: toDate } },
      _count: true,
    }),
    prisma.$queryRawUnsafe<{ bucket: Date; status: string; count: bigint }[]>(
      `SELECT ${truncFn} as bucket, status, COUNT(*) as count
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
