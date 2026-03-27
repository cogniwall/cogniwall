import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { validateEvents } from "@/lib/validation";
import { queryEvents } from "@/lib/queries";
import { Prisma } from "@prisma/client";

function checkApiKey(request: NextRequest): boolean {
  const requiredKey = process.env.COGNIWALL_API_KEY;
  if (!requiredKey) return true;
  const providedKey = request.headers.get("X-CogniWall-Key");
  return providedKey === requiredKey;
}

export async function POST(request: NextRequest) {
  if (!checkApiKey(request)) {
    return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!Array.isArray(body)) {
    return NextResponse.json(
      { error: "Body must be a JSON array of events" },
      { status: 400 }
    );
  }

  const { valid, errors } = validateEvents(body);

  let accepted = 0;
  const insertErrors: { index: number; error: string }[] = [...errors];

  if (valid.length > 0) {
    try {
      const result = await prisma.auditEvent.createMany({
        data: valid.map((e) => ({
          eventId: e.event_id,
          timestamp: new Date(e.timestamp),
          status: e.status,
          rule: e.rule ?? null,
          reason: e.reason ?? null,
          details: (e.details ?? undefined) as Prisma.InputJsonValue | undefined,
          elapsedMs: e.elapsed_ms,
          payload: (e.payload ?? undefined) as Prisma.InputJsonValue | undefined,
          metadata: (e.metadata ?? undefined) as Prisma.InputJsonValue | undefined,
        })),
        skipDuplicates: true,
      });
      accepted = result.count;
    } catch (error) {
      return NextResponse.json(
        { error: "Database insert failed", detail: String(error) },
        { status: 500 }
      );
    }
  }

  return NextResponse.json({
    accepted,
    rejected: errors.length,
    errors: insertErrors,
  });
}

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;

  const result = await queryEvents({
    status: params.get("status") || undefined,
    rule: params.get("rule") || undefined,
    from: params.get("from") || undefined,
    to: params.get("to") || undefined,
    search: params.get("search") || undefined,
    page: params.has("page") ? Number(params.get("page")) : undefined,
    limit: params.has("limit") ? Number(params.get("limit")) : undefined,
    eventId: params.get("event_id") || undefined,
  });

  return NextResponse.json(result);
}
