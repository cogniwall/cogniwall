import { NextRequest, NextResponse } from "next/server";
import { queryAnalytics } from "@/lib/queries";
import { checkApiKey } from "@/lib/auth";

const VALID_INTERVALS = new Set(["hour", "day", "week"]);

export async function GET(request: NextRequest) {
  if (!checkApiKey(request)) {
    return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
  }

  const params = request.nextUrl.searchParams;
  const rawInterval = params.get("interval");
  const interval = VALID_INTERVALS.has(rawInterval ?? "") ? (rawInterval as "hour" | "day" | "week") : undefined;

  const result = await queryAnalytics({
    from: params.get("from") || undefined,
    to: params.get("to") || undefined,
    interval,
  });

  return NextResponse.json(result);
}
