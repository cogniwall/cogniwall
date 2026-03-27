import { NextRequest, NextResponse } from "next/server";
import { queryAnalytics } from "@/lib/queries";

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const interval = params.get("interval") as "hour" | "day" | "week" | null;

  const result = await queryAnalytics({
    from: params.get("from") || undefined,
    to: params.get("to") || undefined,
    interval: interval || undefined,
  });

  return NextResponse.json(result);
}
