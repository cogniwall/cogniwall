import { Suspense } from "react";
import { EventFilters } from "@/components/event-filters";
import { EventTable } from "@/components/event-table";
import { EventSummaryStats } from "@/components/event-summary-stats";
import { queryEvents } from "@/lib/queries";

export default async function EventLogPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const result = await queryEvents({
    status: params.status,
    rule: params.rule,
    from: params.from,
    to: params.to,
    search: params.search,
    page: params.page ? Number(params.page) : 1,
    limit: 50,
  });

  return (
    <div>
      <div className="flex items-baseline gap-3 mb-6">
        <h2 className="text-2xl font-bold">Events</h2>
        <span className="text-slate-500 text-sm">· {result.total.toLocaleString()}</span>
      </div>
      <Suspense fallback={<div>Loading filters...</div>}>
        <EventFilters />
      </Suspense>
      <EventTable
        events={result.events}
        total={result.total}
        page={result.page}
        pages={result.pages}
        searchParams={params}
      >
        <EventSummaryStats summary={result.summary} total={result.total} />
      </EventTable>
    </div>
  );
}
