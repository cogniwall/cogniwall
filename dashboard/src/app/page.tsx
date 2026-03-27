import { Suspense } from "react";
import { EventFilters } from "@/components/event-filters";
import { EventTable } from "@/components/event-table";
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
      <h2 className="text-2xl font-bold mb-6">Events</h2>
      <Suspense fallback={<div>Loading filters...</div>}>
        <EventFilters />
      </Suspense>
      <EventTable
        events={result.events as any}
        total={result.total}
        page={result.page}
        pages={result.pages}
      />
    </div>
  );
}
