import Link from "next/link";
import { notFound } from "next/navigation";
import { EventDetail } from "@/components/event-detail";
import { queryEvents } from "@/lib/queries";

export default async function EventDrilldownPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const result = await queryEvents({ eventId: id });

  if (result.events.length === 0) {
    notFound();
  }

  const event = result.events[0];

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <Link href="/" className="flex items-center gap-1 text-sm text-slate-400 hover:text-white transition-colors">
          <span className="material-symbols-outlined text-[18px]">arrow_back</span>
          Back to Events
        </Link>
        <span className="text-slate-600">|</span>
        <span className="text-sm text-slate-300 font-mono">Event: {id.slice(0, 8)}</span>
      </div>
      <h2 className="text-xl font-bold mb-6">Event Detail</h2>
      <EventDetail event={event} />
    </div>
  );
}
