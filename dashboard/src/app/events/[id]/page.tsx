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
      <div className="flex items-center gap-2 mb-6 text-sm text-zinc-500">
        <Link href="/" className="hover:text-white">Events</Link>
        <span>/</span>
        <span className="text-zinc-300 font-mono">{id.slice(0, 8)}...</span>
      </div>
      <EventDetail event={event as any} />
    </div>
  );
}
