import Link from "next/link";

interface AuditEvent {
  id: string;
  eventId: string;
  timestamp: string;
  status: string;
  rule: string | null;
  reason: string | null;
  elapsedMs: number;
  metadata: Record<string, unknown> | null;
}

const statusColors: Record<string, string> = {
  approved: "bg-emerald-500/20 text-emerald-400",
  blocked: "bg-red-500/20 text-red-400",
  error: "bg-amber-500/20 text-amber-400",
};

export function EventTable({
  events, total, page, pages,
}: {
  events: AuditEvent[];
  total: number;
  page: number;
  pages: number;
}) {
  return (
    <div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-zinc-900">
            <tr>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Timestamp</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Status</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Rule</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Reason</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Agent</th>
              <th className="text-right px-4 py-3 text-zinc-400 font-medium">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {events.map((event) => (
              <tr key={event.id} className="hover:bg-zinc-900/50 transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-zinc-400">
                  <Link href={`/events/${event.eventId}`} className="hover:text-white">
                    {new Date(event.timestamp).toLocaleString()}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[event.status] || ""}`}>
                    {event.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-zinc-300">{event.rule || "—"}</td>
                <td className="px-4 py-3 text-zinc-400 max-w-xs truncate">{event.reason || "—"}</td>
                <td className="px-4 py-3 text-zinc-400 font-mono text-xs">
                  {(event.metadata as Record<string, string>)?.agent_id || "—"}
                </td>
                <td className="px-4 py-3 text-right text-zinc-400 font-mono text-xs">
                  {event.elapsedMs.toFixed(1)}ms
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-zinc-500">No events found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex justify-between items-center mt-4 text-sm text-zinc-500">
        <span>Page {page} of {pages} — {total.toLocaleString()} events</span>
        <div className="flex gap-2">
          {page > 1 && (
            <Link href={`?page=${page - 1}`} className="px-3 py-1 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700">Previous</Link>
          )}
          {page < pages && (
            <Link href={`?page=${page + 1}`} className="px-3 py-1 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700">Next</Link>
          )}
        </div>
      </div>
    </div>
  );
}
