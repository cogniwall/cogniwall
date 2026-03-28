"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { Prisma } from "@prisma/client";

interface AuditEvent {
  id: string;
  eventId: string;
  timestamp: Date | string;
  status: string;
  rule: string | null;
  reason: string | null;
  elapsedMs: number;
  metadata: Prisma.JsonValue | null;
}

const statusColors: Record<string, string> = {
  approved: "bg-emerald-500/20 text-emerald-400",
  blocked: "bg-red-500/20 text-red-400",
  error: "bg-amber-500/20 text-amber-400",
};

export function EventTable({
  events, total, page, pages, searchParams, children,
}: {
  events: AuditEvent[];
  total: number;
  page: number;
  pages: number;
  searchParams?: Record<string, string | undefined>;
  children?: React.ReactNode;
}) {
  const router = useRouter();

  const buildPageUrl = (targetPage: number) => {
    const urlParams = new URLSearchParams();
    if (searchParams) {
      Object.entries(searchParams).forEach(([key, value]) => {
        if (value && key !== "page") urlParams.set(key, value);
      });
    }
    urlParams.set("page", String(targetPage));
    return `/?${urlParams.toString()}`;
  };

  return (
    <div>
      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900">
            <tr>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Timestamp</th>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Status</th>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Rule</th>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Reason</th>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Agent</th>
              <th className="text-right px-4 py-3 text-slate-400 font-medium">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {events.map((event) => (
              <tr key={event.id} className="hover:bg-slate-800/50 transition-colors cursor-pointer" onClick={() => router.push(`/events/${event.eventId}`)}>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">
                  {new Date(event.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${statusColors[event.status] || ""}`}>
                    {event.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-300">{event.rule || "—"}</td>
                <td className="px-4 py-3 text-slate-400 max-w-xs truncate">{event.reason || "—"}</td>
                <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                  {(event.metadata !== null && typeof event.metadata === "object" && !Array.isArray(event.metadata) && typeof (event.metadata as Record<string, Prisma.JsonValue>).agent_id === "string"
                    ? (event.metadata as Record<string, string>).agent_id
                    : "—")}
                </td>
                <td className="px-4 py-3 text-right text-slate-400 font-mono text-xs">
                  {event.elapsedMs.toFixed(1)}ms
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-slate-500">No events found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {children}
      <div className="flex justify-between items-center mt-4 text-sm text-slate-500">
        <span>Page {page} of {pages} — {total.toLocaleString()} events</span>
        <div className="flex gap-2">
          {page > 1 && (
            <Link href={buildPageUrl(page - 1)} className="px-3 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Previous</Link>
          )}
          {page < pages && (
            <Link href={buildPageUrl(page + 1)} className="px-3 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Next</Link>
          )}
        </div>
      </div>
    </div>
  );
}
