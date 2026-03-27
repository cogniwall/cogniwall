import { PayloadViewer } from "./payload-viewer";

const statusColors: Record<string, string> = {
  approved: "bg-emerald-500/20 text-emerald-400",
  blocked: "bg-red-500/20 text-red-400",
  error: "bg-amber-500/20 text-amber-400",
};

interface EventDetailProps {
  event: {
    eventId: string;
    timestamp: string;
    status: string;
    rule: string | null;
    reason: string | null;
    details: Record<string, unknown> | null;
    elapsedMs: number;
    payload: unknown;
    metadata: Record<string, unknown> | null;
  };
}

export function EventDetail({ event }: EventDetailProps) {
  return (
    <div className="space-y-6">
      <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-6">
        <div className="flex items-center gap-4 mb-4">
          <span className={`px-3 py-1.5 rounded text-sm font-bold ${statusColors[event.status] || ""}`}>
            {event.status.toUpperCase()}
          </span>
          <span className="font-mono text-sm text-zinc-500">{event.eventId}</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-zinc-500">Timestamp</p>
            <p className="font-mono text-zinc-300">{new Date(event.timestamp).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-zinc-500">Rule</p>
            <p className="text-zinc-300">{event.rule || "—"}</p>
          </div>
          <div>
            <p className="text-zinc-500">Latency</p>
            <p className="font-mono text-zinc-300">{event.elapsedMs.toFixed(1)}ms</p>
          </div>
          <div>
            <p className="text-zinc-500">Agent</p>
            <p className="font-mono text-zinc-300">{(event.metadata as Record<string, string>)?.agent_id || "—"}</p>
          </div>
        </div>
      </div>

      {event.reason && (
        <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-6">
          <h3 className="text-sm font-medium text-zinc-400 mb-3">Reason</h3>
          <p className="text-zinc-200 mb-4">{event.reason}</p>
          {event.details && (
            <div>
              <h4 className="text-sm font-medium text-zinc-400 mb-2">Details</h4>
              <div className="space-y-1">
                {Object.entries(event.details).map(([key, value]) => (
                  <div key={key} className="flex gap-2 text-sm">
                    <span className="text-zinc-500 font-mono">{key}:</span>
                    <span className="text-zinc-300 font-mono">{JSON.stringify(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <PayloadViewer payload={event.payload} />

      {event.metadata && Object.keys(event.metadata).length > 0 && (
        <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-6">
          <h3 className="text-sm font-medium text-zinc-400 mb-3">Metadata</h3>
          <div className="space-y-1">
            {Object.entries(event.metadata).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-sm">
                <span className="text-zinc-500 font-mono">{key}:</span>
                <span className="text-zinc-300 font-mono">{JSON.stringify(value)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
