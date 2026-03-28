import { Prisma } from "@prisma/client";
import { PayloadViewer } from "./payload-viewer";

const statusColors: Record<string, string> = {
  approved: "bg-emerald-500/20 text-emerald-400",
  blocked: "bg-red-500/20 text-red-400",
  error: "bg-amber-500/20 text-amber-400",
};

const statusBorders: Record<string, string> = {
  approved: "border-l-2 border-l-emerald-400",
  blocked: "border-l-2 border-l-red-400",
  error: "border-l-2 border-l-amber-400",
};

interface EventDetailProps {
  event: {
    eventId: string;
    timestamp: Date | string;
    status: string;
    rule: string | null;
    reason: string | null;
    details: Prisma.JsonValue | null;
    elapsedMs: number;
    payload: Prisma.JsonValue | null;
    metadata: Prisma.JsonValue | null;
  };
}

function isJsonObject(value: Prisma.JsonValue | null): value is Record<string, Prisma.JsonValue> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function EventDetail({ event }: EventDetailProps) {
  const metadataObj = isJsonObject(event.metadata) ? event.metadata : null;
  const detailsObj = isJsonObject(event.details) ? event.details : null;

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-6">
        <div className="flex items-center gap-4 mb-4">
          <span className={`px-3 py-1.5 rounded text-sm font-bold ${statusColors[event.status] || ""}`}>
            {event.status.toUpperCase()}
          </span>
          <span className="font-mono text-sm text-slate-500">{event.eventId}</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-slate-500">Timestamp</p>
            <p className="font-mono text-slate-300">{new Date(event.timestamp).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-slate-500">Rule</p>
            <p className="text-slate-300">{event.rule || "—"}</p>
          </div>
          <div>
            <p className="text-slate-500">Latency</p>
            <p className="font-mono text-slate-300">{event.elapsedMs.toFixed(1)}ms</p>
          </div>
          <div>
            <p className="text-slate-500">Agent</p>
            <p className="font-mono text-slate-300">
              {typeof metadataObj?.agent_id === "string" ? metadataObj.agent_id : "—"}
            </p>
          </div>
        </div>
      </div>

      {event.reason && (
        <div className={`bg-slate-900 rounded-lg border border-slate-800 p-6 ${statusBorders[event.status] || ""}`}>
          <h3 className="text-sm font-medium text-slate-400 mb-3">Reason</h3>
          <p className="text-slate-200 mb-4">{event.reason}</p>
          {detailsObj && (
            <div>
              <h4 className="text-sm font-medium text-slate-400 mb-2">Details</h4>
              <div className="space-y-1">
                {Object.entries(detailsObj).map(([key, value]) => (
                  <div key={key} className="flex gap-2 text-sm">
                    <span className="text-slate-500 font-mono">{key}:</span>
                    <span className="text-slate-300 font-mono">{JSON.stringify(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <PayloadViewer payload={event.payload} />

      {metadataObj && Object.keys(metadataObj).length > 0 && (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-6">
          <h3 className="text-sm font-medium text-slate-400 mb-3">Metadata</h3>
          <div className="space-y-1">
            {Object.entries(metadataObj).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-sm">
                <span className="text-slate-500 font-mono">{key}:</span>
                <span className="text-slate-300 font-mono">{JSON.stringify(value)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
