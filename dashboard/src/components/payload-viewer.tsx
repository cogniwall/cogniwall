"use client";

import { useState } from "react";

export function PayloadViewer({ payload }: { payload: unknown }) {
  const [expanded, setExpanded] = useState(true);

  if (!payload) {
    return (
      <div className="text-sm text-slate-500 italic p-4 bg-slate-900 rounded-lg border border-slate-800">
        Payload not captured. Enable <code className="text-slate-400">include_payload</code> to store payloads.
      </div>
    );
  }

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 text-left text-sm font-medium text-slate-300 hover:bg-slate-800/50 flex justify-between items-center"
      >
        <span>Payload</span>
        <span className="text-slate-500">{expanded ? "▼" : "▶"}</span>
      </button>
      {expanded && (
        <pre className="px-4 pb-4 text-xs font-mono text-slate-400 overflow-x-auto">
          {JSON.stringify(payload, null, 2)}
        </pre>
      )}
    </div>
  );
}
