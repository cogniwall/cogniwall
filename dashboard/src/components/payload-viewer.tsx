"use client";

import { useState } from "react";

export function PayloadViewer({ payload }: { payload: unknown }) {
  const [expanded, setExpanded] = useState(true);

  if (!payload) {
    return (
      <div className="text-sm text-zinc-500 italic p-4 bg-zinc-900 rounded-lg border border-zinc-800">
        Payload not captured. Enable <code className="text-zinc-400">include_payload</code> to store payloads.
      </div>
    );
  }

  return (
    <div className="bg-zinc-900 rounded-lg border border-zinc-800">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 text-left text-sm font-medium text-zinc-300 hover:bg-zinc-800/50 flex justify-between items-center"
      >
        <span>Payload</span>
        <span className="text-zinc-500">{expanded ? "▼" : "▶"}</span>
      </button>
      {expanded && (
        <pre className="px-4 pb-4 text-xs font-mono text-zinc-400 overflow-x-auto">
          {JSON.stringify(payload, null, 2)}
        </pre>
      )}
    </div>
  );
}
