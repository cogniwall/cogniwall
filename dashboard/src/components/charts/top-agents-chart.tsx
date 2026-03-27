"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface AgentData { agent_id: string; blocked_count: number; }

export function TopAgentsChart({ data }: { data: AgentData[] }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
      <h3 className="text-sm font-medium text-zinc-400 mb-4">Top Blocked Agents</h3>
      {data.length === 0 ? (
        <p className="text-zinc-500 text-sm">No agent metadata found. Pass <code className="text-zinc-400">metadata={"{"}"agent_id": "..."{"}"}</code> to evaluate().</p>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" tick={{ fill: "#71717a", fontSize: 11 }} />
            <YAxis dataKey="agent_id" type="category" tick={{ fill: "#a1a1aa", fontSize: 11 }} width={130} />
            <Tooltip contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }} />
            <Bar dataKey="blocked_count" fill="#ef4444" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
