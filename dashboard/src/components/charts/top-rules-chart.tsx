"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface RuleData { rule: string | null; count: number; }

export function TopRulesChart({ data }: { data: RuleData[] }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
      <h3 className="text-sm font-medium text-zinc-400 mb-4">Top Triggered Rules</h3>
      {data.length === 0 ? (
        <p className="text-zinc-500 text-sm">No blocked events yet</p>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" tick={{ fill: "#71717a", fontSize: 11 }} />
            <YAxis dataKey="rule" type="category" tick={{ fill: "#a1a1aa", fontSize: 11 }} width={130} allowDataOverflow={false} />
            <Tooltip contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }} />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
