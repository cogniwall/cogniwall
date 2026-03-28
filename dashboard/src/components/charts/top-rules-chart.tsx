"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface RuleData { rule: string | null; count: number; }

export function TopRulesChart({ data }: { data: RuleData[] }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
      <h3 className="text-sm font-medium text-slate-400 mb-4">Top Triggered Rules</h3>
      {data.length === 0 ? (
        <p className="text-slate-500 text-sm">No blocked events yet</p>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} />
            <YAxis dataKey="rule" type="category" tick={{ fill: "#94a3b8", fontSize: 11 }} width={130} allowDataOverflow={false} />
            <Tooltip contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "8px" }} itemStyle={{ color: "#e2e8f0" }} labelStyle={{ color: "#94a3b8" }} cursor={{ fill: "rgba(148, 163, 184, 0.08)" }} />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
