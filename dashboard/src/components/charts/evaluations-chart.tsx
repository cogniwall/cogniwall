"use client";

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface BucketData {
  bucket: string;
  approved: number;
  blocked: number;
  errors: number;
}

export function EvaluationsChart({ data }: { data: BucketData[] }) {
  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.bucket).toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    }),
  }));

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 mb-8">
      <h3 className="text-sm font-medium text-zinc-400 mb-4">Evaluations Over Time</h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={formatted}>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
          <XAxis dataKey="label" tick={{ fill: "#71717a", fontSize: 11 }} />
          <YAxis tick={{ fill: "#71717a", fontSize: 11 }} />
          <Tooltip contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }} />
          <Area type="monotone" dataKey="approved" stackId="1" stroke="#10b981" fill="#10b98133" />
          <Area type="monotone" dataKey="blocked" stackId="1" stroke="#ef4444" fill="#ef444433" />
          <Area type="monotone" dataKey="errors" stackId="1" stroke="#f59e0b" fill="#f59e0b33" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
