interface EventSummary {
  blocked: number;
  errors: number;
  avg_latency: number;
}

export function EventSummaryStats({ summary, total }: { summary: EventSummary; total: number }) {
  const blockRate = total > 0 ? ((summary.blocked / total) * 100).toFixed(1) : "0.0";
  const errorRate = total > 0 ? ((summary.errors / total) * 100).toFixed(1) : "0.0";

  const stats = [
    { label: "Total Events", value: total.toLocaleString(), color: "text-white" },
    { label: "Block Rate", value: `${blockRate}%`, color: "text-red-400" },
    { label: "Avg Latency", value: `${summary.avg_latency.toFixed(1)}ms`, color: "text-white" },
    { label: "Error Rate", value: `${errorRate}%`, color: "text-amber-400" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
      {stats.map((stat) => (
        <div key={stat.label} className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <p className="text-xs text-slate-500 mb-1">{stat.label}</p>
          <p className={`text-lg font-bold ${stat.color}`}>{stat.value}</p>
        </div>
      ))}
    </div>
  );
}
