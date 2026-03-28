interface AnalyticsSummary {
  total: number;
  approved: number;
  blocked: number;
  errors: number;
  block_rate: number;
}

export function AnalyticsCards({ summary }: { summary: AnalyticsSummary }) {
  const cards = [
    { label: "Total Evaluations", value: summary.total.toLocaleString(), color: "text-white", subtitle: null as string | null },
    { label: "Block Rate", value: `${(summary.block_rate * 100).toFixed(1)}%`, color: "text-white", subtitle: null as string | null },
    { label: "Blocked", value: summary.blocked.toLocaleString(), color: "text-red-400", subtitle: "security intervention required" },
    { label: "Errors", value: summary.errors.toLocaleString(), color: "text-amber-400", subtitle: "API or connectivity failures" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      {cards.map((card) => (
        <div key={card.label} className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <p className="text-xs text-slate-500 mb-1">{card.label}</p>
          <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
          {card.subtitle && (
            <p className="text-xs text-slate-500 mt-1">{card.subtitle}</p>
          )}
        </div>
      ))}
    </div>
  );
}
