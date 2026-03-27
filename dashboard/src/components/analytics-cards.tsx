interface AnalyticsSummary {
  total: number;
  approved: number;
  blocked: number;
  errors: number;
  block_rate: number;
}

export function AnalyticsCards({ summary }: { summary: AnalyticsSummary }) {
  const cards = [
    { label: "Total Evaluations", value: summary.total.toLocaleString(), color: "text-white" },
    { label: "Block Rate", value: `${(summary.block_rate * 100).toFixed(1)}%`, color: "text-white" },
    { label: "Blocked", value: summary.blocked.toLocaleString(), color: "text-red-400" },
    { label: "Errors", value: summary.errors.toLocaleString(), color: "text-amber-400" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      {cards.map((card) => (
        <div key={card.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
          <p className="text-xs text-zinc-500 mb-1">{card.label}</p>
          <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
        </div>
      ))}
    </div>
  );
}
