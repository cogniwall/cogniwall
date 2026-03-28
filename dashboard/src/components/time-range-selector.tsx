"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

const RANGES = [
  { label: "24h", hours: 24, interval: "hour" },
  { label: "7d", hours: 168, interval: "hour" },
  { label: "30d", hours: 720, interval: "day" },
];

function getFromISO(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

export function TimeRangeSelector() {
  const searchParams = useSearchParams();
  const currentFrom = searchParams.get("from");

  const getActiveLabel = () => {
    if (!currentFrom) return "24h";
    const diffHours = (Date.now() - new Date(currentFrom).getTime()) / (1000 * 60 * 60);
    if (diffHours <= 25) return "24h";
    if (diffHours <= 169) return "7d";
    return "30d";
  };

  const activeLabel = getActiveLabel();

  return (
    <div className="flex rounded-lg overflow-hidden border border-slate-700">
      {RANGES.map((range) => {
        const isActive = activeLabel === range.label;
        const href = `/analytics?from=${encodeURIComponent(getFromISO(range.hours))}&interval=${range.interval}`;
        return (
          <Link
            key={range.label}
            href={href}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              isActive
                ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
            }`}
          >
            {range.label}
          </Link>
        );
      })}
    </div>
  );
}
